using System.Security.Cryptography;
using RemoteTool.Core.Audit;
using RemoteTool.Core.Config;
using RemoteTool.Core.Protocol;

namespace RemoteTool.Core.Relay;

public enum RelayStatus { Disabled, Connecting, Online, Offline, AccessDenied }

public interface IIdProvider
{
    string Id { get; }
    /// <summary>Generates, persists and returns a new ID.</summary>
    string Regenerate();
}

public sealed class SettingsIdProvider : IIdProvider
{
    private readonly SettingsStore _store;
    public SettingsIdProvider(SettingsStore store) { _store = store; }
    public string Id => _store.Current.Id;
    public string Regenerate() => _store.RegenerateId();
}

public sealed record RelayRegistrationOptions(
    TimeSpan? IdTakenRetryDelay = null,
    int IdTakenRetries = 3,
    TimeSpan? MaxBackoff = null,
    TimeSpan? ControlReadTimeout = null);

/// <summary>
/// Keeps the host's ID registered on the relay over a long-lived outbound connection, and opens a data connection
/// per incoming viewer. Handles duplicate-ID detection by regenerating the ID.
/// </summary>
public sealed class RelayRegistration : IAsyncDisposable
{
    private readonly RelayEndpoint _ep;
    private readonly IIdProvider _ids;
    private readonly Func<Stream, string, CancellationToken, Task> _onIncoming;
    private readonly IAuditLog _audit;
    private readonly RelayRegistrationOptions _opt;
    private readonly byte[] _instanceId = RandomNumberGenerator.GetBytes(RelayLimits.InstanceIdLength);
    private readonly CancellationTokenSource _cts = new();
    private Task? _loop;
    private RelayStatus _status = RelayStatus.Disabled;

    public RelayRegistration(RelayEndpoint ep, IIdProvider ids, Func<Stream, string, CancellationToken, Task> onIncoming, IAuditLog audit, RelayRegistrationOptions? opt = null)
    {
        _ep = ep;
        _ids = ids;
        _onIncoming = onIncoming;
        _audit = audit;
        _opt = opt ?? new RelayRegistrationOptions();
    }

    public RelayStatus Status => _status;
    public event Action<RelayStatus>? StatusChanged;
    /// <summary>Raised after the ID was changed because the relay reported a duplicate.</summary>
    public event Action<string>? IdRegenerated;

    private void SetStatus(RelayStatus s)
    {
        if (_status == s) return;
        _status = s;
        StatusChanged?.Invoke(s);
    }

    public void Start() => _loop ??= Task.Run(() => LoopAsync(_cts.Token));

    private async Task LoopAsync(CancellationToken ct)
    {
        var backoff = TimeSpan.FromSeconds(1);
        var maxBackoff = _opt.MaxBackoff ?? TimeSpan.FromSeconds(60);
        var idTaken = 0;
        while (!ct.IsCancellationRequested)
        {
            SetStatus(RelayStatus.Connecting);
            try
            {
                var outcome = await RunControlConnectionAsync(ct, () => { backoff = TimeSpan.FromSeconds(1); idTaken = 0; }).ConfigureAwait(false);
                switch (outcome)
                {
                    case Outcome.IdTaken:
                        SetStatus(RelayStatus.Offline);
                        if (++idTaken > _opt.IdTakenRetries)
                        {
                            var newId = _ids.Regenerate();
                            idTaken = 0;
                            _audit.Write("id_regenerated", ("reason", "duplicate-on-relay"));
                            IdRegenerated?.Invoke(newId);
                            continue;
                        }
                        // The previous registration may merely be a stale one from our own crashed process: wait and retry.
                        await Task.Delay(_opt.IdTakenRetryDelay ?? TimeSpan.FromSeconds(10), ct).ConfigureAwait(false);
                        continue;
                    case Outcome.Denied:
                        SetStatus(RelayStatus.AccessDenied);
                        _audit.Write("relay_access_denied");
                        await Task.Delay(TimeSpan.FromSeconds(30), ct).ConfigureAwait(false);
                        continue;
                }
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { return; }
            catch (Exception e) when (e is IOException or System.Net.Sockets.SocketException or ProtocolException or EndOfStreamException
                                           or System.Security.Authentication.AuthenticationException or TimeoutException or OperationCanceledException)
            {
                _audit.Write("relay_connection_lost", ("error", e.GetType().Name));
            }
            SetStatus(RelayStatus.Offline);
            try { await Task.Delay(backoff, ct).ConfigureAwait(false); } catch (OperationCanceledException) { return; }
            backoff = TimeSpan.FromTicks(Math.Min(backoff.Ticks * 2, maxBackoff.Ticks));
        }
    }

    private enum Outcome { Disconnected, IdTaken, Denied }

    private async Task<Outcome> RunControlConnectionAsync(CancellationToken ct, Action onRegistered)
    {
        await using var s = await RelayClient.OpenAsync(_ep, ct).ConfigureAwait(false);
        var w = new FrameWriter(s);
        var r = new FrameReader(s, MessageTypes.IsKnownRelay, RelayLimits.MaxControlPayload);
        var id = _ids.Id;
        await w.WriteAsync(RelayMessageType.Register, new RegisterMessage(_ep.AccessKey, id, _instanceId).Serialize(), ct).ConfigureAwait(false);

        var first = await ReadWithTimeout(r, TimeSpan.FromSeconds(15), ct).ConfigureAwait(false);
        switch ((RelayMessageType)first.Type)
        {
            case RelayMessageType.Registered: break;
            case RelayMessageType.IdTaken: return Outcome.IdTaken;
            case RelayMessageType.Denied: return Outcome.Denied;
            default: throw new ProtocolException("unexpected relay reply");
        }
        onRegistered();
        SetStatus(RelayStatus.Online);
        _audit.Write("relay_registered");

        var readTimeout = _opt.ControlReadTimeout ?? TimeSpan.FromSeconds(35);
        while (true)
        {
            var f = await ReadWithTimeout(r, readTimeout, ct).ConfigureAwait(false);
            switch ((RelayMessageType)f.Type)
            {
                case RelayMessageType.RelayPing:
                    await w.WriteAsync(RelayMessageType.RelayPong, ct).ConfigureAwait(false);
                    break;
                case RelayMessageType.Incoming:
                    var inc = IncomingMessage.Parse(f.Payload);
                    _ = Task.Run(() => HandleIncomingAsync(id, inc, _cts.Token), _cts.Token);
                    break;
                default:
                    throw new ProtocolException("unexpected relay message");
            }
        }
    }

    private static async Task<Frame> ReadWithTimeout(FrameReader r, TimeSpan timeout, CancellationToken ct)
    {
        using var c = CancellationTokenSource.CreateLinkedTokenSource(ct);
        c.CancelAfter(timeout);
        try { return await r.ReadAsync(c.Token).ConfigureAwait(false); }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested) { throw new TimeoutException("relay silent"); }
    }

    private async Task HandleIncomingAsync(string id, IncomingMessage inc, CancellationToken ct)
    {
        Stream? data = null;
        try
        {
            data = await RelayClient.OpenAsync(_ep, ct).ConfigureAwait(false);
            var w = new FrameWriter(data);
            var r = new FrameReader(data, MessageTypes.IsKnownRelay, RelayLimits.MaxControlPayload);
            await w.WriteAsync(RelayMessageType.Accept, new AcceptMessage(_ep.AccessKey, id, inc.Token).Serialize(), ct).ConfigureAwait(false);
            var ready = await ReadWithTimeout(r, TimeSpan.FromSeconds(20), ct).ConfigureAwait(false);
            if (ready.Type != (byte)RelayMessageType.Ready) return;
            var stream = data;
            data = null; // ownership passes to the host service
            await _onIncoming(stream, inc.ViewerAddress, ct).ConfigureAwait(false);
        }
        catch (Exception e) when (e is IOException or ProtocolException or TimeoutException or OperationCanceledException or EndOfStreamException
                                       or System.Net.Sockets.SocketException or System.Security.Authentication.AuthenticationException) { }
        finally { if (data is not null) await data.DisposeAsync().ConfigureAwait(false); }
    }

    public async ValueTask DisposeAsync()
    {
        _cts.Cancel();
        if (_loop is not null) { try { await _loop.ConfigureAwait(false); } catch { } }
        _cts.Dispose();
    }
}
