using RemoteTool.Core.Protocol;
using RemoteTool.Core.Session;

namespace RemoteTool.Service.Helper;

/// <summary>Service-side client of one helper process. Requests are serialised; helper events are surfaced as .NET events.</summary>
public sealed class HelperChannel : IAsyncDisposable
{
    private readonly FrameReader _reader;
    private readonly FrameWriter _writer;
    private readonly Stream _stream;
    private readonly SemaphoreSlim _rpc = new(1, 1);
    private readonly CancellationTokenSource _cts = new();
    private readonly TaskCompletionSource _closed = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private TaskCompletionSource<Frame>? _pending;
    private Task? _loop;

    public HelperChannel(Stream stream)
    {
        _stream = stream;
        _reader = new FrameReader(stream, HelperTypes.IsKnown, HelperTypes.MaxPayload);
        _writer = new FrameWriter(stream);
    }

    public HelperHello Hello { get; private set; } = new(0, 0, false, "");
    public Task Closed => _closed.Task;
    public event Action? EmergencyHotkey;
    public event Action? BannerDisconnect;

    /// <summary>Waits for the helper's Hello and starts the read loop.</summary>
    public async Task StartAsync(TimeSpan timeout)
    {
        using var c = CancellationTokenSource.CreateLinkedTokenSource(_cts.Token);
        c.CancelAfter(timeout);
        var f = await _reader.ReadAsync(c.Token).ConfigureAwait(false);
        if (f.Type != (byte)HelperMessage.Hello) throw new ProtocolException("helper did not say hello");
        Hello = HelperHello.Parse(f.Payload);
        _loop = Task.Run(ReadLoopAsync);
    }

    private async Task ReadLoopAsync()
    {
        try
        {
            while (true)
            {
                var f = await _reader.ReadAsync(_cts.Token).ConfigureAwait(false);
                var m = (HelperMessage)f.Type;
                if (m == HelperMessage.EmergencyHotkey) EmergencyHotkey?.Invoke();
                else if (m == HelperMessage.BannerDisconnect) BannerDisconnect?.Invoke();
                else if (HelperTypes.IsResponse(m)) _pending?.TrySetResult(f);
                else throw new ProtocolException("unexpected message from helper");
            }
        }
        catch (Exception e) when (e is OperationCanceledException or IOException or ProtocolException or ObjectDisposedException)
        {
            _pending?.TrySetException(new HelperException("helper connection lost", e));
        }
        finally { _closed.TrySetResult(); }
    }

    private async Task<Frame> RequestAsync(HelperMessage req, byte[] payload, HelperMessage expect, TimeSpan timeout, CancellationToken ct = default)
    {
        await _rpc.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (_closed.Task.IsCompleted) throw new HelperException("helper is gone");
            var tcs = _pending = new TaskCompletionSource<Frame>(TaskCreationOptions.RunContinuationsAsynchronously);
            await _writer.WriteAsync((byte)req, payload, _cts.Token).ConfigureAwait(false);
            Frame f;
            try { f = await tcs.Task.WaitAsync(timeout, ct).ConfigureAwait(false); }
            catch (TimeoutException) { throw new HelperException($"helper did not answer {req} in time"); }
            if (f.Type == (byte)HelperMessage.Error)
            {
                var (kind, msg) = HelperCodec.ParseError(f.Payload);
                throw kind == 1 ? new CodecUnavailableException(msg) : new HelperException(msg);
            }
            if (f.Type != (byte)expect) throw new HelperException($"helper answered {(HelperMessage)f.Type} to {req}");
            return f;
        }
        finally { _pending = null; _rpc.Release(); }
    }

    private Task Send(HelperMessage m, byte[] payload) => _writer.WriteAsync((byte)m, payload, _cts.Token);

    public async Task<IReadOnlyList<MonitorInfo>> GetMonitorsAsync()
        => ScreenInfoMessage.Parse((await RequestAsync(HelperMessage.GetMonitors, Array.Empty<byte>(), HelperMessage.Monitors, TimeSpan.FromSeconds(5)).ConfigureAwait(false)).Payload).Monitors;

    public async Task<FrameUpdateMessage?> NextFrameAsync(int monitor, int quality, bool key)
    {
        var f = await RequestAsync(HelperMessage.NextFrame, HelperCodec.NextFrameRequest(monitor, quality, key), HelperMessage.Frame, TimeSpan.FromSeconds(5)).ConfigureAwait(false);
        return HelperCodec.ParseOptional(f.Payload) is { } d ? FrameUpdateMessage.Parse(d) : null;
    }

    public async Task<VideoFrameMessage?> NextH264Async(int monitor, bool key, int kbps)
    {
        var f = await RequestAsync(HelperMessage.NextH264, HelperCodec.NextH264Request(monitor, key, kbps), HelperMessage.Video, TimeSpan.FromSeconds(5)).ConfigureAwait(false);
        return HelperCodec.ParseOptional(f.Payload) is { } d ? VideoFrameMessage.Parse(d) : null;
    }

    public async Task<CursorShape> GetCursorAsync()
        => CursorUpdateMessage.Parse((await RequestAsync(HelperMessage.GetCursor, Array.Empty<byte>(), HelperMessage.Cursor, TimeSpan.FromSeconds(3)).ConfigureAwait(false)).Payload).Shape;

    /// <summary>Name of the desktop currently receiving input: "Default" (user desktop) or "Winlogon" (login, lock screen, UAC prompt).</summary>
    public async Task<string> GetInputDesktopAsync()
    {
        var f = await RequestAsync(HelperMessage.GetDesktop, Array.Empty<byte>(), HelperMessage.Desktop, TimeSpan.FromSeconds(3)).ConfigureAwait(false);
        var r = new ProtoReader(f.Payload);
        var s = r.Str(64);
        r.EnsureEnd();
        return s;
    }

    public async Task<ConsentDecision> AskConsentAsync(ConsentRequestInfo info, CancellationToken ct)
    {
        var f = await RequestAsync(HelperMessage.AskConsent,
            HelperCodec.ConsentRequest(new HelperConsentInfo(info.ViewerName, info.Source, info.ViaRelay, info.Requested, info.Allowed, info.Recording)),
            HelperMessage.ConsentAnswer, TimeSpan.FromSeconds(ProtocolConstants.ConsentTimeout.TotalSeconds + 10), ct).ConfigureAwait(false);
        var (granted, perms) = HelperCodec.ParseConsentAnswer(f.Payload);
        return new ConsentDecision(granted, perms);
    }

    public Task SendMouseAsync(MonitorInfo m, MouseEventMessage e) => Send(HelperMessage.Mouse, HelperCodec.MouseRequest(m, e));
    public Task SendKeyAsync(KeyEventMessage e) => Send(HelperMessage.Key, e.Serialize());
    public Task ReleaseAllAsync() => Send(HelperMessage.ReleaseAll, Array.Empty<byte>());
    public Task ShowBannerAsync(string viewer, bool recording) => Send(HelperMessage.ShowBanner, HelperCodec.BannerRequest(viewer, recording));
    public Task HideBannerAsync() => Send(HelperMessage.HideBanner, Array.Empty<byte>());
    public Task ShutdownAsync() => Send(HelperMessage.Shutdown, Array.Empty<byte>());

    public async ValueTask DisposeAsync()
    {
        try { using var c = new CancellationTokenSource(TimeSpan.FromSeconds(1)); await _writer.WriteAsync((byte)HelperMessage.Shutdown, Array.Empty<byte>(), c.Token).ConfigureAwait(false); } catch { }
        _cts.Cancel();
        try { await _stream.DisposeAsync().ConfigureAwait(false); } catch { }
        if (_loop is not null) { try { await _loop.ConfigureAwait(false); } catch { } }
    }
}
