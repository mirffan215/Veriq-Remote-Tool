using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using RemoteTool.Core.Config;
using RemoteTool.Core.Protocol;
using RemoteTool.Core.Relay;

namespace RemoteTool.Relay;

/// <summary>Test hook that sees exactly the bytes the relay forwards (to prove they are opaque ciphertext).</summary>
public interface ISpliceObserver { void OnBytes(bool hostToViewer, ReadOnlySpan<byte> data); }

/// <summary>
/// Transport-agnostic relay: registers host IDs (in memory only), pairs a viewer with a host and splices the two
/// byte streams without interpreting them. Metadata-only logging.
/// </summary>
public sealed class RelayEngine
{
    private sealed class HostReg
    {
        public required string Id { get; init; }
        public required byte[] InstanceId { get; init; }
        public required FrameWriter Writer { get; init; }
        public required CancellationTokenSource Cts { get; init; }
        public bool Alive = true;
    }

    private sealed class Pending
    {
        public required HostReg Host { get; init; }
        public TaskCompletionSource<Stream> HostStream { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Done { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    }

    private readonly RelayOptions _o;
    private readonly ILogger _log;
    private readonly TimeProvider _time;
    private readonly ISpliceObserver? _observer;
    private readonly object _gate = new();
    private readonly Dictionary<string, HostReg> _hosts = new();
    private readonly ConcurrentDictionary<string, Pending> _pending = new();
    private readonly byte[] _keyHash;
    private readonly SlidingWindowLimiter _connects, _failedLookups, _registrations, _accepts;
    private int _sessions;

    public RelayEngine(RelayOptions options, ILogger log, TimeProvider? time = null, ISpliceObserver? observer = null)
    {
        _o = options;
        _log = log;
        _time = time ?? TimeProvider.System;
        _observer = observer;
        _keyHash = SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(options.AccessKey));
        var minute = TimeSpan.FromMinutes(1);
        _connects = new SlidingWindowLimiter(options.ConnectsPerMinutePerIp, minute, _time);
        _failedLookups = new SlidingWindowLimiter(options.FailedLookupsPerMinutePerIp, minute, _time);
        _registrations = new SlidingWindowLimiter(options.RegistrationsPerMinutePerIp, minute, _time);
        _accepts = new SlidingWindowLimiter(options.AcceptsPerMinutePerIp, minute, _time);
    }

    public int RegisteredHosts { get { lock (_gate) return _hosts.Count; } }
    public int ActiveSessions => Volatile.Read(ref _sessions);

    private bool KeyOk(string presented)
        => string.IsNullOrEmpty(_o.AccessKey) || CryptographicOperations.FixedTimeEquals(_keyHash, SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(presented)));

    /// <summary>Handles one inbound connection (already TLS-terminated by the transport). Caller disposes the stream afterwards.</summary>
    public async Task HandleAsync(Stream stream, IPAddress remote, CancellationToken ct)
    {
        var ip = remote.IsIPv4MappedToIPv6 ? remote.MapToIPv4().ToString() : remote.ToString();
        try
        {
            var reader = new FrameReader(stream, MessageTypes.IsKnownRelay, RelayLimits.MaxControlPayload);
            var writer = new FrameWriter(stream);
            Frame first;
            using (var c = CancellationTokenSource.CreateLinkedTokenSource(ct))
            {
                c.CancelAfter(TimeSpan.FromSeconds(10));
                first = await reader.ReadAsync(c.Token).ConfigureAwait(false);
            }
            switch ((RelayMessageType)first.Type)
            {
                case RelayMessageType.Register: await RegisterAsync(RegisterMessage.Parse(first.Payload), reader, writer, ip, ct).ConfigureAwait(false); break;
                case RelayMessageType.Accept: await AcceptAsync(AcceptMessage.Parse(first.Payload), stream, ip, ct).ConfigureAwait(false); break;
                case RelayMessageType.Connect: await ConnectAsync(ConnectMessage.Parse(first.Payload), stream, writer, ip, ct).ConfigureAwait(false); break;
                default: _log.LogDebug("unexpected first message from {Ip}", ip); break;
            }
        }
        catch (Exception e) when (e is ProtocolException or IOException or EndOfStreamException or OperationCanceledException or ObjectDisposedException)
        {
            _log.LogDebug("connection from {Ip} ended: {Error}", ip, e.GetType().Name);
        }
    }

    // ---- host control connection ------------------------------------------------------------------

    private async Task RegisterAsync(RegisterMessage m, FrameReader reader, FrameWriter writer, string ip, CancellationToken ct)
    {
        if (!_registrations.TryHit(ip) || !KeyOk(m.AccessKey) || !ConnectionId.IsValid(m.Id))
        {
            _log.LogWarning("register denied ip={Ip}", ip);
            await writer.WriteAsync(RelayMessageType.Denied, ct).ConfigureAwait(false);
            return;
        }
        var reg = new HostReg { Id = m.Id, InstanceId = m.InstanceId, Writer = writer, Cts = CancellationTokenSource.CreateLinkedTokenSource(ct) };
        lock (_gate)
        {
            if (_hosts.TryGetValue(m.Id, out var old))
            {
                if (CryptographicOperations.FixedTimeEquals(old.InstanceId, m.InstanceId))
                {
                    old.Alive = false; // same process re-registering after a dropped link
                    old.Cts.Cancel();
                }
                else if (old.Alive)
                {
                    reg = null!;
                }
            }
            else if (_hosts.Count >= _o.MaxRegisteredHosts) { reg = null!; }
            if (reg is not null) _hosts[m.Id] = reg;
        }
        if (reg is null)
        {
            // Both "ID taken" and "registry full" are answered without revealing which.
            bool taken;
            lock (_gate) taken = _hosts.ContainsKey(m.Id);
            await writer.WriteAsync(taken ? RelayMessageType.IdTaken : RelayMessageType.Denied, ct).ConfigureAwait(false);
            _log.LogInformation("register refused id={Id} ip={Ip} taken={Taken}", m.Id, ip, taken);
            return;
        }

        _log.LogInformation("host online id={Id} ip={Ip}", m.Id, ip);
        try
        {
            await writer.WriteAsync(RelayMessageType.Registered, reg.Cts.Token).ConfigureAwait(false);
            var ping = TimeSpan.FromSeconds(_o.PingIntervalSeconds);
            var pinger = PingLoopAsync(reg, ping);
            try
            {
                while (true)
                {
                    using var rc = CancellationTokenSource.CreateLinkedTokenSource(reg.Cts.Token);
                    rc.CancelAfter(ping * 3);
                    var f = await reader.ReadAsync(rc.Token).ConfigureAwait(false);
                    if (f.Type != (byte)RelayMessageType.RelayPong && f.Type != (byte)RelayMessageType.RelayPing) break;
                }
            }
            finally { reg.Cts.Cancel(); try { await pinger.ConfigureAwait(false); } catch { } }
        }
        catch (Exception e) when (e is IOException or OperationCanceledException or EndOfStreamException or ProtocolException or ObjectDisposedException) { }
        finally
        {
            reg.Alive = false;
            lock (_gate) { if (_hosts.TryGetValue(m.Id, out var cur) && ReferenceEquals(cur, reg)) _hosts.Remove(m.Id); }
            _log.LogInformation("host offline id={Id}", m.Id);
        }
    }

    private static async Task PingLoopAsync(HostReg reg, TimeSpan interval)
    {
        try
        {
            using var t = new PeriodicTimer(interval);
            while (await t.WaitForNextTickAsync(reg.Cts.Token).ConfigureAwait(false))
                await reg.Writer.WriteAsync(RelayMessageType.RelayPing, reg.Cts.Token).ConfigureAwait(false);
        }
        catch { reg.Cts.Cancel(); }
    }

    // ---- host data connection ---------------------------------------------------------------------

    private async Task AcceptAsync(AcceptMessage m, Stream stream, string ip, CancellationToken ct)
    {
        if (!_accepts.TryHit(ip) || !KeyOk(m.AccessKey)) return;
        var key = Convert.ToHexString(m.Token);
        if (!_pending.TryGetValue(key, out var p) || p.Host.Id != m.Id) return;
        if (!p.HostStream.TrySetResult(stream)) return;
        using var reg = ct.Register(() => p.Done.TrySetCanceled());
        try { await p.Done.Task.ConfigureAwait(false); } catch (OperationCanceledException) { }
    }

    // ---- viewer connection ------------------------------------------------------------------------

    private async Task ConnectAsync(ConnectMessage m, Stream viewer, FrameWriter viewerWriter, string ip, CancellationToken ct)
    {
        // Every failure mode below answers with the identical NotFound (no enumeration hints).
        async Task NotFound() => await viewerWriter.WriteAsync(RelayMessageType.NotFound, ct).ConfigureAwait(false);

        if (!KeyOk(m.AccessKey) || !ConnectionId.IsValid(m.Id) || !_connects.TryHit(ip) || _failedLookups.IsLimited(ip))
        {
            _failedLookups.Hit(ip);
            await NotFound().ConfigureAwait(false);
            return;
        }
        HostReg? host;
        lock (_gate) _hosts.TryGetValue(m.Id, out host);
        if (host is null || !host.Alive || ActiveSessions >= _o.MaxConcurrentSessions)
        {
            _failedLookups.Hit(ip);
            _log.LogInformation("connect not-found ip={Ip}", ip);
            await NotFound().ConfigureAwait(false);
            return;
        }

        var token = RandomNumberGenerator.GetBytes(RelayLimits.TokenLength);
        var key = Convert.ToHexString(token);
        var pending = new Pending { Host = host };
        _pending[key] = pending;
        Stream? hostStream = null;
        try
        {
            await host.Writer.WriteAsync(RelayMessageType.Incoming, new IncomingMessage(token, ip).Serialize(), ct).ConfigureAwait(false);
            hostStream = await pending.HostStream.Task.WaitAsync(TimeSpan.FromSeconds(_o.PendingTimeoutSeconds), ct).ConfigureAwait(false);
        }
        catch (Exception e) when (e is TimeoutException or IOException or OperationCanceledException or ObjectDisposedException)
        {
            _pending.TryRemove(key, out _);
            _failedLookups.Hit(ip);
            await NotFound().ConfigureAwait(false);
            return;
        }
        _pending.TryRemove(key, out _);

        Interlocked.Increment(ref _sessions);
        var sw = Stopwatch.StartNew();
        long toViewer = 0, toHost = 0;
        _log.LogInformation("session start id={Id} viewerIp={Ip}", m.Id, ip);
        try
        {
            await new FrameWriter(hostStream).WriteAsync(RelayMessageType.Ready, ct).ConfigureAwait(false);
            await viewerWriter.WriteAsync(RelayMessageType.Ready, ct).ConfigureAwait(false);
            (toHost, toViewer) = await SpliceAsync(viewer, hostStream, ct).ConfigureAwait(false);
        }
        catch (Exception e) when (e is IOException or OperationCanceledException or ObjectDisposedException) { }
        finally
        {
            Interlocked.Decrement(ref _sessions);
            pending.Done.TrySetResult();
            _log.LogInformation("session end id={Id} viewerIp={Ip} seconds={Seconds} bytesToHost={ToHost} bytesToViewer={ToViewer}",
                m.Id, ip, (int)sw.Elapsed.TotalSeconds, toHost, toViewer);
        }
    }

    /// <summary>Copies bytes both ways until either side closes or the link is idle. Never inspects content.</summary>
    private async Task<(long ToHost, long ToViewer)> SpliceAsync(Stream viewer, Stream host, CancellationToken ct)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var last = Stopwatch.GetTimestamp();
        long toHost = 0, toViewer = 0;
        var idle = TimeSpan.FromSeconds(_o.IdleTimeoutSeconds);

        async Task Pump(Stream from, Stream to, bool hostToViewer)
        {
            var buf = new byte[16 * 1024];
            try
            {
                while (true)
                {
                    var n = await from.ReadAsync(buf, cts.Token).ConfigureAwait(false);
                    if (n == 0) break;
                    _observer?.OnBytes(hostToViewer, buf.AsSpan(0, n));
                    await to.WriteAsync(buf.AsMemory(0, n), cts.Token).ConfigureAwait(false);
                    await to.FlushAsync(cts.Token).ConfigureAwait(false);
                    Volatile.Write(ref last, Stopwatch.GetTimestamp());
                    if (hostToViewer) Interlocked.Add(ref toViewer, n); else Interlocked.Add(ref toHost, n);
                }
            }
            catch (Exception e) when (e is IOException or OperationCanceledException or ObjectDisposedException) { }
            finally { cts.Cancel(); }
        }

        async Task Watchdog()
        {
            try
            {
                using var t = new PeriodicTimer(TimeSpan.FromSeconds(Math.Max(1, Math.Min(5, _o.IdleTimeoutSeconds / 2))));
                while (await t.WaitForNextTickAsync(cts.Token).ConfigureAwait(false))
                    if (Stopwatch.GetElapsedTime(Volatile.Read(ref last)) > idle) { cts.Cancel(); return; }
            }
            catch (OperationCanceledException) { }
        }

        await Task.WhenAll(Pump(viewer, host, false), Pump(host, viewer, true), Watchdog()).ConfigureAwait(false);
        await viewer.DisposeAsync().ConfigureAwait(false);
        await host.DisposeAsync().ConfigureAwait(false);
        return (toHost, toViewer);
    }

    /// <summary>Called on graceful shutdown: drop all host registrations so sessions can drain.</summary>
    public void DropAll()
    {
        lock (_gate) foreach (var h in _hosts.Values) h.Cts.Cancel();
    }
}
