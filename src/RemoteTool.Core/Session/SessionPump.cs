using System.Diagnostics;
using RemoteTool.Core.Protocol;

namespace RemoteTool.Core.Session;

/// <summary>
/// Post-handshake read loop shared by host and viewer: answers pings, measures latency, enforces the heartbeat
/// timeout, ends on Bye, and hands every other frame to the role-specific handler.
/// </summary>
internal sealed class SessionPump
{
    private readonly FrameReader _reader;
    private readonly FrameWriter _writer;
    private readonly Func<Frame, ValueTask> _onFrame;
    private readonly TimeSpan _interval;
    private readonly TimeSpan _timeout;
    private long _lastRx;
    private long _latencyMs;
    private bool _timedOut;

    public SessionPump(FrameReader reader, FrameWriter writer, Func<Frame, ValueTask> onFrame, TimeSpan? interval = null, TimeSpan? timeout = null)
    {
        _reader = reader;
        _writer = writer;
        _onFrame = onFrame;
        _interval = interval ?? ProtocolConstants.HeartbeatInterval;
        _timeout = timeout ?? ProtocolConstants.HeartbeatTimeout;
    }

    public TimeSpan Latency => TimeSpan.FromMilliseconds(Interlocked.Read(ref _latencyMs));

    /// <summary>Returns the peer's Bye (or null if it never arrived). Throws TimeoutException on heartbeat loss.</summary>
    public async Task<ByeMessage?> RunAsync(CancellationToken ct)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        Volatile.Write(ref _lastRx, Stopwatch.GetTimestamp());
        var heartbeat = HeartbeatAsync(cts);
        try
        {
            while (true)
            {
                var f = await _reader.ReadAsync(cts.Token).ConfigureAwait(false);
                Volatile.Write(ref _lastRx, Stopwatch.GetTimestamp());
                switch ((MessageType)f.Type)
                {
                    case MessageType.Ping:
                        await _writer.WriteAsync(MessageType.Pong, PingMessage.Parse(f.Payload).Serialize(), cts.Token).ConfigureAwait(false);
                        break;
                    case MessageType.Pong:
                        var sent = (long)PingMessage.Parse(f.Payload).Ticks;
                        Interlocked.Exchange(ref _latencyMs, Math.Max(0, Environment.TickCount64 - sent));
                        break;
                    case MessageType.Bye:
                        return ByeMessage.Parse(f.Payload);
                    default:
                        await _onFrame(f).ConfigureAwait(false);
                        break;
                }
            }
        }
        catch (OperationCanceledException) when (_timedOut && !ct.IsCancellationRequested)
        {
            throw new TimeoutException("peer heartbeat timed out");
        }
        finally
        {
            cts.Cancel();
            try { await heartbeat.ConfigureAwait(false); } catch { /* already reported via main loop */ }
        }
    }

    private async Task HeartbeatAsync(CancellationTokenSource cts)
    {
        try
        {
            using var timer = new PeriodicTimer(_interval);
            while (await timer.WaitForNextTickAsync(cts.Token).ConfigureAwait(false))
            {
                if (Stopwatch.GetElapsedTime(Volatile.Read(ref _lastRx)) > _timeout)
                {
                    _timedOut = true;
                    cts.Cancel();
                    return;
                }
                await _writer.WriteAsync(MessageType.Ping, new PingMessage((ulong)Environment.TickCount64).Serialize(), cts.Token).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception) { cts.Cancel(); }
    }
}
