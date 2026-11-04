using System.Diagnostics;
using RemoteTool.Core.Protocol;

namespace RemoteTool.Core.Session;

public sealed partial class HostService
{
    /// <summary>Consent, then the streaming/input phase. Runs while the session gate is held.</summary>
    private async Task RunSessionAsync(Security.SecureChannel ch, FrameReader reader, FrameWriter writer, PeerOrigin origin, string viewerName, CancellationToken ct)
    {
        var requestPayload = await ReadExpectedAsync(reader, MessageType.ConsentRequest, TimeSpan.FromSeconds(20), ct).ConfigureAwait(false);
        var requested = ConsentRequestMessage.Parse(requestPayload).Requested;
        var allowed = Policy.Allowed;

        ConsentDecision decision;
        using (var consentCts = CancellationTokenSource.CreateLinkedTokenSource(ct))
        {
            consentCts.CancelAfter(ProtocolConstants.ConsentTimeout);
            try
            {
                decision = await _consent.RequestAsync(new ConsentRequestInfo(viewerName, origin.Display, origin.ViaRelay, requested, allowed), consentCts.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested) { decision = new ConsentDecision(false, Permissions.None); }
        }

        var granted = decision.Granted ? decision.Permissions & allowed & requested : Permissions.None;
        if (!decision.Granted || granted == Permissions.None)
        {
            _audit.Write("consent_denied", ("source", origin.Display), ("viewer", viewerName));
            await writer.WriteAsync(MessageType.ConsentResult, new ConsentResultMessage(false, Permissions.None, ByeReason.Denied).Serialize(), ct).ConfigureAwait(false);
            return;
        }
        await writer.WriteAsync(MessageType.ConsentResult, new ConsentResultMessage(true, granted, ByeReason.Normal).Serialize(), ct).ConfigureAwait(false);

        var info = new SessionInfo(Guid.NewGuid(), viewerName, origin.Display, granted, DateTimeOffset.UtcNow);
        _audit.Write("consent_granted", ("session", info.Id), ("source", origin.Display), ("viewer", viewerName), ("permissions", granted));
        _audit.Write("session_start", ("session", info.Id), ("viewer", viewerName), ("source", origin.Display), ("permissions", granted));

        using var activeCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        _activeCts = activeCts;
        _activeEndReason = ByeReason.HostDisconnected;
        ActiveSession = info;
        var sw = Stopwatch.StartNew();
        var endReason = ByeReason.Normal;
        using var producer = _producerFactory();
        using var injector = _injectorFactory();
        try
        {
            SessionStarted?.Invoke(info);
            var monitors = producer.GetMonitors();
            var active = monitors.FirstOrDefault(m => m.Primary) ?? monitors[0];
            await writer.WriteAsync(MessageType.ScreenInfo, new ScreenInfoMessage(monitors, active.Index).Serialize(), activeCts.Token).ConfigureAwait(false);

            var inputCount = 0L;
            var pump = new SessionPump(reader, writer, f => HandleViewerFrame(f, granted, injector, active, ref inputCount), null, null);
            var video = VideoLoopAsync(producer, writer, active.Index, activeCts.Token);
            Task<ByeMessage?> read = pump.RunAsync(activeCts.Token);
            try
            {
                var done = await Task.WhenAny(read, video).ConfigureAwait(false);
                if (done == read) { var bye = await read.ConfigureAwait(false); endReason = bye?.Reason ?? ByeReason.Normal; }
                else await video.ConfigureAwait(false);
            }
            finally
            {
                activeCts.Cancel();
                await Task.WhenAll(Swallow(read), Swallow(video)).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) { endReason = _activeEndReason; }
        catch (TimeoutException) { endReason = ByeReason.Timeout; }
        catch (Exception e) when (e is ProtocolException or IOException or EndOfStreamException)
        {
            endReason = ByeReason.ProtocolError;
            _audit.Write("session_error", ("session", info.Id), ("error", e.GetType().Name));
        }
        finally
        {
            injector.ReleaseAll(); // never leave a key or button stuck down
            if (endReason == ByeReason.Normal && activeCts.IsCancellationRequested) endReason = _activeEndReason;
            try
            {
                using var bye = new CancellationTokenSource(TimeSpan.FromSeconds(2));
                await writer.WriteAsync(MessageType.Bye, new ByeMessage(endReason, "").Serialize(), bye.Token).ConfigureAwait(false);
            }
            catch { }
            ActiveSession = null;
            _activeCts = null;
            _audit.Write("session_end", ("session", info.Id), ("viewer", viewerName), ("reason", endReason),
                ("durationSeconds", (int)sw.Elapsed.TotalSeconds), ("bytesIn", reader.BytesRead), ("bytesOut", writer.BytesWritten));
            SessionEnded?.Invoke(info, endReason);
        }
    }

    private static async Task Swallow(Task t) { try { await t.ConfigureAwait(false); } catch { } }

    private static async Task<byte[]> ReadExpectedAsync(FrameReader r, MessageType t, TimeSpan timeout, CancellationToken ct)
    {
        using var c = CancellationTokenSource.CreateLinkedTokenSource(ct);
        c.CancelAfter(timeout);
        return await ReadExpected(r, t, c.Token).ConfigureAwait(false);
    }

    private ValueTask HandleViewerFrame(Frame f, Permissions granted, IInputInjector injector, MonitorInfo monitor, ref long inputCount)
    {
        switch ((MessageType)f.Type)
        {
            case MessageType.MouseEvent:
                var m = MouseEventMessage.Parse(f.Payload);
                if ((granted & Permissions.Control) != 0) injector.Mouse(monitor, m);
                break;
            case MessageType.KeyEvent:
                var k = KeyEventMessage.Parse(f.Payload);
                if ((granted & Permissions.Control) != 0) injector.Key(k);
                break;
            case MessageType.ClipboardData or MessageType.FileOffer or MessageType.FileChunk or MessageType.FileAck:
                break; // Phase 2 (policy-gated)
            default:
                throw new ProtocolException($"unexpected {(MessageType)f.Type} from viewer");
        }
        return ValueTask.CompletedTask;
    }

    /// <summary>Captures and sends updates at ~<see cref="TargetFps"/>; lowers JPEG quality when the link is slow.</summary>
    private async Task VideoLoopAsync(IFrameProducer producer, FrameWriter writer, int monitor, CancellationToken ct)
    {
        var interval = TimeSpan.FromMilliseconds(1000.0 / TargetFps);
        var quality = 70;
        var keyframe = true;
        var shape = (CursorShape)255;
        while (!ct.IsCancellationRequested)
        {
            var started = Stopwatch.GetTimestamp();
            var frame = await Task.Run(() => producer.NextFrame(monitor, quality, keyframe), ct).ConfigureAwait(false);
            keyframe = false;
            var sendStart = Stopwatch.GetTimestamp();
            if (frame is not null) await writer.WriteAsync(MessageType.FrameUpdate, frame.Serialize(), ct).ConfigureAwait(false);
            var sendTime = Stopwatch.GetElapsedTime(sendStart);
            if (sendTime > interval * 2) quality = Math.Max(40, quality - 10);
            else if (sendTime < interval / 2 && quality < 85) quality += 1;

            var s = producer.GetCursorShape();
            if (s != shape) { shape = s; await writer.WriteAsync(MessageType.CursorUpdate, new CursorUpdateMessage(s).Serialize(), ct).ConfigureAwait(false); }

            var remaining = interval - Stopwatch.GetElapsedTime(started);
            if (remaining > TimeSpan.Zero) await Task.Delay(remaining, ct).ConfigureAwait(false);
        }
    }
}
