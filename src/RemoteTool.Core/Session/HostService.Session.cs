using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using RemoteTool.Core.Protocol;

namespace RemoteTool.Core.Session;

public sealed partial class HostService
{
    private FileTransferService? _activeFiles;

    private sealed class SessionState
    {
        public volatile MonitorInfo Monitor = null!;
        public int KeyframeRequested = 1;
        public IReadOnlyList<MonitorInfo> Monitors = Array.Empty<MonitorInfo>();
    }

    /// <summary>Consent (or automatic grant when resuming), then the streaming/input phase. Runs while the session gate is held.</summary>
    private async Task RunSessionAsync(Security.SecureChannel ch, FrameReader reader, FrameWriter writer, PeerOrigin origin, AuthOutcome auth, CancellationToken ct)
    {
        var viewerName = auth.ViewerName;
        var requestPayload = await ReadExpectedAsync(reader, MessageType.ConsentRequest, TimeSpan.FromSeconds(20), ct).ConfigureAwait(false);
        var requested = ConsentRequestMessage.Parse(requestPayload).Requested;
        var allowed = Policy.Allowed;

        ConsentDecision decision;
        if (auth.Resumed is { } old)
        {
            // Reconnect of an already-consented session: same permissions, never more than the policy allows now.
            decision = new ConsentDecision(true, old.Permissions);
            _audit.Write("session_resumed", ("source", origin.Display), ("viewer", viewerName));
        }
        else
        {
            using var consentCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            consentCts.CancelAfter(ProtocolConstants.ConsentTimeout);
            try
            {
                decision = await _consent.RequestAsync(new ConsentRequestInfo(viewerName, origin.Display, origin.ViaRelay, requested, allowed), consentCts.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested) { decision = new ConsentDecision(false, Permissions.None); }
        }

        var granted = decision.Granted ? decision.Permissions & allowed & requested : Permissions.None;
        // Clicking Allow with every box cleared is a valid view-only grant.
        var allow = decision.Granted;
        if (!allow)
        {
            _audit.Write("consent_denied", ("source", origin.Display), ("viewer", viewerName));
            await writer.WriteAsync(MessageType.ConsentResult, new ConsentResultMessage(false, Permissions.None, ByeReason.Denied).Serialize(), ct).ConfigureAwait(false);
            return;
        }

        var ticket = new ResumeTicket { Secret = Convert.ToHexString(RandomNumberGenerator.GetBytes(24)), Permissions = granted, ViewerName = viewerName };
        _ticket = ticket;
        await writer.WriteAsync(MessageType.ConsentResult, new ConsentResultMessage(true, granted, ByeReason.Normal, Encoding.ASCII.GetBytes(ticket.Secret)).Serialize(), ct).ConfigureAwait(false);

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
        FileTransferService? files = null;
        ClipboardSync? clipboard = null;
        try
        {
            SessionStarted?.Invoke(info);
            var state = new SessionState { Monitors = producer.GetMonitors() };
            state.Monitor = state.Monitors.FirstOrDefault(m => m.Primary) ?? state.Monitors[0];
            await writer.WriteAsync(MessageType.ScreenInfo, new ScreenInfoMessage(state.Monitors, state.Monitor.Index).Serialize(), activeCts.Token).ConfigureAwait(false);

            if ((granted & Permissions.FileTransfer) != 0 && _filePrompt is not null)
                _activeFiles = files = new FileTransferService(writer, _filePrompt, new FileTransferOptions(_receiveDirectory), _audit, viewerName);
            if ((granted & Permissions.Clipboard) != 0 && _clipboardFactory is not null)
            {
                clipboard = new ClipboardSync(_clipboardFactory(), p => writer.WriteAsync(MessageType.ClipboardData, p, activeCts.Token), _audit);
                clipboard.Start();
            }

            var pump = new SessionPump(reader, writer, f => HandleViewerFrame(f, granted, injector, state, writer, files, clipboard, activeCts.Token));
            var video = VideoLoopAsync(producer, writer, state, activeCts.Token);
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
            clipboard?.Dispose();
            files?.Dispose();
            _activeFiles = null;
            if (endReason == ByeReason.Normal && activeCts.IsCancellationRequested) endReason = _activeEndReason;
            // Only an abnormal end (network loss) keeps the resume ticket alive, and only for a short window.
            if (ReferenceEquals(_ticket, ticket))
            {
                if (endReason is ByeReason.Timeout or ByeReason.ProtocolError) ticket.ExpiresAt = _time.GetUtcNow() + ProtocolConstants.ResumeWindow;
                else _ticket = null;
            }
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

    private async ValueTask HandleViewerFrame(Frame f, Permissions granted, IInputInjector injector, SessionState state, FrameWriter writer,
        FileTransferService? files, ClipboardSync? clipboard, CancellationToken ct)
    {
        switch ((MessageType)f.Type)
        {
            case MessageType.MouseEvent:
                var m = MouseEventMessage.Parse(f.Payload);
                if ((granted & Permissions.Control) != 0) injector.Mouse(state.Monitor, m);
                break;
            case MessageType.KeyEvent:
                var k = KeyEventMessage.Parse(f.Payload);
                if ((granted & Permissions.Control) != 0) injector.Key(k);
                break;
            case MessageType.MonitorSelect:
                var sel = MonitorSelectMessage.Parse(f.Payload);
                var target = state.Monitors.FirstOrDefault(x => x.Index == sel.Index);
                if (target is not null && target != state.Monitor)
                {
                    state.Monitor = target;
                    Interlocked.Exchange(ref state.KeyframeRequested, 1);
                    await writer.WriteAsync(MessageType.ScreenInfo, new ScreenInfoMessage(state.Monitors, target.Index).Serialize(), ct).ConfigureAwait(false);
                }
                break;
            case MessageType.ClipboardData:
                var cp = ClipboardDataMessage.Parse(f.Payload); // always validate, even if we then drop it
                if (clipboard is not null) clipboard.Receive(f.Payload); else _audit.Write("clipboard_blocked", ("reason", "not-permitted"), ("bytes", cp.Text.Length));
                break;
            case MessageType.FileOffer or MessageType.FileChunk or MessageType.FileAck:
                if (files is not null) await files.HandleAsync(f, ct).ConfigureAwait(false);
                else if (f.Type == (byte)MessageType.FileOffer)
                {
                    var o = FileOfferMessage.Parse(f.Payload);
                    _audit.Write("file_rejected", ("reason", "not-permitted"));
                    await writer.WriteAsync(MessageType.FileAck, new FileAckMessage(o.TransferId, FileStatus.Reject, 0).Serialize(), ct).ConfigureAwait(false);
                }
                break;
            default:
                throw new ProtocolException($"unexpected {(MessageType)f.Type} from viewer");
        }
    }

    /// <summary>Captures and sends updates, adapting JPEG quality and frame rate to how fast the link drains.</summary>
    private async Task VideoLoopAsync(IFrameProducer producer, FrameWriter writer, SessionState state, CancellationToken ct)
    {
        var adaptive = new AdaptiveQuality();
        var shape = (CursorShape)255;
        while (!ct.IsCancellationRequested)
        {
            var started = Stopwatch.GetTimestamp();
            var monitor = state.Monitor;
            var key = Interlocked.Exchange(ref state.KeyframeRequested, 0) == 1;
            var quality = adaptive.Quality;
            var frame = await Task.Run(() => producer.NextFrame(monitor.Index, quality, key), ct).ConfigureAwait(false);
            if (frame is not null)
            {
                var sendStart = Stopwatch.GetTimestamp();
                await writer.WriteAsync(MessageType.FrameUpdate, frame.Serialize(), ct).ConfigureAwait(false);
                adaptive.Report(Stopwatch.GetElapsedTime(sendStart));
            }
            var s = producer.GetCursorShape();
            if (s != shape) { shape = s; await writer.WriteAsync(MessageType.CursorUpdate, new CursorUpdateMessage(s).Serialize(), ct).ConfigureAwait(false); }

            var remaining = adaptive.Interval - Stopwatch.GetElapsedTime(started);
            if (remaining > TimeSpan.Zero) await Task.Delay(remaining, ct).ConfigureAwait(false);
        }
    }
}
