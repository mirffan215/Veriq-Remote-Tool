using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using RemoteTool.Core.Protocol;
using RemoteTool.Core.Recording;
using RemoteTool.Core.Security;

namespace RemoteTool.Core.Session;

public sealed partial class HostService
{
    private FileTransferService? _activeFiles;

    private sealed class SessionState
    {
        public volatile MonitorInfo Monitor = null!;
        public int KeyframeRequested = 1;
        public int Codec = (int)VideoCodecs.TileJpeg;
        public IReadOnlyList<MonitorInfo> Monitors = Array.Empty<MonitorInfo>();
        public ISessionRecorder? Recorder;
    }

    /// <summary>Consent (or automatic grant when resuming / unattended), then the streaming/input phase. Runs while the session gate is held.</summary>
    private async Task RunSessionAsync(Security.SecureChannel ch, FrameReader reader, FrameWriter writer, PeerOrigin origin, AuthOutcome auth, CancellationToken ct)
    {
        var viewerName = auth.ViewerName;
        var req = ConsentRequestMessage.Parse(await ReadExpectedAsync(reader, MessageType.ConsentRequest, TimeSpan.FromSeconds(20), ct).ConfigureAwait(false));
        var requested = req.Requested;
        var unattendedSession = auth.Mode == AuthMode.Permanent;
        // An unattended session never gets more than the service-level unattended policy, whatever the viewer asks for.
        var allowed = unattendedSession ? Policy.Allowed & _unattended!.Permissions : Policy.Allowed;

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
            var ask = new ConsentRequestInfo(viewerName, origin.Display, origin.ViaRelay, requested, allowed, Recording: _recorderFactory is not null,
                SecurityCode: auth.SecurityCode, ConsentOnly: auth.Mode == AuthMode.Consent);
            try
            {
                decision = unattendedSession
                    ? await _unattended!.DecideAsync(ask, consentCts.Token).ConfigureAwait(false)
                    : await _consent.RequestAsync(ask, consentCts.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested) { decision = new ConsentDecision(false, Permissions.None); }
        }

        var granted = decision.Granted ? decision.Permissions & allowed & requested : Permissions.None;
        // Clicking Allow with every box cleared is a valid view-only grant.
        if (!decision.Granted)
        {
            _audit.Write("consent_denied", ("source", origin.Display), ("viewer", viewerName), ("unattended", unattendedSession));
            // A click-only request has no password to guess, so repeated refusals are the abuse signal: 5 denials/timeouts block the source for 15 minutes.
            if (auth.Mode == AuthMode.Consent && _lockout.RegisterFailure(origin.SourceKey))
                _audit.Write("source_blocked", ("source", origin.Display), ("minutes", (int)AuthLockout.BlockDuration.TotalMinutes), ("reason", "repeated-denied-requests"));
            await writer.WriteAsync(MessageType.ConsentResult, new ConsentResultMessage(false, Permissions.None, ByeReason.Denied).Serialize(), ct).ConfigureAwait(false);
            return;
        }

        if (auth.Mode == AuthMode.Consent) _lockout.RegisterSuccess(origin.SourceKey);   // accepted: the requester is no longer a nuisance
        using var producer = _producerFactory();
        using var injector = _injectorFactory();
        var codec = (req.Codecs & VideoCodecs.H264) != 0 && producer is IH264Source { H264Available: true } ? VideoCodecs.H264 : VideoCodecs.TileJpeg;

        var info = new SessionInfo(Guid.NewGuid(), viewerName, origin.Display, granted, DateTimeOffset.UtcNow);
        var recorder = _recorderFactory?.Create(info, Policy.DisplayName);
        var ticket = new ResumeTicket { Secret = Convert.ToHexString(RandomNumberGenerator.GetBytes(24)), Permissions = granted, ViewerName = viewerName };
        _ticket = ticket;
        await writer.WriteAsync(MessageType.ConsentResult,
            new ConsentResultMessage(true, granted, ByeReason.Normal, Encoding.ASCII.GetBytes(ticket.Secret), codec, recorder is not null).Serialize(), ct).ConfigureAwait(false);

        _audit.Write("consent_granted", ("session", info.Id), ("source", origin.Display), ("viewer", viewerName), ("permissions", granted), ("unattended", unattendedSession), ("codec", codec));
        _audit.Write("session_start", ("session", info.Id), ("viewer", viewerName), ("source", origin.Display), ("permissions", granted));
        if (recorder is not null) _audit.Write("recording_started", ("session", info.Id));

        using var activeCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        _activeCts = activeCts;
        _activeEndReason = ByeReason.HostDisconnected;
        ActiveSession = info;
        var sw = Stopwatch.StartNew();
        var endReason = ByeReason.Normal;
        FileTransferService? files = null;
        ClipboardSync? clipboard = null;
        try
        {
            SessionStarted?.Invoke(info);
            var state = new SessionState { Monitors = producer.GetMonitors(), Codec = (int)codec, Recorder = recorder };
            state.Monitor = state.Monitors.FirstOrDefault(m => m.Primary) ?? state.Monitors[0];
            await writer.WriteAsync(MessageType.ScreenInfo, new ScreenInfoMessage(state.Monitors, state.Monitor.Index).Serialize(), activeCts.Token).ConfigureAwait(false);

            if ((granted & Permissions.FileTransfer) != 0 && _filePrompt is not null)
                _activeFiles = files = new FileTransferService(writer, _filePrompt, new FileTransferOptions(_receiveDirectory), _audit, viewerName);
            if ((granted & Permissions.Clipboard) != 0 && _clipboardFactory is not null)
            {
                clipboard = new ClipboardSync(_clipboardFactory(), p => writer.WriteAsync(MessageType.ClipboardData, p, activeCts.Token), _audit);
                clipboard.Start();
            }

            var pump = new SessionPump(reader, writer, f => HandleViewerFrame(f, granted, injector, state, writer, files, clipboard, info, activeCts.Token));
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
            if (recorder is not null)
            {
                var done = recorder.Complete(endReason.ToString());
                recorder.Dispose();
                if (done is { } d) _audit.Write("recording_stopped", ("session", info.Id), ("file", Path.GetFileName(d.Path)), ("sha256", d.Sha256));
            }
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
        FileTransferService? files, ClipboardSync? clipboard, SessionInfo info, CancellationToken ct)
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
            case MessageType.SpecialKey:
                SpecialKeyMessage.Parse(f.Payload);
                if ((granted & Permissions.Control) != 0 && injector is ISpecialKeys sk)
                {
                    _audit.Write("special_key", ("session", info.Id), ("kind", "CtrlAltDel"));
                    sk.SendCtrlAltDel();
                }
                else _audit.Write("special_key_unavailable", ("session", info.Id));
                break;
            case MessageType.CodecSwitch:
                // Viewer's decoder failed: it asks for the mandatory tile codec. Anything else is ignored (the host decides on H.264).
                if (CodecSwitchMessage.Parse(f.Payload).Codec == VideoCodecs.TileJpeg && Interlocked.Exchange(ref state.Codec, (int)VideoCodecs.TileJpeg) != (int)VideoCodecs.TileJpeg)
                {
                    Interlocked.Exchange(ref state.KeyframeRequested, 1);
                    _audit.Write("codec_fallback", ("session", info.Id), ("by", "viewer"));
                }
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

    /// <summary>Captures and sends updates (H.264 when negotiated and healthy, tile-JPEG otherwise), adapting to how fast the link drains.</summary>
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
            byte[]? payload = null;
            MessageType type = MessageType.FrameUpdate;

            if ((VideoCodecs)Volatile.Read(ref state.Codec) == VideoCodecs.H264 && producer is IH264Source h264)
            {
                try
                {
                    var vf = await Task.Run(() => h264.NextH264(monitor.Index, key, 800 + (quality - AdaptiveQuality.MinQuality) * 100), ct).ConfigureAwait(false);
                    if (vf is not null) { payload = vf.Serialize(); type = MessageType.VideoFrame; state.Recorder?.WriteVideo(vf); }
                }
                catch (CodecUnavailableException e)
                {
                    // Encoder died or is unsupported on this GPU/driver: tell the viewer, restart the stream as tiles from a keyframe.
                    Volatile.Write(ref state.Codec, (int)VideoCodecs.TileJpeg);
                    _audit.Write("codec_fallback", ("by", "host"), ("reason", e.Message));
                    await writer.WriteAsync(MessageType.CodecSwitch, new CodecSwitchMessage(VideoCodecs.TileJpeg).Serialize(), ct).ConfigureAwait(false);
                    Interlocked.Exchange(ref state.KeyframeRequested, 1);
                    continue;
                }
            }
            else
            {
                var frame = await Task.Run(() => producer.NextFrame(monitor.Index, quality, key), ct).ConfigureAwait(false);
                if (frame is not null) { payload = frame.Serialize(); state.Recorder?.WriteFrame(frame); }
            }

            if (payload is not null)
            {
                var sendStart = Stopwatch.GetTimestamp();
                await writer.WriteAsync(type, payload, ct).ConfigureAwait(false);
                adaptive.Report(Stopwatch.GetElapsedTime(sendStart));
            }
            var s = producer.GetCursorShape();
            if (s != shape) { shape = s; await writer.WriteAsync(MessageType.CursorUpdate, new CursorUpdateMessage(s).Serialize(), ct).ConfigureAwait(false); }

            var remaining = adaptive.Interval - Stopwatch.GetElapsedTime(started);
            if (remaining > TimeSpan.Zero) await Task.Delay(remaining, ct).ConfigureAwait(false);
        }
    }
}
