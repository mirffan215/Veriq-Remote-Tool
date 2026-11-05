using System.Security.Cryptography;
using RemoteTool.Core.Audit;
using RemoteTool.Core.Protocol;
using RemoteTool.Core.Security;

namespace RemoteTool.Core.Session;

/// <summary>Viewer side of an authenticated, consented session.</summary>
public sealed class ViewerSession : IAsyncDisposable
{
    private readonly SecureChannel _channel;
    private readonly FrameReader _reader;
    private readonly FrameWriter _writer;
    private readonly IAuditLog _audit;
    private readonly CancellationTokenSource _cts = new();
    private readonly SessionPump _pump;
    private readonly Guid _id = Guid.NewGuid();
    private readonly DateTimeOffset _started = DateTimeOffset.UtcNow;
    private Task? _run;
    private int _ended;

    private ClipboardSync? _clipboard;
    private FileTransferService? _files;

    public string HostName { get; }
    /// <summary>Single-use ticket for <see cref="ViewerReconnect"/>; changes with every (re)connect. Treat like a password.</summary>
    public string ResumeToken { get; private set; } = "";
    public byte ActiveMonitor { get; private set; }
    /// <summary>6-digit code both people can compare; a different code on the two screens means someone is in the middle.</summary>
    public string SecurityCode { get; private set; } = "";
    /// <summary>True when no password was used: the other person's Accept click authorised this session (so the security code matters).</summary>
    public bool ConsentOnly { get; private set; }
    /// <summary>Codec currently used for the video stream (may fall back to tiles mid-session).</summary>
    public VideoCodecs Codec { get; private set; } = VideoCodecs.TileJpeg;
    /// <summary>True when the host records this session: the UI must show a clear REC indicator.</summary>
    public bool Recording { get; private set; }
    private IH264Decoder? _decoder;
    public Permissions Permissions { get; }
    public ScreenInfoMessage? Screen { get; private set; }
    public TimeSpan Latency => _pump.Latency;
    public long BytesReceived => _reader.BytesRead;
    public long BytesSent => _writer.BytesWritten;

    public event Action<ScreenInfoMessage>? ScreenInfoReceived;
    public event Action<FrameUpdateMessage>? FrameReceived;
    public event Action<CursorShape>? CursorChanged;
    public event Action<ByeReason, string>? Ended;
    /// <summary>A file arrived from the host and passed its SHA-256 check (final path).</summary>
    public event Action<string>? FileReceived;
    /// <summary>H.264 path: a fully decoded frame (BGRA, tight stride).</summary>
    public event Action<DecodedFrame>? FullFrameReceived;
    public event Action<VideoCodecs>? CodecChanged;

    private ViewerSession(SecureChannel ch, FrameReader r, FrameWriter w, string hostName, Permissions perms, IAuditLog audit)
    {
        _channel = ch;
        _reader = r;
        _writer = w;
        HostName = hostName;
        Permissions = perms;
        _audit = audit;
        _pump = new SessionPump(r, w, OnFrameAsync);
    }

    /// <summary>
    /// Runs TLS + password handshake + consent over an already-connected transport (direct TCP or relay splice).
    /// </summary>
    public static async Task<ViewerSession> ConnectAsync(Stream transport, string viewerName, string password, IAuditLog audit,
        Permissions requested, CancellationToken ct, bool resume = false, bool permanent = false, VideoCodecs codecs = VideoCodecs.TileJpeg,
        bool consentOnly = false, Action<string>? onSecurityCode = null)
    {
        using var cert = EphemeralCertificate.Create("RemoteTool viewer");
        SecureChannel ch;
        try
        {
            using var tlsCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            tlsCts.CancelAfter(ProtocolConstants.HandshakeTimeout);
            ch = await TlsChannel.ConnectAsync(transport, cert.Certificate, tlsCts.Token).ConfigureAwait(false);
        }
        catch (Exception e) when (e is not OperationCanceledException || !ct.IsCancellationRequested)
        {
            await transport.DisposeAsync().ConfigureAwait(false);
            throw new ConnectFailedException(ConnectFailure.Network, $"Secure channel could not be established ({(e.InnerException ?? e).GetType().Name}: {(e.InnerException ?? e).Message}). Both computers need Windows 10 (1809) / Server 2019 or newer and the same RemoteTool version.", e);
        }

        var reader = new FrameReader(ch.Stream, MessageTypes.IsKnownPeer, ProtocolConstants.PreAuthMaxFramePayload);
        var writer = new FrameWriter(ch.Stream);
        var securityCode = "";
        try
        {
            using var hs = CancellationTokenSource.CreateLinkedTokenSource(ct);
            hs.CancelAfter(ProtocolConstants.HandshakeTimeout);

            // Commit to our nonce first, reveal it only after the host has shown its own (see PasswordHandshake.SecurityCode).
            var nonceV = RandomNumberGenerator.GetBytes(ProtocolConstants.NonceLength);
            var mode = consentOnly ? AuthMode.Consent : permanent ? AuthMode.Permanent : resume ? AuthMode.Resume : AuthMode.OneTimePassword;
            await writer.WriteAsync(MessageType.Hello, new HelloMessage(ProtocolConstants.Version, NameSanitizer.Clean(viewerName, "viewer"), PasswordHandshake.Commit(nonceV), mode).Serialize(), hs.Token).ConfigureAwait(false);

            var challenge = AuthChallengeMessage.Parse(await Expect(reader, MessageType.AuthChallenge, hs.Token).ConfigureAwait(false));
            var key = consentOnly ? PasswordHandshake.ConsentModeKey : await Task.Run(() => PasswordHandshake.DeriveKey(password, challenge.Salt), hs.Token).ConfigureAwait(false);
            var proof = PasswordHandshake.ViewerProof(key, nonceV, challenge.Nonce, ch.LocalFingerprint, ch.RemoteFingerprint);
            // Both people can now compare this code (the host's Accept dialog shows the same one).
            securityCode = PasswordHandshake.SecurityCode(nonceV, challenge.Nonce, ch.LocalFingerprint, ch.RemoteFingerprint);
            onSecurityCode?.Invoke(securityCode);
            await writer.WriteAsync(MessageType.AuthResponse, new AuthResponseMessage(proof, nonceV).Serialize(), hs.Token).ConfigureAwait(false);

            var result = AuthResultMessage.Parse(await Expect(reader, MessageType.AuthResult, hs.Token).ConfigureAwait(false));
            if (!result.Success) throw Map(result.Failure);
            var expected = PasswordHandshake.HostProof(key, nonceV, challenge.Nonce, ch.LocalFingerprint, ch.RemoteFingerprint);
            if (!PasswordHandshake.ConstantTimeEquals(expected, result.HostProof))
                throw new ConnectFailedException(ConnectFailure.PeerAuthenticationFailed,
                    "The remote peer could not prove it knows the password (possible man-in-the-middle). Connection aborted.");
            reader.MaxPayload = ProtocolConstants.MaxFramePayload;

            await writer.WriteAsync(MessageType.ConsentRequest, new ConsentRequestMessage(requested, codecs | VideoCodecs.TileJpeg).Serialize(), hs.Token).ConfigureAwait(false);
            using var consentCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            consentCts.CancelAfter(ProtocolConstants.ConsentTimeout + TimeSpan.FromSeconds(30));
            var consent = ConsentResultMessage.Parse(await Expect(reader, MessageType.ConsentResult, consentCts.Token).ConfigureAwait(false));
            if (!consent.Granted) throw new ConnectFailedException(ConnectFailure.Denied, "The remote user denied the connection.");

            var s = new ViewerSession(ch, reader, writer, challenge.HostName, consent.GrantedPermissions, audit);
            s.SecurityCode = securityCode;
            s.ConsentOnly = consentOnly;
            s.Codec = consent.Codec;
            s.Recording = consent.Recording;
            s.ResumeToken = consent.ResumeToken is { Length: > 0 } t ? System.Text.Encoding.ASCII.GetString(t) : "";
            audit.Write("session_start", ("session", s._id), ("host", s.HostName), ("permissions", consent.GrantedPermissions));
            return s; // caller subscribes to events, then calls Start() so the first keyframe cannot be missed
        }
        catch (ConnectFailedException e)
        {
            audit.Write("connect_failed", ("reason", e.Failure));
            await ch.Stream.DisposeAsync().ConfigureAwait(false);
            throw;
        }
        catch (Exception e) when (e is OperationCanceledException && !ct.IsCancellationRequested)
        {
            await ch.Stream.DisposeAsync().ConfigureAwait(false);
            throw new ConnectFailedException(ConnectFailure.Timeout, "The remote side did not answer in time.", e);
        }
        catch (Exception e) when (e is ProtocolException or EndOfStreamException or IOException)
        {
            await ch.Stream.DisposeAsync().ConfigureAwait(false);
            throw new ConnectFailedException(ConnectFailure.Protocol, "The remote side closed the connection or sent invalid data.", e);
        }
    }

    /// <summary>Begins processing incoming frames. Call after subscribing to the events.</summary>
    public void Start()
    {
        if (_disposed == 0) _run ??= RunAsync();
    }

    private static ConnectFailedException Map(AuthFailure f) => f switch
    {
        AuthFailure.BadPassword => new(ConnectFailure.BadPassword, "Wrong password."),
        AuthFailure.Blocked => new(ConnectFailure.Blocked, "Too many failed attempts. This device is temporarily blocked."),
        AuthFailure.Busy => new(ConnectFailure.Busy, "The remote PC already has an active session."),
        AuthFailure.VersionMismatch => new(ConnectFailure.VersionMismatch, "Incompatible RemoteTool versions."),
        AuthFailure.PasswordRequired => new(ConnectFailure.PasswordRequired, "This PC only accepts connections with a password."),
        _ => new(ConnectFailure.NotAllowed, "This connection is not allowed by the remote PC."),
    };

    private static async Task<byte[]> Expect(FrameReader r, MessageType t, CancellationToken ct)
    {
        var f = await r.ReadAsync(ct).ConfigureAwait(false);
        if (f.Type == (byte)MessageType.Bye)
        {
            var bye = ByeMessage.Parse(f.Payload);
            throw new ConnectFailedException(bye.Reason == ByeReason.Denied ? ConnectFailure.Denied : ConnectFailure.Protocol, bye.Text.Length > 0 ? bye.Text : "Connection closed by the remote PC.");
        }
        if (f.Type != (byte)t) throw new ProtocolException($"expected {t}, got {(MessageType)f.Type}");
        return f.Payload;
    }

    private async ValueTask OnFrameAsync(Frame f)
    {
        switch ((MessageType)f.Type)
        {
            case MessageType.ScreenInfo:
                Screen = ScreenInfoMessage.Parse(f.Payload);
                ActiveMonitor = Screen.ActiveMonitor;
                ScreenInfoReceived?.Invoke(Screen);
                break;
            case MessageType.FrameUpdate:
                FrameReceived?.Invoke(FrameUpdateMessage.Parse(f.Payload));
                break;
            case MessageType.CursorUpdate:
                CursorChanged?.Invoke(CursorUpdateMessage.Parse(f.Payload).Shape);
                break;
            case MessageType.VideoFrame:
                await OnVideoFrameAsync(VideoFrameMessage.Parse(f.Payload)).ConfigureAwait(false);
                break;
            case MessageType.CodecSwitch:
                Codec = CodecSwitchMessage.Parse(f.Payload).Codec;
                CodecChanged?.Invoke(Codec);
                break;
            case MessageType.ClipboardData:
                ClipboardDataMessage.Parse(f.Payload);
                _clipboard?.Receive(f.Payload);
                break;
            case MessageType.FileOffer or MessageType.FileChunk or MessageType.FileAck:
                if (_files is not null) await _files.HandleAsync(f, _cts.Token).ConfigureAwait(false);
                else if (f.Type == (byte)MessageType.FileOffer)
                    await _writer.WriteAsync(MessageType.FileAck, new FileAckMessage(FileOfferMessage.Parse(f.Payload).TransferId, FileStatus.Reject, 0).Serialize(), _cts.Token).ConfigureAwait(false);
                break;
            default:
                throw new ProtocolException($"unexpected {(MessageType)f.Type} from host");
        }
    }

    /// <summary>Provide the decoder before <see cref="Start"/>; only needed if H.264 was offered in <c>codecs</c>.</summary>
    public void AttachH264Decoder(IH264Decoder decoder) => _decoder = decoder;

    private async Task OnVideoFrameAsync(VideoFrameMessage v)
    {
        if (Codec != VideoCodecs.H264 || _decoder is null)
        {
            // We never offered/accepted H.264 (or lost the decoder): drop and insist on tiles.
            await RequestTileCodecAsync().ConfigureAwait(false);
            return;
        }
        DecodedFrame? frame;
        DecodeStatus st;
        try { st = _decoder.TryDecode(v.Data, v.Keyframe, out frame); }
        catch (Exception e) when (e is not OutOfMemoryException) { st = DecodeStatus.Failed; frame = null; }
        if (st == DecodeStatus.Frame && frame is not null) FullFrameReceived?.Invoke(frame);
        else if (st == DecodeStatus.Failed) await RequestTileCodecAsync().ConfigureAwait(false);
    }

    private async Task RequestTileCodecAsync()
    {
        if (Codec == VideoCodecs.TileJpeg) return;
        Codec = VideoCodecs.TileJpeg;
        _audit.Write("codec_fallback", ("by", "viewer"));
        CodecChanged?.Invoke(Codec);
        await SafeSend(MessageType.CodecSwitch, new CodecSwitchMessage(VideoCodecs.TileJpeg).Serialize()).ConfigureAwait(false);
    }

    public Task SendSpecialKeyAsync(SpecialKeyKind kind) => (Permissions & Permissions.Control) == 0 ? Task.CompletedTask : SafeSend(MessageType.SpecialKey, new SpecialKeyMessage(kind).Serialize());

    /// <summary>Enable clipboard sync (needs the Clipboard permission). Call before <see cref="Start"/>.</summary>
    public void AttachClipboard(IClipboardAccess clipboard)
    {
        if ((Permissions & Permissions.Clipboard) == 0) { clipboard.Dispose(); return; }
        _clipboard = new ClipboardSync(clipboard, p => _writer.WriteAsync(MessageType.ClipboardData, p, _cts.Token), _audit);
        _clipboard.Start();
    }

    /// <summary>Enable file transfer in both directions (needs the FileTransfer permission). Call before <see cref="Start"/>.</summary>
    public void AttachFileTransfer(IFileTransferPrompt prompt, FileTransferOptions options)
    {
        if ((Permissions & Permissions.FileTransfer) == 0) return;
        _files = new FileTransferService(_writer, prompt, options, _audit, HostName);
        _files.FileReceived += p => FileReceived?.Invoke(p);
    }

    public bool CanTransferFiles => _files is not null;

    public Task<FileSendOutcome> SendFileAsync(string path, IProgress<long>? progress = null, CancellationToken ct = default)
        => _files is { } f ? f.SendAsync(path, progress, ct) : Task.FromResult(FileSendOutcome.Failed);

    public Task SelectMonitorAsync(byte index) => SafeSend(MessageType.MonitorSelect, new MonitorSelectMessage(index).Serialize());

    private async Task RunAsync()
    {
        var reason = ByeReason.Normal;
        var text = "";
        try
        {
            var bye = await _pump.RunAsync(_cts.Token).ConfigureAwait(false);
            if (bye is not null) { reason = bye.Reason; text = bye.Text; }
        }
        catch (OperationCanceledException) { }
        catch (TimeoutException) { reason = ByeReason.Timeout; text = "connection lost"; }
        catch (Exception e) when (e is ProtocolException or IOException or EndOfStreamException) { reason = ByeReason.ProtocolError; text = "connection error"; }
        Finish(reason, text);
    }

    private void Finish(ByeReason reason, string text)
    {
        if (Interlocked.Exchange(ref _ended, 1) == 1) return;
        _audit.Write("session_end", ("session", _id), ("reason", reason), ("durationSeconds", (int)(DateTimeOffset.UtcNow - _started).TotalSeconds),
            ("bytesIn", BytesReceived), ("bytesOut", BytesSent));
        try { _files?.Dispose(); _clipboard?.Dispose(); _decoder?.Dispose(); } catch { }
        try { _channel.Stream.Dispose(); } catch { }
        Ended?.Invoke(reason, text);
    }

    public Task SendMouseAsync(MouseEventMessage m) => (Permissions & Permissions.Control) == 0 ? Task.CompletedTask : SafeSend(MessageType.MouseEvent, m.Serialize());
    public Task SendKeyAsync(KeyEventMessage k) => (Permissions & Permissions.Control) == 0 ? Task.CompletedTask : SafeSend(MessageType.KeyEvent, k.Serialize());

    private async Task SafeSend(MessageType t, byte[] payload)
    {
        try { await _writer.WriteAsync(t, payload, _cts.Token).ConfigureAwait(false); }
        catch (Exception e) when (e is IOException or OperationCanceledException or ObjectDisposedException) { }
    }

    private int _disposed;

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 1) return;
        try { using var c = new CancellationTokenSource(TimeSpan.FromSeconds(2)); await _writer.WriteAsync(MessageType.Bye, new ByeMessage(ByeReason.Normal, "").Serialize(), c.Token).ConfigureAwait(false); }
        catch { }
        _cts.Cancel();
        if (_run is not null) { try { await _run.ConfigureAwait(false); } catch { } }
        Finish(ByeReason.Normal, "");
        _cts.Dispose();
    }
}
