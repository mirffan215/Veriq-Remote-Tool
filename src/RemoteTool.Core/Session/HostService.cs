using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using RemoteTool.Core.Audit;
using RemoteTool.Core.Protocol;
using RemoteTool.Core.Security;

namespace RemoteTool.Core.Session;

/// <summary>Where an incoming connection came from. For relay connections the address is only what the relay claims.</summary>
public sealed record PeerOrigin(string SourceKey, string Display, bool ViaRelay, IPAddress? Address);

/// <summary>
/// Host side: accepts connections (direct or via relay), authenticates, asks for consent, then streams the screen
/// and injects input. One active session at a time. UI-free.
/// </summary>
public sealed partial class HostService : IAsyncDisposable
{
    private const int MaxPreAuth = 4;
    private const int TargetFps = 20;

    private readonly Func<IFrameProducer> _producerFactory;
    private readonly Func<IInputInjector> _injectorFactory;
    private readonly IConsentProvider _consent;
    private readonly IAuditLog _audit;
    private readonly AuthLockout _lockout;
    private readonly SemaphoreSlim _sessionGate = new(1, 1);
    private readonly CancellationTokenSource _lifetime = new();
    private readonly object _pwGate = new();
    private string _password = PasswordGenerator.Generate();
    private int _preAuth;
    private CancellationTokenSource? _activeCts;
    private ByeReason _activeEndReason = ByeReason.HostDisconnected;

    private readonly Func<IClipboardAccess>? _clipboardFactory;
    private readonly IFileTransferPrompt? _filePrompt;
    private readonly string _receiveDirectory;
    private readonly TimeProvider _time;
    private ResumeTicket? _ticket;

    /// <summary>Single-use credential letting the same viewer resume after a network drop without a new password/consent dialog.</summary>
    private sealed class ResumeTicket
    {
        public required string Secret { get; init; }
        public required Permissions Permissions { get; init; }
        public required string ViewerName { get; init; }
        public DateTimeOffset? ExpiresAt; // null while the session is alive
    }

    public HostService(Func<IFrameProducer> producerFactory, Func<IInputInjector> injectorFactory, IConsentProvider consent,
        IAuditLog audit, HostPolicy policy, AuthLockout? lockout = null,
        Func<IClipboardAccess>? clipboardFactory = null, IFileTransferPrompt? filePrompt = null, string? receiveDirectory = null,
        TimeProvider? time = null)
    {
        _clipboardFactory = clipboardFactory;
        _filePrompt = filePrompt;
        _receiveDirectory = receiveDirectory ?? Path.Combine(Path.GetTempPath(), "RemoteTool Received");
        _time = time ?? TimeProvider.System;
        _producerFactory = producerFactory;
        _injectorFactory = injectorFactory;
        _consent = consent;
        _audit = audit;
        Policy = policy;
        _lockout = lockout ?? new AuthLockout();
    }

    /// <summary>Current policy snapshot. Replace the whole record to change policy; takes effect for new connections.</summary>
    public HostPolicy Policy { get => Volatile.Read(ref _policy); set { Volatile.Write(ref _policy, value); } }
    private HostPolicy _policy = null!;

    public SessionInfo? ActiveSession { get; private set; }
    public event Action? PasswordChanged;
    public event Action<SessionInfo>? SessionStarted;
    public event Action<SessionInfo, ByeReason>? SessionEnded;

    public string Password { get { lock (_pwGate) return _password; } }

    /// <summary>Generates and activates a fresh one-time password.</summary>
    public void RotatePassword()
    {
        lock (_pwGate) _password = PasswordGenerator.Generate();
        PasswordChanged?.Invoke();
    }

    /// <summary>Ends the active session (user pressed Disconnect or the emergency hotkey).</summary>
    public void DisconnectActive(ByeReason reason = ByeReason.HostDisconnected)
    {
        _activeEndReason = reason;
        try { _activeCts?.Cancel(); } catch (ObjectDisposedException) { }
    }

    /// <summary>Sends a file to the viewer of the active session (needs FileTransfer permission and a prompt-capable peer).</summary>
    public Task<FileSendOutcome> SendFileAsync(string path, IProgress<long>? progress = null, CancellationToken ct = default)
        => _activeFiles is { } f ? f.SendAsync(path, progress, ct) : Task.FromResult(FileSendOutcome.Failed);

    private bool IpAllowed(IPAddress? ip)
    {
        var list = Policy.IpAllowList;
        if (list is null || list.Count == 0) return true;
        if (ip is null) return false;
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        return list.Any(e => IPAddress.TryParse(e.Trim(), out var a) && a.Equals(ip));
    }

    /// <summary>Entry point for every incoming transport (takes ownership of <paramref name="raw"/>).</summary>
    public async Task HandleConnectionAsync(Stream raw, PeerOrigin origin, CancellationToken ct = default)
    {
        using var link = CancellationTokenSource.CreateLinkedTokenSource(ct, _lifetime.Token);
        var token = link.Token;
        if (Interlocked.Increment(ref _preAuth) > MaxPreAuth)
        {
            Interlocked.Decrement(ref _preAuth);
            await raw.DisposeAsync().ConfigureAwait(false);
            return;
        }
        var preAuthHeld = true;
        SecureChannel? ch = null;
        try
        {
            if (!IpAllowed(origin.Address))
            {
                _audit.Write("connection_rejected", ("source", origin.Display), ("reason", "not-in-allow-list"));
                return;
            }
            if (_lockout.IsBlocked(origin.SourceKey))
            {
                _audit.Write("connection_rejected", ("source", origin.Display), ("reason", "blocked"));
                return;
            }
            _audit.Write("connection_attempt", ("source", origin.Display), ("viaRelay", origin.ViaRelay));

            using var cert = EphemeralCertificate.Create("RemoteTool host");
            using (var tlsCts = CancellationTokenSource.CreateLinkedTokenSource(token))
            {
                tlsCts.CancelAfter(ProtocolConstants.HandshakeTimeout);
                ch = await TlsChannel.AcceptAsync(raw, cert.Certificate, tlsCts.Token).ConfigureAwait(false);
            }
            raw = Stream.Null; // ownership moved to the TLS stream

            var reader = new FrameReader(ch.Stream, MessageTypes.IsKnownPeer, ProtocolConstants.PreAuthMaxFramePayload);
            var writer = new FrameWriter(ch.Stream);

            var auth = await AuthenticateAsync(ch, reader, writer, origin, token).ConfigureAwait(false);
            if (auth is null) return;

            var gotGate = _sessionGate.Wait(0);
            if (!gotGate && auth.Resumed is not null)
            {
                // Same viewer coming back before we noticed the old connection died: retire the stale session first.
                _activeEndReason = ByeReason.Timeout;
                try { _activeCts?.Cancel(); } catch (ObjectDisposedException) { }
                gotGate = await _sessionGate.WaitAsync(TimeSpan.FromSeconds(8), token).ConfigureAwait(false);
            }
            if (!gotGate)
            {
                await writer.WriteAsync(MessageType.AuthResult, new AuthResultMessage(false, AuthFailure.Busy, new byte[ProtocolConstants.ProofLength]).Serialize(), token).ConfigureAwait(false);
                _audit.Write("auth_busy", ("source", origin.Display));
                return;
            }
            Interlocked.Decrement(ref _preAuth);
            preAuthHeld = false;
            try
            {
                await writer.WriteAsync(MessageType.AuthResult, new AuthResultMessage(true, AuthFailure.None, auth.HostProof).Serialize(), token).ConfigureAwait(false);
                reader.MaxPayload = ProtocolConstants.MaxFramePayload;
                if (auth.Resumed is null) RotatePassword(); // single-use: the password that was just accepted is dead from now on
                _lockout.RegisterSuccess(origin.SourceKey);
                _audit.Write("auth_success", ("source", origin.Display), ("viewer", auth.ViewerName), ("resume", auth.Resumed is not null));
                await RunSessionAsync(ch, reader, writer, origin, auth, token).ConfigureAwait(false);
            }
            finally { _sessionGate.Release(); }
        }
        catch (OperationCanceledException) { }
        catch (Exception e) when (e is ProtocolException or IOException or EndOfStreamException or System.Security.Authentication.AuthenticationException)
        {
            _audit.Write("connection_error", ("source", origin.Display), ("error", e.GetType().Name));
        }
        finally
        {
            if (preAuthHeld) Interlocked.Decrement(ref _preAuth);
            if (ch is not null) await ch.Stream.DisposeAsync().ConfigureAwait(false);
            else await raw.DisposeAsync().ConfigureAwait(false);
        }
    }

    private sealed record AuthOutcome(string ViewerName, byte[] HostProof, ResumeTicket? Resumed);

    /// <summary>Hello -> challenge -> proof check. Returns null (after replying) on any failure.</summary>
    private async Task<AuthOutcome?> AuthenticateAsync(SecureChannel ch, FrameReader reader, FrameWriter writer, PeerOrigin origin, CancellationToken ct)
    {
        using var hs = CancellationTokenSource.CreateLinkedTokenSource(ct);
        hs.CancelAfter(ProtocolConstants.HandshakeTimeout);
        var zero = new byte[ProtocolConstants.ProofLength];

        var hello = HelloMessage.Parse(await ReadExpected(reader, MessageType.Hello, hs.Token).ConfigureAwait(false));
        if (hello.Version != ProtocolConstants.Version)
        {
            await writer.WriteAsync(MessageType.AuthResult, new AuthResultMessage(false, AuthFailure.VersionMismatch, zero).Serialize(), hs.Token).ConfigureAwait(false);
            return null;
        }

        // Password mode: the current one-time password. Resume mode: the (high-entropy) resume ticket, if one is valid.
        // An unknown/expired ticket still runs the full computation against a random secret so failures look identical.
        var ticket = hello.Resume ? _ticket : null;
        if (ticket is not null && ticket.ExpiresAt is { } exp && exp <= _time.GetUtcNow()) ticket = null;
        var password = hello.Resume ? (ticket?.Secret ?? Convert.ToHexString(RandomNumberGenerator.GetBytes(24))) : Password;
        var nonceH = RandomNumberGenerator.GetBytes(ProtocolConstants.NonceLength);
        var salt = RandomNumberGenerator.GetBytes(ProtocolConstants.SaltLength);
        var name = NameSanitizer.Clean(Policy.DisplayName, "host");
        await writer.WriteAsync(MessageType.AuthChallenge, new AuthChallengeMessage(name, nonceH, salt).Serialize(), hs.Token).ConfigureAwait(false);

        var resp = AuthResponseMessage.Parse(await ReadExpected(reader, MessageType.AuthResponse, hs.Token).ConfigureAwait(false));
        var key = await Task.Run(() => PasswordHandshake.DeriveKey(password, salt), hs.Token).ConfigureAwait(false);
        // Fingerprints from the host's perspective: viewer = remote, host = local.
        var expected = PasswordHandshake.ViewerProof(key, hello.Nonce, nonceH, ch.RemoteFingerprint, ch.LocalFingerprint);
        if (!PasswordHandshake.ConstantTimeEquals(expected, resp.Proof))
        {
            var blockedNow = _lockout.RegisterFailure(origin.SourceKey);
            _audit.Write("auth_failure", ("source", origin.Display), ("viewer", hello.ViewerName), ("blocked", blockedNow));
            if (blockedNow)
            {
                _audit.Write("source_blocked", ("source", origin.Display), ("minutes", (int)AuthLockout.BlockDuration.TotalMinutes));
                RotatePassword();
            }
            await writer.WriteAsync(MessageType.AuthResult,
                new AuthResultMessage(false, blockedNow ? AuthFailure.Blocked : AuthFailure.BadPassword, zero).Serialize(), hs.Token).ConfigureAwait(false);
            return null;
        }
        if (hello.Resume && Interlocked.CompareExchange(ref _ticket, null, ticket) != ticket)
        {
            // lost a race with another resume attempt: the ticket is single-use
            await writer.WriteAsync(MessageType.AuthResult, new AuthResultMessage(false, AuthFailure.BadPassword, zero).Serialize(), hs.Token).ConfigureAwait(false);
            return null;
        }
        var hostProof = PasswordHandshake.HostProof(key, hello.Nonce, nonceH, ch.RemoteFingerprint, ch.LocalFingerprint);
        return new AuthOutcome(NameSanitizer.Clean(hello.ViewerName, "viewer"), hostProof, hello.Resume ? ticket : null);
    }

    private static async Task<byte[]> ReadExpected(FrameReader r, MessageType t, CancellationToken ct)
    {
        var f = await r.ReadAsync(ct).ConfigureAwait(false);
        if (f.Type != (byte)t) throw new ProtocolException($"expected {t}, got {(MessageType)f.Type}");
        return f.Payload;
    }

    public async ValueTask DisposeAsync()
    {
        _lifetime.Cancel();
        await StopListenersAsync().ConfigureAwait(false);
        _lifetime.Dispose();
    }
}
