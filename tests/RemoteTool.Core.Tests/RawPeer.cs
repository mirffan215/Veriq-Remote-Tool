using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using RemoteTool.Core.Protocol;
using RemoteTool.Core.Security;

namespace RemoteTool.Core.Tests;

/// <summary>
/// A hand-rolled protocol client for ATTACK tests: it can do the real handshake, but also skip steps, replay old proofs, send frames in the wrong
/// order, and send arbitrary bytes - things the real ViewerSession (rightly) never does.
/// </summary>
public sealed class RawPeer : IAsyncDisposable
{
    private readonly TcpClient _tcp;
    private readonly EphemeralCertificate _cert;
    public Stream Stream { get; }
    public FrameReader R { get; }
    public FrameWriter W { get; }
    public byte[] LocalFp { get; }
    public byte[] RemoteFp { get; }

    private RawPeer(TcpClient tcp, EphemeralCertificate cert, SecureChannel ch)
    {
        _tcp = tcp; _cert = cert; Stream = ch.Stream; LocalFp = ch.LocalFingerprint; RemoteFp = ch.RemoteFingerprint;
        R = new FrameReader(ch.Stream, MessageTypes.IsKnownPeer, ProtocolConstants.MaxFramePayload);
        W = new FrameWriter(ch.Stream);
    }

    public static async Task<RawPeer> ConnectAsync(int port)
    {
        var tcp = new TcpClient { NoDelay = true };
        await tcp.ConnectAsync(IPAddress.Loopback, port);
        var cert = EphemeralCertificate.Create("attacker");
        var ch = await TlsChannel.ConnectAsync(tcp.GetStream(), cert.Certificate, default);
        return new RawPeer(tcp, cert, ch);
    }

    public sealed record Proof(byte[] NonceV, byte[] ViewerProof, AuthChallengeMessage Challenge, AuthResultMessage? Result);

    /// <summary>Hello -> challenge -> proof. Pass <paramref name="replayProof"/>/<paramref name="fixedNonce"/> to replay a captured exchange.</summary>
    public async Task<Proof> AuthAsync(string password, byte[]? fixedNonce = null, byte[]? replayProof = null, string name = "attacker")
    {
        var nonceV = fixedNonce ?? RandomNumberGenerator.GetBytes(32);
        await W.WriteAsync(MessageType.Hello, new HelloMessage(ProtocolConstants.Version, name, nonceV).Serialize(), default);
        var challenge = AuthChallengeMessage.Parse((await R.ReadAsync(default)).Payload);
        var key = PasswordHandshake.DeriveKey(password, challenge.Salt);
        var proof = replayProof ?? PasswordHandshake.ViewerProof(key, nonceV, challenge.Nonce, LocalFp, RemoteFp);
        await W.WriteAsync(MessageType.AuthResponse, new AuthResponseMessage(proof).Serialize(), default);
        var f = await R.ReadAsync(default);
        var result = f.Type == (byte)MessageType.AuthResult ? AuthResultMessage.Parse(f.Payload) : null;
        if (result is { Success: true }) R.MaxPayload = ProtocolConstants.MaxFramePayload;
        return new Proof(nonceV, proof, challenge, result);
    }

    /// <summary>Full legitimate login + consent; returns the ConsentResult.</summary>
    public async Task<ConsentResultMessage> LoginAsync(string password, Permissions want = Permissions.All)
    {
        var p = await AuthAsync(password);
        if (p.Result is not { Success: true }) throw new InvalidOperationException("login failed: " + p.Result?.Failure);
        await W.WriteAsync(MessageType.ConsentRequest, new ConsentRequestMessage(want).Serialize(), default);
        while (true)
        {
            var f = await R.ReadAsync(default);
            if (f.Type == (byte)MessageType.ConsentResult) return ConsentResultMessage.Parse(f.Payload);
        }
    }

    /// <summary>True if the peer closed the connection (or sent Bye) within the timeout, ignoring ordinary video traffic.</summary>
    public async Task<bool> ConnectionEndsWithinAsync(TimeSpan timeout)
    {
        using var cts = new CancellationTokenSource(timeout);
        try
        {
            while (true)
            {
                var f = await R.ReadAsync(cts.Token);
                if (f.Type == (byte)MessageType.Bye) return true;
            }
        }
        catch (OperationCanceledException) { return false; }
        catch (Exception e) when (e is IOException or EndOfStreamException or ProtocolException or ObjectDisposedException or System.Security.Authentication.AuthenticationException) { return true; }
    }

    public async ValueTask DisposeAsync()
    {
        try { await Stream.DisposeAsync(); } catch { }
        _tcp.Dispose();
        _cert.Dispose();
    }
}
