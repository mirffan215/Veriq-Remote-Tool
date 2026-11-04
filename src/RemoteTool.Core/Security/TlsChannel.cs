using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

namespace RemoteTool.Core.Security;

/// <summary>An authenticated TLS 1.3 stream plus the SHA-256 fingerprints of both certificates (for channel binding).</summary>
public sealed record SecureChannel(Stream Stream, byte[] LocalFingerprint, byte[] RemoteFingerprint);

/// <summary>
/// Peer-to-peer TLS 1.3 (mutual, certificate presence required). Certificate chains are deliberately NOT validated:
/// identity comes from the password handshake which is bound to these fingerprints (see PROTOCOL.md).
/// </summary>
public static class TlsChannel
{
    public static async Task<SecureChannel> AcceptAsync(Stream inner, X509Certificate2 cert, CancellationToken ct)
    {
        var ssl = new SslStream(inner, leaveInnerStreamOpen: false);
        try
        {
            await ssl.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
            {
                ServerCertificate = cert,
                ClientCertificateRequired = true,
                EnabledSslProtocols = SslProtocols.Tls13,
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                EncryptionPolicy = EncryptionPolicy.RequireEncryption,
                RemoteCertificateValidationCallback = static (_, c, _, _) => c != null,
            }, ct).ConfigureAwait(false);
            return Wrap(ssl);
        }
        catch { await ssl.DisposeAsync().ConfigureAwait(false); throw; }
    }

    public static async Task<SecureChannel> ConnectAsync(Stream inner, X509Certificate2 cert, CancellationToken ct)
    {
        var ssl = new SslStream(inner, leaveInnerStreamOpen: false);
        try
        {
            await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = "remotetool.peer",
                ClientCertificates = new X509CertificateCollection { cert },
                LocalCertificateSelectionCallback = (_, _, _, _, _) => cert,
                EnabledSslProtocols = SslProtocols.Tls13,
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                EncryptionPolicy = EncryptionPolicy.RequireEncryption,
                RemoteCertificateValidationCallback = static (_, c, _, _) => c != null,
            }, ct).ConfigureAwait(false);
            return Wrap(ssl);
        }
        catch { await ssl.DisposeAsync().ConfigureAwait(false); throw; }
    }

    private static SecureChannel Wrap(SslStream ssl)
    {
        if (ssl.SslProtocol != SslProtocols.Tls13) throw new AuthenticationException("TLS 1.3 is required");
        if (ssl.LocalCertificate is null || ssl.RemoteCertificate is null)
            throw new AuthenticationException("mutual certificates are required");
        return new SecureChannel(ssl, EphemeralCertificate.Fingerprint(ssl.LocalCertificate), EphemeralCertificate.Fingerprint(ssl.RemoteCertificate));
    }
}
