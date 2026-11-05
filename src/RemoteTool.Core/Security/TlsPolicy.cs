using System.Net.Security;
using System.Security.Authentication;

namespace RemoteTool.Core.Security;

/// <summary>
/// The one place that decides which TLS versions and cipher suites any RemoteTool link may use.
/// TLS 1.3 is always preferred. TLS 1.2 is accepted ONLY so Windows 10 / Server 2019 (whose SChannel has no TLS 1.3) can work, and ONLY with
/// forward-secret AEAD suites (ECDHE + AES-GCM or ChaCha20-Poly1305). Everything older, and every CBC/RSA-key-exchange suite, is refused.
/// Peer identity never rests on TLS alone: the password proofs are bound to both certificate fingerprints, so a TLS-1.2 downgrade gains an attacker nothing.
/// </summary>
public static class TlsPolicy
{
    public const SslProtocols Protocols = SslProtocols.Tls12 | SslProtocols.Tls13;

    private static readonly HashSet<TlsCipherSuite> Tls12Allowed = new()
    {
        TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        TlsCipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    };

    /// <summary>Throws unless the negotiated session is TLS 1.3, or TLS 1.2 with an allowed forward-secret AEAD suite.</summary>
    public static void Require(SslStream ssl)
    {
        if (ssl.SslProtocol == SslProtocols.Tls13) return;
        if (ssl.SslProtocol == SslProtocols.Tls12 && Tls12Allowed.Contains(ssl.NegotiatedCipherSuite)) return;
        throw new AuthenticationException($"TLS policy: {ssl.SslProtocol} / {ssl.NegotiatedCipherSuite} is not allowed");
    }

    /// <summary>Restricts the server/client offer where the OS allows it (not supported by SChannel); <see cref="Require"/> still checks the result everywhere.</summary>
    public static CipherSuitesPolicy? OfferedSuites() => OperatingSystem.IsWindows() ? null : new CipherSuitesPolicy(new[]
    {
        TlsCipherSuite.TLS_AES_256_GCM_SHA384, TlsCipherSuite.TLS_AES_128_GCM_SHA256, TlsCipherSuite.TLS_CHACHA20_POLY1305_SHA256,
        TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        TlsCipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    });
}
