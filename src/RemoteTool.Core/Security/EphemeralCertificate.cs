using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace RemoteTool.Core.Security;

/// <summary>
/// Self-signed ECDSA P-256 certificate used only as a TLS key carrier. Trust is NOT derived from the
/// certificate; peers are authenticated by the password handshake bound to the certificate fingerprints.
/// </summary>
public sealed class EphemeralCertificate : IDisposable
{
    public X509Certificate2 Certificate { get; }

    private EphemeralCertificate(X509Certificate2 cert) { Certificate = cert; }

    public static EphemeralCertificate Create(string commonName = "RemoteTool", TimeSpan? validity = null)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest($"CN={commonName}", key, HashAlgorithmName.SHA256);
        req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            new OidCollection { new("1.3.6.1.5.5.7.3.1"), new("1.3.6.1.5.5.7.3.2") }, false));
        var now = DateTimeOffset.UtcNow;
        using var selfSigned = req.CreateSelfSigned(now.AddMinutes(-10), now.Add(validity ?? TimeSpan.FromDays(2)));
        // Round-trip through PFX: Windows SChannel cannot use the in-memory (ephemeral) key of CreateSelfSigned.
        var cert = new X509Certificate2(selfSigned.Export(X509ContentType.Pfx), (string?)null, X509KeyStorageFlags.Exportable);
        return new EphemeralCertificate(cert);
    }

    public static byte[] Fingerprint(X509Certificate cert) => SHA256.HashData(cert.GetRawCertData());

    public void Dispose()
    {
        if (OperatingSystem.IsWindows()) TryDeleteWindowsKey(Certificate);
        Certificate.Dispose();
    }

    [SupportedOSPlatform("windows")]
    private static void TryDeleteWindowsKey(X509Certificate2 cert)
    {
        // The PFX import persists a CNG key container in the user profile; remove it so no key material outlives the session.
        try
        {
            using var ec = cert.GetECDsaPrivateKey();
            if (ec is ECDsaCng cng) cng.Key.Delete();
        }
        catch { /* best effort */ }
    }
}
