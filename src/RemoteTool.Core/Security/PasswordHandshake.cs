using System.Security.Cryptography;
using System.Text;
using RemoteTool.Core.Protocol;

namespace RemoteTool.Core.Security;

/// <summary>
/// Password-authenticated, channel-bound mutual proof. See docs/PROTOCOL.md and docs/DECISIONS.md (D-04).
/// key   = PBKDF2-HMAC-SHA256(password, salt, 600k)
/// proof = HMAC-SHA256(key, label || version || nonceV || nonceH || fpViewer || fpHost)
/// The password never crosses the wire; a MITM terminating TLS produces different fingerprints so proofs fail.
/// </summary>
public static class PasswordHandshake
{
    private const string ViewerLabel = "RemoteTool/1 viewer-proof";
    private const string HostLabel = "RemoteTool/1 host-proof";

    public static byte[] DeriveKey(string password, byte[] salt)
        => Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(PasswordGenerator.Normalize(password)), salt, ProtocolConstants.Pbkdf2Iterations, HashAlgorithmName.SHA256, 32);

    public static byte[] ViewerProof(byte[] key, byte[] nonceViewer, byte[] nonceHost, byte[] fpViewer, byte[] fpHost)
        => Proof(ViewerLabel, key, nonceViewer, nonceHost, fpViewer, fpHost);

    public static byte[] HostProof(byte[] key, byte[] nonceViewer, byte[] nonceHost, byte[] fpViewer, byte[] fpHost)
        => Proof(HostLabel, key, nonceViewer, nonceHost, fpViewer, fpHost);

    public static bool ConstantTimeEquals(byte[] a, byte[] b) => CryptographicOperations.FixedTimeEquals(a, b);

    private static byte[] Proof(string label, byte[] key, byte[] nv, byte[] nh, byte[] fpV, byte[] fpH)
    {
        var data = new ProtoWriter().Fixed(Encoding.ASCII.GetBytes(label)).U16(ProtocolConstants.Version)
            .Bytes(nv).Bytes(nh).Bytes(fpV).Bytes(fpH).ToArray();
        return HMACSHA256.HashData(key, data);
    }
}
