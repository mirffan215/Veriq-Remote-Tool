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

    /// <summary>The viewer commits to its nonce before it sees the host's nonce.</summary>
    public static byte[] Commit(byte[] nonce) => SHA256.HashData(nonce);

    /// <summary>Public, fixed key for consent-only sessions: the proofs then give integrity/binding but NO authentication (there is no shared secret).</summary>
    public static readonly byte[] ConsentModeKey = SHA256.HashData(Encoding.ASCII.GetBytes("RemoteTool/4 consent-mode: no shared secret"));

    /// <summary>
    /// 6-digit security code over BOTH nonces and BOTH certificate fingerprints, shown on both screens ("482 913"). Honest peers compute the same value;
    /// a man-in-the-middle terminates TLS twice (two different certificate pairs) and cannot make the codes agree because the viewer's nonce was
    /// committed before the host's nonce was revealed (it would need a 1-in-a-million guess, visible to the users as a mismatch).
    /// </summary>
    public static string SecurityCode(byte[] nonceViewer, byte[] nonceHost, byte[] fpViewer, byte[] fpHost)
    {
        var data = new ProtoWriter().Fixed(Encoding.ASCII.GetBytes("RemoteTool/4 security-code")).Bytes(nonceViewer).Bytes(nonceHost).Bytes(fpViewer).Bytes(fpHost).ToArray();
        var h = SHA256.HashData(data);
        var v = System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(h) % 1_000_000;
        return $"{v / 1000:D3} {v % 1000:D3}";
    }

    public static bool ConstantTimeEquals(byte[] a, byte[] b) => CryptographicOperations.FixedTimeEquals(a, b);

    private static byte[] Proof(string label, byte[] key, byte[] nv, byte[] nh, byte[] fpV, byte[] fpH)
    {
        var data = new ProtoWriter().Fixed(Encoding.ASCII.GetBytes(label)).U16(ProtocolConstants.Version)
            .Bytes(nv).Bytes(nh).Bytes(fpV).Bytes(fpH).ToArray();
        return HMACSHA256.HashData(key, data);
    }
}
