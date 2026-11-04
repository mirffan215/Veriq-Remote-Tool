using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using RemoteTool.Core.Config;

namespace RemoteTool.Service.Windows;

/// <summary>DPAPI, machine scope: secrets of the SYSTEM service stay readable only on this PC (and to its administrators).</summary>
[SupportedOSPlatform("windows")]
public sealed class MachineDpapiProtector : ISecretProtector
{
    private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("RemoteTool.service.v1");

    public string Protect(string plaintext)
        => Convert.ToBase64String(ProtectedData.Protect(Encoding.UTF8.GetBytes(plaintext), Entropy, DataProtectionScope.LocalMachine));

    public string Unprotect(string protectedText)
    {
        try { return Encoding.UTF8.GetString(ProtectedData.Unprotect(Convert.FromBase64String(protectedText), Entropy, DataProtectionScope.LocalMachine)); }
        catch (Exception e) when (e is CryptographicException or FormatException) { return ""; }
    }
}
