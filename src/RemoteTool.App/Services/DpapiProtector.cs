using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using RemoteTool.Core.Config;

namespace RemoteTool.App.Services;

/// <summary>Protects stored secrets with Windows DPAPI (current user scope).</summary>
[SupportedOSPlatform("windows")]
public sealed class DpapiProtector : ISecretProtector
{
    private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("RemoteTool.settings.v1");

    public string Protect(string plaintext)
        => Convert.ToBase64String(ProtectedData.Protect(Encoding.UTF8.GetBytes(plaintext), Entropy, DataProtectionScope.CurrentUser));

    public string Unprotect(string protectedText)
    {
        try { return Encoding.UTF8.GetString(ProtectedData.Unprotect(Convert.FromBase64String(protectedText), Entropy, DataProtectionScope.CurrentUser)); }
        catch (Exception e) when (e is CryptographicException or FormatException) { return ""; }
    }
}
