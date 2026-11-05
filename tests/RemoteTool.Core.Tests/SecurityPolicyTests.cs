using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using RemoteTool.Core.Audit;
using RemoteTool.Core.Protocol;
using RemoteTool.Core.Session;

namespace RemoteTool.Core.Tests;

/// <summary>Static and cross-cutting security rules enforced on the SOURCE TREE and on real log files.</summary>
public class SecurityPolicyTests
{
    private static string Root()
    {
        var d = new DirectoryInfo(AppContext.BaseDirectory);
        while (d is not null && !File.Exists(Path.Combine(d.FullName, "RemoteTool.sln"))) d = d.Parent;
        return d?.FullName ?? throw new InvalidOperationException("repo root not found");
    }

    private static IEnumerable<(string Path, string Text)> Sources()
    {
        var sep = Path.DirectorySeparatorChar;
        foreach (var f in Directory.EnumerateFiles(Path.Combine(Root(), "src"), "*.cs", SearchOption.AllDirectories))
            if (!f.Contains($"{sep}obj{sep}") && !f.Contains($"{sep}bin{sep}")) yield return (f.Replace('\\', '/'), File.ReadAllText(f));
    }

    private static string Rel(string p) => p[(Root().Replace('\\', '/').Length + 1)..];

    [Theory]
    [InlineData(@"\bBinaryFormatter\b|\bNetDataContractSerializer\b|\bSoapFormatter\b|\bLosFormatter\b", "unsafe deserialisers")]
    [InlineData(@"\bMD5\b|\bSHA1\b|\bHMACSHA1\b|\bHMACMD5\b|\bDES(CryptoServiceProvider)?\b|\bTripleDES\b|\bRC2\b|\bRijndaelManaged\b", "broken or legacy primitives")]
    [InlineData(@"SslProtocols\.(Ssl2|Ssl3|Tls|Tls11|Tls12|Default|None)\b", "anything but TLS 1.3")]
    [InlineData(@"Assembly\.(Load|LoadFrom|LoadFile)\(|Activator\.CreateInstance\(\s*Type\.GetType", "dynamic code loading")]
    [InlineData(@"ServicePointManager\.ServerCertificateValidationCallback|DangerousAcceptAnyServerCertificateValidator", "global certificate bypass")]
    [InlineData(@"\bEncoding\.\w+\.GetString\([^)]*\)\s*\.\s*Contains\(\s*""password", "ad-hoc password handling")]
    public void BannedApisDoNotAppearInProductCode(string pattern, string why)
    {
        var hits = Sources().Where(s => Regex.IsMatch(s.Text, pattern)).Select(s => Rel(s.Path)).ToList();
        Assert.True(hits.Count == 0, $"{why}: {string.Join(", ", hits)}");
    }

    [Fact]
    public void PredictableRandomIsNeverUsedInProductCode_OnlyInTheBenchmarkData()
    {
        var hits = Sources().Where(s => Regex.IsMatch(s.Text, @"new\s+Random\(|Random\.Shared")).Select(s => Rel(s.Path)).ToList();
        Assert.Equal(new[] { "src/RemoteTool.Video/CodecBenchmark.cs" }, hits);     // synthetic benchmark pixels, not secrets
    }

    [Fact]
    public void CertificateValidationCallbacksExistOnlyWhereTheDesignRequiresThem()
    {
        // Peer certs are ephemeral self-signed keys: identity comes from the channel-bound password proof (TlsChannel);
        // the relay link is validated by pin or system trust (RelayClient). Nowhere else may a callback decide trust.
        var allowed = new[] { "src/RemoteTool.Core/Security/TlsChannel.cs", "src/RemoteTool.Core/Relay/RelayClient.cs" };
        var hits = Sources().Where(s => Regex.IsMatch(s.Text, @"RemoteCertificateValidationCallback|SslStream\([^;]*,\s*[^;]*=>")).Select(s => Rel(s.Path)).ToList();
        Assert.Empty(hits.Except(allowed));
        var tls = Sources().Single(s => Rel(s.Path) == allowed[0]).Text;
        Assert.DoesNotContain("=> true", tls);                      // the callback must demand a certificate, never wave everything through
        Assert.Equal(2, Regex.Matches(tls, @"c != null").Count);    // server and client side each require the peer's certificate
    }

    [Fact]
    public void ProcessLaunchesAreLimitedToKnownElevationAndAdminTools_NeverShellInterpreted()
    {
        var allowed = new[] { "src/RemoteTool.Service/Windows/ServiceInstaller.cs", "src/RemoteTool.Service/Windows/WtsHelperLauncher.cs", "src/RemoteTool.App/Windows/MainWindow.xaml.cs" };
        var hits = Sources().Where(s => Regex.IsMatch(s.Text, @"Process\.Start\(|new\s+ProcessStartInfo\(")).Select(s => Rel(s.Path)).ToList();
        Assert.Empty(hits.Except(allowed));
        foreach (var s in Sources().Where(x => Rel(x.Path).Contains("ServiceInstaller")))
        {
            Assert.DoesNotContain("cmd.exe", s.Text); Assert.DoesNotContain("powershell", s.Text, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("ArgumentList.Add", s.Text);            // arguments are passed as an array, not a concatenated command line
        }
        var shell = Sources().Where(s => Regex.IsMatch(s.Text, @"UseShellExecute\s*=\s*true")).Select(s => Rel(s.Path)).ToList();
        Assert.Equal(new[] { "src/RemoteTool.App/Windows/MainWindow.xaml.cs" }, shell);   // the UAC "runas" relaunch only
    }

    [Fact]
    public void SecretComparisonsInAuthCodeAreConstantTime()
    {
        foreach (var name in new[] { "PasswordHandshake.cs", "HostService.cs", "ViewerSession.cs", "RelayEngine.cs", "RelayClient.cs", "PermanentPasswordStore.cs" })
        {
            var f = Sources().Single(s => s.Path.EndsWith("/" + name));
            Assert.False(Regex.IsMatch(f.Text, @"\.SequenceEqual\(|\bproof\s*==|Key\s*==\s*\w+\.Key"), $"{name} compares secrets with a timing-dependent operator");
        }
        Assert.Contains("FixedTimeEquals", Sources().Single(s => s.Path.EndsWith("/PasswordHandshake.cs")).Text);
        Assert.Contains("FixedTimeEquals", Sources().Single(s => s.Path.EndsWith("/RelayEngine.cs")).Text);
    }

    [Fact]
    public void NoSecretsOrKeyMaterialAreCommittedToTheRepository()
    {
        var root = Root();
        var sep = Path.DirectorySeparatorChar;
        var bad = Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories)
            .Where(f => !f.Contains($"{sep}.git{sep}") && !f.Contains($"{sep}obj{sep}") && !f.Contains($"{sep}bin{sep}") && !f.Contains($"{sep}artifacts{sep}"))
            .Where(f => Regex.IsMatch(f, @"\.(pfx|p12|pem|key|snk|jks)$", RegexOptions.IgnoreCase) || Regex.IsMatch(File.ReadAllText(f).Length < 2_000_000 && !IsBinary(f) ? File.ReadAllText(f) : "", @"-----BEGIN [A-Z ]*PRIVATE KEY-----"))
            .ToList();
        Assert.Empty(bad);
    }

    private static bool IsBinary(string f) => Regex.IsMatch(Path.GetExtension(f), @"\.(dll|exe|png|ico|pdb|zip|nupkg|so|dylib)$", RegexOptions.IgnoreCase);

    [Fact]
    public async Task SecretsNeverReachTheAuditLogsOnDisk_PasswordTicketOrProofs()
    {
        var dir = Path.Combine(Path.GetTempPath(), "rt-logs-" + Guid.NewGuid().ToString("N"));
        try
        {
            var hostLog = new JsonlAuditLog(Path.Combine(dir, "host"), "host");
            var viewerLog = new JsonlAuditLog(Path.Combine(dir, "viewer"), "viewer");
            await using var host = new HostService(() => new FakeProducer(), () => new FakeInjector(), new FakeConsent(), hostLog, new HostPolicy("PC"));
            var p = new TcpListener(IPAddress.Loopback, 0); p.Start(); var port = ((IPEndPoint)p.LocalEndpoint).Port; p.Stop();
            host.StartDirectListener(port);

            var password = host.Password;
            var c = new TcpClient(); await c.ConnectAsync(IPAddress.Loopback, port);
            var v = await ViewerSession.ConnectAsync(c.GetStream(), "alice", password, viewerLog, Permissions.All, default);
            var ticket = v.ResumeToken; v.Start(); await Task.Delay(200);
            await Assert.ThrowsAsync<ConnectFailedException>(async () => { var c2 = new TcpClient(); await c2.ConnectAsync(IPAddress.Loopback, port);
                await ViewerSession.ConnectAsync(c2.GetStream(), "mallory", "WRONGPW2", viewerLog, Permissions.All, default); });
            await v.DisposeAsync();

            var text = string.Join("\n", Directory.EnumerateFiles(dir, "*.jsonl", SearchOption.AllDirectories).Select(File.ReadAllText));
            Assert.Contains("auth_success", text);                                             // the logs are real and populated
            Assert.Contains("auth_failure", text);
            foreach (var secret in new[] { password, ticket, "WRONGPW2" }) Assert.DoesNotContain(secret, text);
            Assert.True(AuditVerifier.Verify(Path.Combine(dir, "host"), "host").Ok);
        }
        finally { try { Directory.Delete(dir, true); } catch { } }
    }
}
