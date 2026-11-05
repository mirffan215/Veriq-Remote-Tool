using System.Net;
using System.Net.Sockets;
using System.Text;
using RemoteTool.Core.Config;
using RemoteTool.Core.Protocol;
using RemoteTool.Core.Security;
using RemoteTool.Core.Session;

namespace RemoteTool.Core.Tests;

public class DefaultsAndAccessTests
{
    private static string B64(string s) => Convert.ToBase64String(Encoding.UTF8.GetBytes(s));

    [Fact]
    public void BuiltInDefaultsParsePlainOrBase64_AndGarbageIsHarmless()
    {
        var d = DeploymentDefaults.Parse($"{{\"relayB64\":\"{B64("relay.corp:443")}\",\"fingerprintB64\":\"{B64("AABB")}\",\"accessKeyB64\":\"{B64("k\"ey\\with\nodd chars")}\"}}");
        Assert.Equal(("relay.corp:443", "AABB", "k\"ey\\with\nodd chars"), (d.Relay, d.Fingerprint, d.AccessKey));      // base64 survives characters that would break JSON
        var plain = DeploymentDefaults.Parse("{\"relay\":\"r:1\",\"accessKey\":\"x\"}");
        Assert.Equal(("r:1", "", "x"), (plain.Relay, plain.Fingerprint, plain.AccessKey));
        foreach (var junk in new[] { "", "   ", "{", "[]", "null", "{\"relayB64\":\"!!!notbase64!!!\"}", "{\"relay\":5}" })
            Assert.True(DeploymentDefaults.Parse(junk).IsEmpty, junk);
    }

    [Fact]
    public void DefaultsFillOnlyEmptySettings_NeverOverwriteWhatTheUserOrAdminChose_AndKeyIsStoredProtected()
    {
        var defaults = new DeploymentDefaults("relay.corp:443", "AABB", "secret-key");
        var s = new AppSettings();
        Assert.True(defaults.ApplyTo(s, new TestProtector()));
        Assert.Equal("relay.corp:443", s.RelayAddress);
        Assert.DoesNotContain("secret-key", s.RelayAccessKeyProtected);                 // not in clear in settings.json
        Assert.Equal("secret-key", new TestProtector().Unprotect(s.RelayAccessKeyProtected));

        var custom = new AppSettings { RelayAddress = "my.own:8443", RelayFingerprint = "CC" };
        defaults.ApplyTo(custom, new TestProtector());
        Assert.Equal("my.own:8443", custom.RelayAddress); Assert.Equal("CC", custom.RelayFingerprint);
        Assert.False(new DeploymentDefaults("", "", "").ApplyTo(new AppSettings(), new TestProtector()));
    }

    [Fact]
    public void MergePrefersHigherPriorityPerField()
    {
        var m = DeploymentDefaults.Merge(new DeploymentDefaults("", "FP-ENV", ""), null, new DeploymentDefaults("embedded:443", "FP-EMB", "key-emb"));
        Assert.Equal(("embedded:443", "FP-ENV", "key-emb"), (m.Relay, m.Fingerprint, m.AccessKey));
    }

    // ---- the optional ACCESS PASSWORD of the normal app ---------------------------------------------------------

    private sealed class Rig : IAsyncDisposable
    {
        public HostService Host = null!; public FakeConsent Consent = new(); public ListAudit Audit = new(); public int Port; public string Dir = Path.Combine(Path.GetTempPath(), "rt-acc-" + Guid.NewGuid().ToString("N"));
        public const string AccessPw = "Our-Team-Pass-42";
        public static Rig Start(bool setPassword = true)
        {
            var r = new Rig(); Directory.CreateDirectory(r.Dir);
            var store = new PermanentPasswordStore(Path.Combine(r.Dir, "access.json"), new TestProtector());
            if (setPassword) store.Set(AccessPw);
            r.Host = new HostService(() => new FakeProducer(), () => new FakeInjector(), r.Consent, r.Audit, new HostPolicy("Desk-PC"),
                permanentCredential: store, unattended: new UserAccessPolicy());
            var p = new TcpListener(IPAddress.Loopback, 0); p.Start(); r.Port = ((IPEndPoint)p.LocalEndpoint).Port; p.Stop();
            r.Host.StartDirectListener(r.Port);
            return r;
        }
        public async Task<ViewerSession> Connect(string secret, bool permanent, bool consentOnly)
        {
            var c = new TcpClient { NoDelay = true }; await c.ConnectAsync(IPAddress.Loopback, Port);
            return await ViewerSession.ConnectAsync(c.GetStream(), "friend", secret, new ListAudit(), Permissions.All, default, permanent: permanent, consentOnly: consentOnly);
        }
        public async ValueTask DisposeAsync() { await Host.DisposeAsync(); try { Directory.Delete(Dir, true); } catch { } }
    }

    [Fact]
    public async Task KnowingTheAccessPasswordConnectsWithoutAClick_ButOnlyWithControlAndClipboard()
    {
        await using var rig = Rig.Start();
        await using var v = await rig.Connect(Rig.AccessPw, permanent: true, consentOnly: false);
        Assert.Equal(0, rig.Consent.Calls);                                              // no Accept dialog
        Assert.Equal(Permissions.Control | Permissions.Clipboard, v.Permissions);        // viewer asked for All: file transfer needs a person
        Assert.False(v.ConsentOnly);
    }

    [Fact]
    public async Task WrongAccessPasswordIsRefused_AndClickOnlyStillWorksSideBySide()
    {
        await using var rig = Rig.Start();
        var e = await Assert.ThrowsAsync<ConnectFailedException>(() => rig.Connect("Wrong-Pass-0000", permanent: true, consentOnly: false));
        Assert.Equal(ConnectFailure.BadPassword, e.Failure);
        Assert.Equal(0, rig.Consent.Calls);
        await using var v = await rig.Connect("", permanent: false, consentOnly: true);   // the click route is unaffected by having a password
        Assert.Equal(1, rig.Consent.Calls);
        Assert.True(v.ConsentOnly);
    }

    [Fact]
    public async Task WithoutAnAccessPasswordSetTheAccessRouteDoesNotExist()
    {
        await using var rig = Rig.Start(setPassword: false);
        var e = await Assert.ThrowsAsync<ConnectFailedException>(() => rig.Connect(Rig.AccessPw, permanent: true, consentOnly: false));
        Assert.Equal(ConnectFailure.BadPassword, e.Failure);
        Assert.Equal(0, rig.Consent.Calls);
    }
}
