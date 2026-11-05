using System.Net;
using System.Net.Sockets;
using RemoteTool.Core.Audit;
using RemoteTool.Core.Protocol;
using RemoteTool.Core.Session;
using RemoteTool.Service;
using RemoteTool.Service.Helper;

namespace RemoteTool.Core.Tests;

public sealed class FakeSas : ISasSender { public int Calls; public void SendSas() => Interlocked.Increment(ref Calls); }

public sealed class FakeHelperUi : IHelperUi
{
    public volatile string Desktop = "Winlogon";
    public volatile bool Answer = true;
    public int Asked;
    public string? Banner;
    public bool BannerVisible;
    public string CurrentInputDesktop() => Desktop;
    public void ShowBanner(string viewer, bool recording) { Banner = viewer; BannerVisible = true; }
    public void HideBanner() => BannerVisible = false;
    public Task<ConsentDecision> AskConsentAsync(ConsentRequestInfo info)
    {
        Interlocked.Increment(ref Asked);
        return Task.FromResult(new ConsentDecision(Answer, info.Allowed));
    }
}

/// <summary>Runs the real HelperEndpoint in-process on a dedicated thread, connected through a loopback socket (stands in for the named pipe).</summary>
public sealed class FakeHelperLauncher : IHelperLauncher
{
    public readonly FakeHelperUi Ui = new();
    public readonly FakeInjector Injector = new();
    public int Launches;
    public Func<IFrameProducer> Producer = () => new FakeProducer();
    private volatile HelperProc? _current;

    public int? ActiveSessionId() => 1;

    public async Task<IHelperProcess> LaunchAsync(int sessionId, CancellationToken ct)
    {
        Interlocked.Increment(ref Launches);
        var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        var port = ((IPEndPoint)l.LocalEndpoint).Port;
        var clientTask = Task.Run(async () => { var c = new TcpClient(); await c.ConnectAsync(IPAddress.Loopback, port); return c; });
        var server = await l.AcceptTcpClientAsync(ct);
        var client = await clientTask;
        l.Stop();
        var proc = new HelperProc(server.GetStream(), client);
        var endpoint = new HelperEndpoint(client.GetStream(), Producer(), Injector, Ui, sessionId, "tester");
        proc.Endpoint = endpoint;
        new Thread(() => { try { endpoint.Run(proc.Cts.Token); } finally { proc.Exit(); } }) { IsBackground = true }.Start();
        _current = proc;
        return proc;
    }

    public void Crash() => _current?.Kill();
    public HelperEndpoint? Endpoint => _current?.Endpoint;

    private sealed class HelperProc : IHelperProcess
    {
        private readonly TcpClient _client;
        private readonly TaskCompletionSource _exited = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public readonly CancellationTokenSource Cts = new();
        public HelperEndpoint? Endpoint;
        public HelperProc(Stream pipe, TcpClient client) { Pipe = pipe; _client = client; }
        public Stream Pipe { get; }
        public Task Exited => _exited.Task;
        public int ProcessId => 1234;
        public void Exit() => _exited.TrySetResult();
        public void Kill() { Cts.Cancel(); try { _client.Dispose(); } catch { } _exited.TrySetResult(); }
        public ValueTask DisposeAsync() { Kill(); return ValueTask.CompletedTask; }
    }
}

public class HelperProtocolTests
{
    [Fact]
    public void FuzzedHelperPayloadsOnlyFailWithProtocolException()
    {
        var rng = new Random(7);
        for (var i = 0; i < 20000; i++)
        {
            var d = new byte[rng.Next(0, 60)];
            rng.NextBytes(d);
            foreach (var parse in new Action<byte[]>[]
            {
                p => HelperCodec.ParseNextFrame(p), p => HelperCodec.ParseNextH264(p), p => HelperCodec.ParseOptional(p), p => HelperCodec.ParseMouse(p),
                p => HelperCodec.ParseBanner(p), p => HelperCodec.ParseConsent(p), p => HelperCodec.ParseConsentAnswer(p), p => HelperCodec.ParseError(p), p => HelperHello.Parse(p),
            })
            {
                try { parse(d); } catch (ProtocolException) { }
            }
        }
    }

    [Fact]
    public void UserPresenceFollowsTheDesktopName()
    {
        Assert.False(UnattendedPolicy.IsUserPresent("Winlogon"));
        Assert.True(UnattendedPolicy.IsUserPresent("Default"));
        Assert.True(UnattendedPolicy.IsUserPresent("Screen-saver"));
    }
}

public class ServiceRuntimeTests
{
    private const string Pw = "Correct-Horse-9";

    private sealed class Rig : IAsyncDisposable
    {
        public ServiceRuntime Runtime = null!;
        public FakeHelperLauncher Launcher = new();
        public FakeSas Sas = new();
        public string Root = Path.Combine(Path.GetTempPath(), "rt-svc-" + Guid.NewGuid().ToString("N"));
        public int Port;

        public static async Task<Rig> StartAsync(Action<ServiceConfig>? tweak = null, bool setPassword = true)
        {
            var r = new Rig();
            var paths = new ServicePaths(r.Root);
            Directory.CreateDirectory(paths.ServiceDir);
            var probe = new TcpListener(IPAddress.Loopback, 0); probe.Start(); r.Port = ((IPEndPoint)probe.LocalEndpoint).Port; probe.Stop();
            var store = new ServiceConfigStore(paths.ConfigFile);
            var cfg = store.Load();
            cfg.UnattendedEnabled = true; cfg.DirectListenerEnabled = true; cfg.DirectPort = r.Port; cfg.DisplayName = "SERVER-01";
            tweak?.Invoke(cfg);
            store.Save(cfg);
            if (setPassword) new RemoteTool.Core.Security.PermanentPasswordStore(paths.PermanentFile, new TestProtector()).Set(Pw);
            r.Runtime = new ServiceRuntime(paths, new TestProtector(), r.Launcher, r.Sas, new ListAudit(), helperRetry: TimeSpan.FromMilliseconds(100));
            r.Runtime.Start();
            await r.Runtime.Helpers.GetChannelAsync(TimeSpan.FromSeconds(10));
            return r;
        }

        public async Task<ViewerSession> Connect(string secret = Pw, bool permanent = true)
        {
            var c = new TcpClient { NoDelay = true };
            await c.ConnectAsync(IPAddress.Loopback, Port);
            return await ViewerSession.ConnectAsync(c.GetStream(), "ops", secret, new ListAudit(), Permissions.All, default, permanent: permanent);
        }

        public async ValueTask DisposeAsync() { await Runtime.DisposeAsync(); try { Directory.Delete(Root, true); } catch { } }
    }

    private static async Task WaitFor(Func<bool> c, int sec = 10) { var t = DateTime.UtcNow.AddSeconds(sec); while (!c() && DateTime.UtcNow < t) await Task.Delay(20); Assert.True(c(), "condition not reached"); }

    [Fact]
    public async Task LoginScreenSession_NoDialog_FramesInputBannerAndCtrlAltDel()
    {
        await using var rig = await Rig.StartAsync();
        rig.Launcher.Ui.Desktop = "Winlogon";            // nobody at the machine
        await using var v = await rig.Connect();
        Assert.Equal(Permissions.Control, v.Permissions);
        Assert.Equal(0, rig.Launcher.Ui.Asked);
        var got = new TaskCompletionSource<bool>(); v.FrameReceived += _ => got.TrySetResult(true); v.Start();
        Assert.True(await got.Task.WaitAsync(TimeSpan.FromSeconds(10)));

        await v.SendMouseAsync(new MouseEventMessage(MouseKind.Move, MouseButton.None, 100, 200, 0));
        await v.SendKeyAsync(new KeyEventMessage(65, false, false));
        await WaitFor(() => rig.Launcher.Injector.Events.Count >= 2);
        Assert.Contains("mouse:Move:100:200", rig.Launcher.Injector.Events);

        await v.SendSpecialKeyAsync(SpecialKeyKind.CtrlAltDel);
        await WaitFor(() => rig.Sas.Calls == 1);                      // the SERVICE sends SAS, not the helper

        await WaitFor(() => rig.Launcher.Ui.BannerVisible);
        Assert.Equal("ops", rig.Launcher.Ui.Banner);
        await v.DisposeAsync();
        await WaitFor(() => !rig.Launcher.Ui.BannerVisible);
        await WaitFor(() => File.Exists(new ServicePaths(rig.Root).PublicStatusFile));
        Assert.DoesNotContain("Correct", File.ReadAllText(new ServicePaths(rig.Root).PublicStatusFile));
    }

    [Fact]
    public async Task UserAtTheScreen_IsAskedFirst_AndCanSayNo()
    {
        await using var rig = await Rig.StartAsync();
        rig.Launcher.Ui.Desktop = "Default";
        rig.Launcher.Ui.Answer = false;
        var e = await Assert.ThrowsAsync<ConnectFailedException>(() => rig.Connect());
        Assert.Equal(ConnectFailure.Denied, e.Failure);
        Assert.Equal(1, rig.Launcher.Ui.Asked);
        rig.Launcher.Ui.Answer = true;
        await using var v = await rig.Connect();
        Assert.Equal(2, rig.Launcher.Ui.Asked);
    }

    [Fact]
    public async Task ConsentWhenUserPresentCanBeSwitchedOffForKiosks()
    {
        await using var rig = await Rig.StartAsync(c => c.ConsentWhenUserPresent = false);
        rig.Launcher.Ui.Desktop = "Default";
        await using var v = await rig.Connect();
        Assert.Equal(0, rig.Launcher.Ui.Asked);
    }

    [Fact]
    public async Task MasterSwitchOff_OrNoPasswordOrOneTimePasswordMode_AllRefused()
    {
        await using (var rig = await Rig.StartAsync(c => c.UnattendedEnabled = false))
            Assert.Equal(ConnectFailure.BadPassword, (await Assert.ThrowsAsync<ConnectFailedException>(() => rig.Connect())).Failure);
        await using (var rig = await Rig.StartAsync(setPassword: false))
            Assert.Equal(ConnectFailure.BadPassword, (await Assert.ThrowsAsync<ConnectFailedException>(() => rig.Connect())).Failure);
        await using (var rig = await Rig.StartAsync())
        {
            // the service has no usable one-time password: guessing one is pointless, even the "current" one
            var e = await Assert.ThrowsAsync<ConnectFailedException>(() => rig.Connect(rig.Runtime.Host.Password, permanent: false));
            Assert.Equal(ConnectFailure.BadPassword, e.Failure);
        }
    }

    [Fact]
    public async Task EmergencyHotkeyAndBannerButtonOnTheHelperEndTheSession()
    {
        await using var rig = await Rig.StartAsync();
        await using var v = await rig.Connect();
        var ended = new TaskCompletionSource<ByeReason>(); v.Ended += (r, _) => ended.TrySetResult(r); v.Start();
        await WaitFor(() => rig.Runtime.Host.ActiveSession is not null);
        rig.Launcher.Endpoint!.NotifyEmergencyHotkey();
        Assert.Equal(ByeReason.Emergency, await ended.Task.WaitAsync(TimeSpan.FromSeconds(10)));

        await WaitFor(() => rig.Runtime.Host.ActiveSession is null);
        await using var v2 = await rig.Connect();
        var ended2 = new TaskCompletionSource<ByeReason>(); v2.Ended += (r, _) => ended2.TrySetResult(r); v2.Start();
        await WaitFor(() => rig.Runtime.Host.ActiveSession is not null);
        rig.Launcher.Endpoint!.NotifyBannerDisconnect();
        Assert.Equal(ByeReason.HostDisconnected, await ended2.Task.WaitAsync(TimeSpan.FromSeconds(10)));
    }

    [Fact]
    public async Task HelperCrashMidSession_IsRelaunched_AndViewerResumesWithoutPassword()
    {
        await using var rig = await Rig.StartAsync();
        var v = await rig.Connect();
        var token = v.ResumeToken;
        var ended = new TaskCompletionSource<ByeReason>(); v.Ended += (r, _) => ended.TrySetResult(r); v.Start();
        await WaitFor(() => rig.Runtime.Host.ActiveSession is not null);
        Assert.Equal(1, rig.Launcher.Launches);

        rig.Launcher.Crash();                                          // helper process dies (e.g. session switch / crash)
        Assert.True(ViewerReconnect.IsRecoverable(await ended.Task.WaitAsync(TimeSpan.FromSeconds(15))));

        var dial = new Func<CancellationToken, Task<Stream>>(async ct => { var c = new TcpClient(); await c.ConnectAsync(IPAddress.Loopback, rig.Port, ct); return c.GetStream(); });
        await using var v2 = await ViewerReconnect.ResumeAsync(dial, "ops", token, new ListAudit(), Permissions.All, default, firstDelay: TimeSpan.FromMilliseconds(100));
        var got = new TaskCompletionSource<bool>(); v2.FrameReceived += _ => got.TrySetResult(true); v2.Start();
        Assert.True(await got.Task.WaitAsync(TimeSpan.FromSeconds(10)));
        Assert.True(rig.Launcher.Launches >= 2);                       // a fresh helper serves the resumed session
    }

    [Fact]
    public async Task H264RequestToHelperWithoutEncoderFallsBackCleanly()
    {
        await using var rig = await Rig.StartAsync();
        var ch = await rig.Runtime.Helpers.GetChannelAsync(TimeSpan.FromSeconds(5));
        Assert.False(ch.Hello.H264);
        await Assert.ThrowsAsync<CodecUnavailableException>(() => ch.NextH264Async(0, true, 2000));
    }

    [Fact]
    public void ConfigStorePersistsServiceIdAndSurvivesCorruption()
    {
        var dir = Path.Combine(Path.GetTempPath(), "rt-cfg-" + Guid.NewGuid().ToString("N"));
        try
        {
            var f = Path.Combine(dir, "config.json");
            var id = new ServiceConfigStore(f).Load().Id;
            Assert.Equal(id, new ServiceConfigStore(f).Load().Id);
            File.WriteAllText(f, "{ broken");
            Assert.True(RemoteTool.Core.Config.ConnectionId.IsValid(new ServiceConfigStore(f).Load().Id));
        }
        finally { try { Directory.Delete(dir, true); } catch { } }
    }
}

public class WindowsServiceLogicTests
{
    private sealed class FakeSwitch : RemoteTool.Service.Windows.IDesktopSwitch
    {
        public string Name = "Default"; public bool ChangeOnNext;
        public string EnsureInputDesktop(out bool changed) { changed = ChangeOnNext; ChangeOnNext = false; return Name; }
    }

    private sealed class CountingProducer : IFrameProducer
    {
        public static int Created;
        public bool? LastKeyframe;
        public CountingProducer() { Interlocked.Increment(ref Created); }
        public IReadOnlyList<MonitorInfo> GetMonitors() => new[] { new MonitorInfo(0, 0, 0, 10, 10, true, "m") };
        public FrameUpdateMessage? NextFrame(int m, int q, bool key) { LastKeyframe = key; return null; }
        public CursorShape GetCursorShape() => CursorShape.Arrow;
        public void Dispose() { }
    }

    [Fact]
    public void CaptureFollowsTheSecureDesktop_RecreatesSurfaceAndForcesKeyframe()
    {
        var sw = new FakeSwitch();
        CountingProducer.Created = 0;
        CountingProducer? last = null;
        using var p = new RemoteTool.Service.Windows.DesktopAwareProducer(sw, () => last = new CountingProducer());
        Assert.Equal(1, CountingProducer.Created);
        p.NextFrame(0, 70, false);
        Assert.False(last!.LastKeyframe);
        sw.Name = "Winlogon"; sw.ChangeOnNext = true;        // UAC prompt / lock screen appeared
        p.NextFrame(0, 70, false);
        Assert.Equal(2, CountingProducer.Created);
        Assert.True(last!.LastKeyframe);                      // viewer gets a full picture of the new desktop
        Assert.Equal("Winlogon", p.CurrentDesktop);
        p.NextFrame(0, 70, false);
        Assert.False(last!.LastKeyframe);
    }

    [Fact]
    public void InputInjectionAttachesToTheInputDesktopFirst()
    {
        var calls = new List<string>();
        var sw = new SwitchSpy(calls);
        var inner = new SpyInjector(calls);
        using var inj = new RemoteTool.Service.Windows.DesktopAwareInjector(sw, inner);
        inj.Key(new KeyEventMessage(65, false, false));
        inj.Mouse(new MonitorInfo(0, 0, 0, 1, 1, true, ""), new MouseEventMessage(MouseKind.Move, MouseButton.None, 1, 1, 0));
        Assert.Equal(new[] { "switch", "key", "switch", "mouse" }, calls);
    }

    private sealed class SwitchSpy : RemoteTool.Service.Windows.IDesktopSwitch
    {
        private readonly List<string> _c; public SwitchSpy(List<string> c) { _c = c; }
        public string EnsureInputDesktop(out bool changed) { changed = false; _c.Add("switch"); return "Default"; }
    }
    private sealed class SpyInjector : IInputInjector
    {
        private readonly List<string> _c; public SpyInjector(List<string> c) { _c = c; }
        public void Mouse(MonitorInfo m, MouseEventMessage e) => _c.Add("mouse");
        public void Key(KeyEventMessage e) => _c.Add("key");
        public void ReleaseAll() => _c.Add("release");
        public void Dispose() { }
    }

    [Fact]
    public void ScCommandsAreExactAndRunTheServiceFromTheInstalledCopy()
    {
        var cmds = RemoteTool.Service.Windows.ScCommands.Create(@"C:\Program Files\RemoteTool\RemoteTool.exe");
        var create = cmds[0];
        Assert.Equal("create", create[0]);
        Assert.Equal("\"C:\\Program Files\\RemoteTool\\RemoteTool.exe\" --service", create[create.ToList().IndexOf("binPath=") + 1]);
        Assert.Equal("LocalSystem", create[create.ToList().IndexOf("obj=") + 1]);
        Assert.Contains(cmds, c => c[0] == "failure" && c.Contains("restart/5000/restart/5000/restart/60000"));
        Assert.Equal(new[] { "stop", "RemoteToolService" }, RemoteTool.Service.Windows.ScCommands.Stop());
    }
}

public class ServiceSetupArgsTests
{
    private static Func<string, string?> Env(params (string, string)[] kv) => n => kv.FirstOrDefault(x => x.Item1 == n).Item2;

    [Fact]
    public void ParsesAFullIntuneCommandLine_SecretsComeFromEnvironmentNotArguments()
    {
        var args = new[] { "--configure-service", "--relay", "relay1.corp:443,relay2.corp:443", "--relay-fp", "AABB", "--relay-key-env", "RT_KEY", "--password-env", "RT_PW", "--enable", "--record", "--retention-days", "14", "--name", "KIOSK-7" };
        var (input, err) = RemoteTool.Service.ServiceSetupArgs.Parse(args, Env(("RT_KEY", "relay-secret"), ("RT_PW", "Correct-Horse-9")));
        Assert.Null(err);
        Assert.Equal("relay-secret", input!.RelayKey);
        Assert.Equal("Correct-Horse-9", input.NewPermanentPassword);
        Assert.True(input.Enabled); Assert.True(input.Record); Assert.True(input.ConsentWhenUserPresent);
        Assert.Equal(14, input.RetentionDays); Assert.Equal("KIOSK-7", input.DisplayName);
        Assert.DoesNotContain(args, a => a.Contains("Correct") || a.Contains("secret"));
    }

    [Theory]
    [InlineData("--enable")]                                             // enabling without a permanent password
    [InlineData("--relay", "not-a-valid-relay")]
    [InlineData("--password-env", "MISSING")]
    public void RejectsUnsafeOrIncompleteConfigurations(params string[] extra)
    {
        var (input, err) = RemoteTool.Service.ServiceSetupArgs.Parse(new[] { "--configure-service" }.Concat(extra).ToArray(), Env());
        Assert.Null(input);
        Assert.False(string.IsNullOrEmpty(err));
    }

    [Fact]
    public void WeakPermanentPasswordIsRejectedBeforeAnythingIsInstalled()
    {
        var (input, err) = RemoteTool.Service.ServiceSetupArgs.Parse(new[] { "--password-env", "P" }, Env(("P", "short")));
        Assert.Null(input);
        Assert.Contains("rejected", err);
    }

    [Fact]
    public void ConsentCanBeDisabledOnlyExplicitly()
    {
        var (input, _) = RemoteTool.Service.ServiceSetupArgs.Parse(new[] { "--no-user-consent" }, Env());
        Assert.False(input!.ConsentWhenUserPresent);
        var (def, _) = RemoteTool.Service.ServiceSetupArgs.Parse(Array.Empty<string>(), Env());
        Assert.True(def!.ConsentWhenUserPresent);
        Assert.False(def.Enabled);                                       // nothing is enabled unless asked for
    }
}

public class LanServiceTests
{
    [Fact]
    public void FirewallRulesAreScopedToProgramPrivateDomainAndLocalSubnet_NeverPublic()
    {
        var rules = RemoteTool.Service.Windows.FirewallCommands.Add(@"C:\Program Files\RemoteTool\RemoteTool.exe", 21118, 21119);
        Assert.Equal(2, rules.Count);
        foreach (var r in rules)
        {
            Assert.Contains("dir=in", r); Assert.Contains("profile=private,domain", r); Assert.Contains("remoteip=localsubnet", r);
            Assert.Contains(@"program=C:\Program Files\RemoteTool\RemoteTool.exe", r);
            Assert.DoesNotContain(r, a => a.Contains("public", StringComparison.OrdinalIgnoreCase) || a.Contains("any", StringComparison.OrdinalIgnoreCase) || a.Contains("profile=all"));
        }
        Assert.Contains(rules[0], a => a == "protocol=TCP"); Assert.Contains(rules[0], a => a == "localport=21118");
        Assert.Contains(rules[1], a => a == "protocol=UDP"); Assert.Contains(rules[1], a => a == "localport=21119");
        Assert.Equal(2, RemoteTool.Service.Windows.FirewallCommands.Remove().Count);
    }

    [Fact]
    public void LanFlagTurnsOnDirectListenerAndVisibility_OnlyWhenAsked()
    {
        var (on, _) = RemoteTool.Service.ServiceSetupArgs.Parse(new[] { "--lan" }, _ => null);
        Assert.True(on!.Lan);
        var (off, _) = RemoteTool.Service.ServiceSetupArgs.Parse(Array.Empty<string>(), _ => null);
        Assert.False(off!.Lan);
    }

    [Fact]
    public async Task ServiceAnswersDiscoveryOnlyWhenLanModeIsOn()
    {
        foreach (var lan in new[] { false, true })
        {
            var root = Path.Combine(Path.GetTempPath(), "rt-svc-lan-" + Guid.NewGuid().ToString("N"));
            try
            {
                var paths = new RemoteTool.Service.ServicePaths(root);
                Directory.CreateDirectory(paths.ServiceDir);
                var probe = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0); probe.Start(); var port = ((System.Net.IPEndPoint)probe.LocalEndpoint).Port; probe.Stop();
                var store = new RemoteTool.Service.ServiceConfigStore(paths.ConfigFile);
                var cfg = store.Load();
                cfg.UnattendedEnabled = true; cfg.DirectListenerEnabled = true; cfg.DirectPort = port; cfg.LanVisible = lan; cfg.LanDiscoveryPort = 0; cfg.DisplayName = "SVC-LAN";
                store.Save(cfg);
                await using var rt = new RemoteTool.Service.ServiceRuntime(paths, new TestProtector(), new FakeHelperLauncher(), new FakeSas(), new ListAudit(), TimeSpan.FromMilliseconds(100));
                rt.Start();
                if (!lan) { Assert.Null(rt.LanPort); continue; }
                var udp = Assert.IsType<int>(rt.LanPort);
                var hosts = await RemoteTool.Core.Lan.LanDiscovery.DiscoverAsync(TimeSpan.FromMilliseconds(700), default, udp, new[] { new System.Net.IPEndPoint(System.Net.IPAddress.Loopback, udp) });
                Assert.Equal(cfg.Id, Assert.Single(hosts).Id);
            }
            finally { try { Directory.Delete(root, true); } catch { } }
        }
    }
}
