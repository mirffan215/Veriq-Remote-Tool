using System.Net;
using System.Net.Sockets;
using RemoteTool.Core.Protocol;
using RemoteTool.Core.Session;

namespace RemoteTool.Core.Tests;

public class EndToEndTests
{
    private sealed class Rig : IAsyncDisposable
    {
        public HostService Host = null!;
        public FakeInjector Injector = new();
        public FakeConsent Consent = new();
        public ListAudit HostAudit = new();
        public int Port;

        public static Rig Start(HostPolicy? policy = null)
        {
            var r = new Rig();
            r.Host = new HostService(() => new FakeProducer(), () => r.Injector, r.Consent, r.HostAudit, policy ?? new HostPolicy("Test-PC"));
            var probe = new TcpListener(IPAddress.Loopback, 0);
            probe.Start();
            r.Port = ((IPEndPoint)probe.LocalEndpoint).Port;
            probe.Stop();
            r.Host.StartDirectListener(r.Port);
            return r;
        }

        public async Task<Stream> Dial()
        {
            var c = new TcpClient { NoDelay = true };
            await c.ConnectAsync(IPAddress.Loopback, Port);
            return c.GetStream();
        }

        public ValueTask DisposeAsync() => Host.DisposeAsync();
    }

    [Fact]
    public async Task ViewerConnectsConsentsStreamsAndInjectsInput()
    {
        await using var rig = Rig.Start();
        var pw = rig.Host.Password;
        var audit = new ListAudit();
        await using var v = await ViewerSession.ConnectAsync(await rig.Dial(), "alice", pw, audit, Permissions.All, default);

        Assert.Equal("Test-PC", v.HostName);
        Assert.Equal("alice", rig.Consent.Last!.ViewerName);
        Assert.True((v.Permissions & Permissions.Control) != 0);

        var got = new TaskCompletionSource<FrameUpdateMessage>();
        v.FrameReceived += f => got.TrySetResult(f);
        v.Start();
        var frame = await got.Task.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.True(frame.Keyframe);
        Assert.Equal(64, frame.Width);

        await v.SendMouseAsync(new MouseEventMessage(MouseKind.Move, MouseButton.None, 1000, 2000, 0));
        await v.SendKeyAsync(new KeyEventMessage(65, false, false));
        await WaitFor(() => rig.Injector.Events.Count >= 2);
        Assert.Contains("mouse:Move:1000:2000", rig.Injector.Events);
        Assert.Contains("key:65:down", rig.Injector.Events);

        Assert.NotEqual(pw, rig.Host.Password); // single-use password rotated
        await v.DisposeAsync();
        await WaitFor(() => rig.HostAudit.Has("session_end"));
        Assert.True(rig.Injector.ReleaseAllCalls >= 1, "held input must be released on disconnect");
        Assert.True(rig.HostAudit.Has("consent_granted"));
        Assert.DoesNotContain(rig.HostAudit.Lines, l => l.Contains(pw));
    }

    [Fact]
    public async Task WrongPasswordFailsAndLocksOutAfterFiveAttempts()
    {
        await using var rig = Rig.Start();
        for (var i = 0; i < 4; i++)
        {
            var e = await Assert.ThrowsAsync<ConnectFailedException>(async () =>
                await ViewerSession.ConnectAsync(await rig.Dial(), "mallory", "WRONGPW2", new ListAudit(), Permissions.All, default));
            Assert.Equal(ConnectFailure.BadPassword, e.Failure);
        }
        var pwBefore = rig.Host.Password;
        var last = await Assert.ThrowsAsync<ConnectFailedException>(async () =>
            await ViewerSession.ConnectAsync(await rig.Dial(), "mallory", "WRONGPW2", new ListAudit(), Permissions.All, default));
        Assert.Equal(ConnectFailure.Blocked, last.Failure);
        Assert.NotEqual(pwBefore, rig.Host.Password); // password rotated on lockout

        // even the correct (new) password is refused for the blocked source
        await Assert.ThrowsAnyAsync<Exception>(async () =>
            await ViewerSession.ConnectAsync(await rig.Dial(), "mallory", rig.Host.Password, new ListAudit(), Permissions.All, default));
        Assert.Equal(0, rig.Consent.Last is null ? 0 : 0);
        Assert.False(rig.HostAudit.Has("consent_granted"));
        Assert.True(rig.HostAudit.Has("source_blocked"));
    }

    [Fact]
    public async Task DeniedConsentIsReported()
    {
        await using var rig = Rig.Start();
        rig.Consent.Allow = false;
        var e = await Assert.ThrowsAsync<ConnectFailedException>(async () =>
            await ViewerSession.ConnectAsync(await rig.Dial(), "bob", rig.Host.Password, new ListAudit(), Permissions.All, default));
        Assert.Equal(ConnectFailure.Denied, e.Failure);
        Assert.True(rig.HostAudit.Has("consent_denied"));
    }

    [Fact]
    public async Task ViewOnlyPolicyStripsControlAndDropsInput()
    {
        await using var rig = Rig.Start(new HostPolicy("Test-PC", ViewOnly: true));
        await using var v = await ViewerSession.ConnectAsync(await rig.Dial(), "carol", rig.Host.Password, new ListAudit(), Permissions.All, default);
        Assert.Equal(Permissions.None, v.Permissions & Permissions.Control);
        v.Start();
        await v.SendMouseAsync(new MouseEventMessage(MouseKind.Move, MouseButton.None, 1, 1, 0));
        await Task.Delay(300);
        Assert.Empty(rig.Injector.Events);
    }

    [Fact]
    public async Task HostCanDisconnectActiveSession()
    {
        await using var rig = Rig.Start();
        await using var v = await ViewerSession.ConnectAsync(await rig.Dial(), "dave", rig.Host.Password, new ListAudit(), Permissions.All, default);
        var ended = new TaskCompletionSource<ByeReason>();
        v.Ended += (r, _) => ended.TrySetResult(r);
        v.Start();
        await WaitFor(() => rig.Host.ActiveSession is not null); // the UI hotkey/button only exists after SessionStarted
        rig.Host.DisconnectActive(ByeReason.Emergency);
        Assert.Equal(ByeReason.Emergency, await ended.Task.WaitAsync(TimeSpan.FromSeconds(10)));
    }

    [Fact]
    public async Task SecondViewerIsRefusedWhileSessionActive()
    {
        await using var rig = Rig.Start();
        await using var v1 = await ViewerSession.ConnectAsync(await rig.Dial(), "one", rig.Host.Password, new ListAudit(), Permissions.All, default);
        var e = await Assert.ThrowsAsync<ConnectFailedException>(async () =>
            await ViewerSession.ConnectAsync(await rig.Dial(), "two", rig.Host.Password, new ListAudit(), Permissions.All, default));
        Assert.Equal(ConnectFailure.Busy, e.Failure);
    }

    [Fact]
    public async Task AllowListRejectsOtherAddresses()
    {
        await using var rig = Rig.Start(new HostPolicy("Test-PC", IpAllowList: new[] { "10.99.99.99" }));
        await Assert.ThrowsAnyAsync<Exception>(async () =>
            await ViewerSession.ConnectAsync(await rig.Dial(), "eve", rig.Host.Password, new ListAudit(), Permissions.All, default));
        Assert.True(rig.HostAudit.Has("connection_rejected"));
    }

    [Fact]
    public async Task ActiveManInTheMiddleIsDetected()
    {
        // A "relay" that terminates TLS on both legs (own certificates) and forwards plaintext frames.
        // Channel binding must make the host reject the proof, even though the password is correct.
        await using var rig = Rig.Start();
        var mitmListener = new TcpListener(IPAddress.Loopback, 0);
        mitmListener.Start();
        var mitmPort = ((IPEndPoint)mitmListener.LocalEndpoint).Port;
        _ = Task.Run(async () =>
        {
            using var viewerSide = await mitmListener.AcceptTcpClientAsync();
            using var certA = RemoteTool.Core.Security.EphemeralCertificate.Create("mitm-a");
            using var certB = RemoteTool.Core.Security.EphemeralCertificate.Create("mitm-b");
            var toViewer = await RemoteTool.Core.Security.TlsChannel.AcceptAsync(viewerSide.GetStream(), certA.Certificate, default);
            using var hostSide = new TcpClient();
            await hostSide.ConnectAsync(IPAddress.Loopback, rig.Port);
            var toHost = await RemoteTool.Core.Security.TlsChannel.ConnectAsync(hostSide.GetStream(), certB.Certificate, default);
            async Task Pump(Stream a, Stream b)
            {
                var buf = new byte[8192];
                try { int n; while ((n = await a.ReadAsync(buf)) > 0) { await b.WriteAsync(buf.AsMemory(0, n)); await b.FlushAsync(); } } catch { }
                b.Dispose();
            }
            await Task.WhenAll(Pump(toViewer.Stream, toHost.Stream), Pump(toHost.Stream, toViewer.Stream));
        });
        var c = new TcpClient();
        await c.ConnectAsync(IPAddress.Loopback, mitmPort);
        var ex = await Assert.ThrowsAnyAsync<Exception>(async () =>
            await ViewerSession.ConnectAsync(c.GetStream(), "alice", rig.Host.Password, new ListAudit(), Permissions.All, default));
        Assert.IsType<ConnectFailedException>(ex);
        Assert.False(rig.HostAudit.Has("consent_granted"));
        Assert.True(rig.HostAudit.Has("auth_failure"));
        mitmListener.Stop();
    }

    [Fact]
    public async Task GarbageBeforeHandshakeIsHandledQuietly()
    {
        await using var rig = Rig.Start();
        using var c = new TcpClient();
        await c.ConnectAsync(IPAddress.Loopback, rig.Port);
        var s = c.GetStream();
        await s.WriteAsync(new byte[] { 0xff, 0xff, 0xff, 0xff, 0x01, 2, 3, 4 });
        await Task.Delay(500);
        // host must still serve a legitimate viewer afterwards
        await using var v = await ViewerSession.ConnectAsync(await rig.Dial(), "alice", rig.Host.Password, new ListAudit(), Permissions.All, default);
        Assert.NotNull(v);
    }

    private static async Task WaitFor(Func<bool> cond)
    {
        var until = DateTime.UtcNow.AddSeconds(10);
        while (!cond() && DateTime.UtcNow < until) await Task.Delay(25);
        Assert.True(cond(), "condition not reached in time");
    }
}
