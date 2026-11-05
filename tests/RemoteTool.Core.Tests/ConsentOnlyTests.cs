using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using RemoteTool.Core.Protocol;
using RemoteTool.Core.Security;
using RemoteTool.Core.Session;

namespace RemoteTool.Core.Tests;

/// <summary>The AnyDesk-style flow: type the code, the other person clicks Accept. No password; a 6-digit code protects against a man in the middle.</summary>
public class ConsentOnlyTests
{
    private sealed class Rig : IAsyncDisposable
    {
        public HostService Host = null!; public FakeConsent Consent = new(); public ListAudit Audit = new(); public FakeInjector Injector = new(); public int Port;
        public static Rig Start(HostPolicy? policy = null)
        {
            var r = new Rig();
            r.Host = new HostService(() => new FakeProducer(), () => r.Injector, r.Consent, r.Audit, policy ?? new HostPolicy("Reception-PC"));
            var p = new TcpListener(IPAddress.Loopback, 0); p.Start(); r.Port = ((IPEndPoint)p.LocalEndpoint).Port; p.Stop();
            r.Host.StartDirectListener(r.Port);
            return r;
        }
        public async Task<ViewerSession> Request(int? port = null, Action<string>? onCode = null, string name = "IT-Support")
        {
            var c = new TcpClient { NoDelay = true }; await c.ConnectAsync(IPAddress.Loopback, port ?? Port);
            return await ViewerSession.ConnectAsync(c.GetStream(), name, "", new ListAudit(), Permissions.All, default, consentOnly: true, onSecurityCode: onCode);
        }
        public ValueTask DisposeAsync() => Host.DisposeAsync();
    }

    [Fact]
    public async Task TypeTheCode_TheOtherUserAccepts_NoPasswordNeeded_AndBothSeeTheSameSecurityCode()
    {
        await using var rig = Rig.Start();
        string? shownWhileWaiting = null;
        await using var v = await rig.Request(onCode: c => shownWhileWaiting = c);
        Assert.Equal(1, rig.Consent.Calls);
        Assert.True(rig.Consent.Last!.ConsentOnly);
        Assert.Equal(v.SecurityCode, rig.Consent.Last.SecurityCode);          // honest connection: identical codes on both screens
        Assert.Equal(shownWhileWaiting, v.SecurityCode);                      // the viewer could show it while waiting for the click
        Assert.Matches(@"^\d{3} \d{3}$", v.SecurityCode);
        var got = new TaskCompletionSource<bool>(); v.FrameReceived += _ => got.TrySetResult(true); v.Start();
        Assert.True(await got.Task.WaitAsync(TimeSpan.FromSeconds(10)));
    }

    [Fact]
    public async Task WithoutTheAcceptClickNothingHappens_DenyEndsItAndInputIsNeverInjected()
    {
        await using var rig = Rig.Start();
        rig.Consent.Allow = false;
        var e = await Assert.ThrowsAsync<ConnectFailedException>(() => rig.Request());
        Assert.Equal(ConnectFailure.Denied, e.Failure);
        Assert.Empty(rig.Injector.Events);
        Assert.False(rig.Audit.Has("session_start"));

        // a raw attacker that authenticates click-only and then skips straight to input
        rig.Consent.Allow = true;
        await using var a = await RawPeer.ConnectAsync(rig.Port);
        var p = await a.AuthAsync("", mode: AuthMode.Consent);
        Assert.True(p.Result!.Success);                                          // authentication proves nothing in this mode ...
        await a.W.WriteAsync(MessageType.MouseEvent, new MouseEventMessage(MouseKind.Down, MouseButton.Left, 1, 1, 0).Serialize(), default);
        Assert.True(await a.ConnectionEndsWithinAsync(TimeSpan.FromSeconds(5)));  // ... so the host insists on the consent step and drops the peer
        Assert.Empty(rig.Injector.Events);
        Assert.Equal(1, rig.Consent.Calls);                                       // the skipped-ahead attempt never even reached the dialog
    }

    [Fact]
    public async Task RepeatedlyDeniedRequestsBlockTheRequester_NoSpamming()
    {
        await using var rig = Rig.Start();
        rig.Consent.Allow = false;
        for (var i = 0; i < AuthLockout.MaxFailures; i++)
            Assert.Equal(ConnectFailure.Denied, (await Assert.ThrowsAsync<ConnectFailedException>(() => rig.Request())).Failure);
        Assert.Contains(rig.Audit.Lines, l => l.StartsWith("source_blocked") && l.Contains("repeated-denied-requests"));
        var calls = rig.Consent.Calls;
        await Assert.ThrowsAnyAsync<Exception>(() => rig.Request());                // 6th: dropped before any dialog
        Assert.Equal(calls, rig.Consent.Calls);
    }

    [Fact]
    public async Task OnlyOneRequestAtATime_AnotherRequesterGetsBusyWhileTheDialogIsOpen()
    {
        var release = new TaskCompletionSource();
        var slow = new SlowConsent(release.Task);
        var host = new HostService(() => new FakeProducer(), () => new FakeInjector(), slow, new ListAudit(), new HostPolicy("PC"));
        await using var _ = host;
        var p = new TcpListener(IPAddress.Loopback, 0); p.Start(); var port = ((IPEndPoint)p.LocalEndpoint).Port; p.Stop();
        host.StartDirectListener(port);
        var first = Task.Run(async () => { var c = new TcpClient(); await c.ConnectAsync(IPAddress.Loopback, port);
            return await ViewerSession.ConnectAsync(c.GetStream(), "first", "", new ListAudit(), Permissions.All, default, consentOnly: true); });
        await Task.Delay(500);                                                      // the first dialog is now open
        var c2 = new TcpClient(); await c2.ConnectAsync(IPAddress.Loopback, port);
        var e = await Assert.ThrowsAsync<ConnectFailedException>(async () => await ViewerSession.ConnectAsync(c2.GetStream(), "second", "", new ListAudit(), Permissions.All, default, consentOnly: true));
        Assert.Equal(ConnectFailure.Busy, e.Failure);
        release.SetResult();
        await using var v = await first;
    }

    private sealed class SlowConsent : IConsentProvider
    {
        private readonly Task _gate; public SlowConsent(Task gate) { _gate = gate; }
        public async Task<ConsentDecision> RequestAsync(ConsentRequestInfo info, CancellationToken ct) { await _gate; return new ConsentDecision(true, info.Allowed); }
    }

    [Fact]
    public async Task HostsThatRequireAPasswordRefuseClickOnlyRequests_WithoutShowingAnyDialog()
    {
        await using var rig = Rig.Start(new HostPolicy("Locked-Down-PC", AllowConsentOnly: false));
        var e = await Assert.ThrowsAsync<ConnectFailedException>(() => rig.Request());
        Assert.Equal(ConnectFailure.PasswordRequired, e.Failure);
        Assert.Equal(0, rig.Consent.Calls);
        // and the normal password path still works on the same host
        var c = new TcpClient(); await c.ConnectAsync(IPAddress.Loopback, rig.Port);
        await using var v = await ViewerSession.ConnectAsync(c.GetStream(), "u", rig.Host.Password, new ListAudit(), Permissions.All, default);
        Assert.Equal(1, rig.Consent.Calls);
    }

    /// <summary>
    /// A protocol-aware attacker (e.g. a malicious relay): terminates TLS towards both sides and runs BOTH click-only handshakes itself - possible because
    /// the click-only key is public. It then forwards everything, so the session "works" and the attacker reads the screen.
    /// </summary>
    private static async Task RunSmartMitm(TcpListener listener, int hostPort)
    {
        using var viewerSide = await listener.AcceptTcpClientAsync();
        using var certA = EphemeralCertificate.Create("mitm-a"); using var certB = EphemeralCertificate.Create("mitm-b");
        var toViewer = await TlsChannel.AcceptAsync(viewerSide.GetStream(), certA.Certificate, default);
        var r1 = new FrameReader(toViewer.Stream, MessageTypes.IsKnownPeer, ProtocolConstants.PreAuthMaxFramePayload); var w1 = new FrameWriter(toViewer.Stream);
        var hello = HelloMessage.Parse((await r1.ReadAsync(default)).Payload);

        using var hostSide = new TcpClient(); await hostSide.ConnectAsync(IPAddress.Loopback, hostPort);
        var toHost = await TlsChannel.ConnectAsync(hostSide.GetStream(), certB.Certificate, default);
        var r2 = new FrameReader(toHost.Stream, MessageTypes.IsKnownPeer, ProtocolConstants.PreAuthMaxFramePayload); var w2 = new FrameWriter(toHost.Stream);

        // attacker acts as the viewer towards the host
        var nonceMV = RandomNumberGenerator.GetBytes(32);
        await w2.WriteAsync(MessageType.Hello, new HelloMessage(ProtocolConstants.Version, hello.ViewerName, PasswordHandshake.Commit(nonceMV), AuthMode.Consent).Serialize(), default);
        var ch2 = AuthChallengeMessage.Parse((await r2.ReadAsync(default)).Payload);
        var proof2 = PasswordHandshake.ViewerProof(PasswordHandshake.ConsentModeKey, nonceMV, ch2.Nonce, toHost.LocalFingerprint, toHost.RemoteFingerprint);
        await w2.WriteAsync(MessageType.AuthResponse, new AuthResponseMessage(proof2, nonceMV).Serialize(), default);
        await r2.ReadAsync(default);                                                             // AuthResult (success)
        r2.MaxPayload = ProtocolConstants.MaxFramePayload;

        // ... and as the host towards the viewer
        var nonceMH = RandomNumberGenerator.GetBytes(32);
        await w1.WriteAsync(MessageType.AuthChallenge, new AuthChallengeMessage(ch2.HostName, nonceMH, RandomNumberGenerator.GetBytes(16)).Serialize(), default);
        var resp1 = AuthResponseMessage.Parse((await r1.ReadAsync(default)).Payload);
        var hostProof1 = PasswordHandshake.HostProof(PasswordHandshake.ConsentModeKey, resp1.RevealedNonce, nonceMH, toViewer.RemoteFingerprint, toViewer.LocalFingerprint);
        await w1.WriteAsync(MessageType.AuthResult, new AuthResultMessage(true, AuthFailure.None, hostProof1).Serialize(), default);
        r1.MaxPayload = ProtocolConstants.MaxFramePayload;

        async Task Pump(FrameReader from, FrameWriter to) { try { while (true) { var f = await from.ReadAsync(default); await to.WriteAsync(f.Type, f.Payload, default); } } catch { } }
        await Task.WhenAll(Pump(r1, w2), Pump(r2, w1));
    }

    [Fact]
    public async Task ActiveManInTheMiddle_GetsThroughTheHandshake_ButTheTwoScreensShowDifferentSecurityCodes()
    {
        await using var rig = Rig.Start();
        // 1) honest connection: codes agree
        await using (var honest = await rig.Request()) Assert.Equal(honest.SecurityCode, rig.Consent.Last!.SecurityCode);
        await WaitUntil(() => rig.Host.ActiveSession is null);

        // 2) a protocol-aware attacker in the middle: the session is established and works (this mode cannot prevent that by itself) ...
        var mitm = new TcpListener(IPAddress.Loopback, 0); mitm.Start();
        var mitmPort = ((IPEndPoint)mitm.LocalEndpoint).Port;
        _ = Task.Run(() => RunSmartMitm(mitm, rig.Port));
        await using var viaMitm = await rig.Request(port: mitmPort);
        var hostSees = rig.Consent.Last!.SecurityCode;
        // ... but the people can see it: the code on the viewer's screen is not the code in the host's dialog (they differ with probability 1 - 10^-6)
        Assert.NotEqual(viaMitm.SecurityCode, hostSees);
        mitm.Stop();
    }

    [Fact]
    public async Task SimpleByteForwardingRelayIsAlreadyRejectedByTheHandshakeItself()
    {
        await using var rig = Rig.Start();
        var mitm = new TcpListener(IPAddress.Loopback, 0); mitm.Start();
        var mitmPort = ((IPEndPoint)mitm.LocalEndpoint).Port;
        _ = Task.Run(async () =>
        {
            using var viewerSide = await mitm.AcceptTcpClientAsync();
            using var certA = EphemeralCertificate.Create("a"); using var certB = EphemeralCertificate.Create("b");
            var toViewer = await TlsChannel.AcceptAsync(viewerSide.GetStream(), certA.Certificate, default);
            using var hostSide = new TcpClient(); await hostSide.ConnectAsync(IPAddress.Loopback, rig.Port);
            var toHost = await TlsChannel.ConnectAsync(hostSide.GetStream(), certB.Certificate, default);
            async Task Pump(Stream a, Stream b) { var buf = new byte[8192]; try { int n; while ((n = await a.ReadAsync(buf)) > 0) { await b.WriteAsync(buf.AsMemory(0, n)); await b.FlushAsync(); } } catch { } b.Dispose(); }
            await Task.WhenAll(Pump(toViewer.Stream, toHost.Stream), Pump(toHost.Stream, toViewer.Stream));
        });
        await Assert.ThrowsAnyAsync<ConnectFailedException>(() => rig.Request(port: mitmPort));
        Assert.Equal(0, rig.Consent.Calls);
        mitm.Stop();
    }

    [Fact]
    public async Task SecurityCodeCannotBeGround_ARevealedNonceThatDoesNotMatchTheCommitmentIsRejected()
    {
        await using var rig = Rig.Start();
        await using var a = await RawPeer.ConnectAsync(rig.Port);
        var committed = RandomNumberGenerator.GetBytes(32);
        var different = RandomNumberGenerator.GetBytes(32);                         // attacker swaps in a nonce chosen AFTER seeing the host's nonce
        await a.W.WriteAsync(MessageType.Hello, new HelloMessage(ProtocolConstants.Version, "grinder", PasswordHandshake.Commit(committed), AuthMode.Consent).Serialize(), default);
        var ch = AuthChallengeMessage.Parse((await a.R.ReadAsync(default)).Payload);
        var proof = PasswordHandshake.ViewerProof(PasswordHandshake.ConsentModeKey, different, ch.Nonce, a.LocalFp, a.RemoteFp);
        await a.W.WriteAsync(MessageType.AuthResponse, new AuthResponseMessage(proof, different).Serialize(), default);
        Assert.False(AuthResultMessage.Parse((await a.R.ReadAsync(default)).Payload).Success);
        Assert.Equal(0, rig.Consent.Calls);
    }

    [Fact]
    public void SecurityCodeDependsOnEveryInputAndIsWellDistributed()
    {
        byte[] R() => RandomNumberGenerator.GetBytes(32);
        byte[] nv = R(), nh = R(), fv = R(), fh = R();
        var c = PasswordHandshake.SecurityCode(nv, nh, fv, fh);
        Assert.Equal(c, PasswordHandshake.SecurityCode(nv, nh, fv, fh));
        Assert.NotEqual(c, PasswordHandshake.SecurityCode(R(), nh, fv, fh));
        Assert.NotEqual(c, PasswordHandshake.SecurityCode(nv, R(), fv, fh));
        Assert.NotEqual(c, PasswordHandshake.SecurityCode(nv, nh, R(), fh));
        Assert.NotEqual(c, PasswordHandshake.SecurityCode(nv, nh, fv, R()));
        var seen = new HashSet<string>();
        for (var i = 0; i < 5000; i++) { var x = PasswordHandshake.SecurityCode(R(), R(), R(), R()); Assert.Matches(@"^\d{3} \d{3}$", x); seen.Add(x); }
        Assert.InRange(seen.Count, 4900, 5000);                                      // ~uniform over 10^6 values
    }

    private static async Task WaitUntil(Func<bool> c, int sec = 10) { var t = DateTime.UtcNow.AddSeconds(sec); while (!c() && DateTime.UtcNow < t) await Task.Delay(20); Assert.True(c(), "condition not reached"); }
}
