using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using RemoteTool.Core.Protocol;
using RemoteTool.Core.Security;
using RemoteTool.Core.Session;

#pragma warning disable SYSLIB0039 // the attack test deliberately offers obsolete TLS versions
namespace RemoteTool.Core.Tests;

/// <summary>Attack-style tests: each one plays the adversary against a real host over real TLS/TCP sockets.</summary>
public class SecurityAttackTests
{
    private sealed class Rig : IAsyncDisposable
    {
        public HostService Host = null!;
        public FakeInjector Injector = new();
        public FakeConsent Consent = new();
        public ListAudit Audit = new();
        public int Port;

        public static Rig Start(HostPolicy? policy = null)
        {
            var r = new Rig();
            r.Host = new HostService(() => new FakeProducer(), () => r.Injector, r.Consent, r.Audit, policy ?? new HostPolicy("Target-PC"));
            var probe = new TcpListener(IPAddress.Loopback, 0); probe.Start(); r.Port = ((IPEndPoint)probe.LocalEndpoint).Port; probe.Stop();
            r.Host.StartDirectListener(r.Port);
            return r;
        }

        public async Task<ViewerSession> LegitViewer(string? password = null)
        {
            var c = new TcpClient { NoDelay = true }; await c.ConnectAsync(IPAddress.Loopback, Port);
            return await ViewerSession.ConnectAsync(c.GetStream(), "legit", password ?? Host.Password, new ListAudit(), Permissions.All, default);
        }

        /// <summary>After an attack the host must still serve the real user.</summary>
        public async Task AssertStillServing()
        {
            await using var v = await LegitViewer();
            Assert.Equal("Target-PC", v.HostName);
        }

        public ValueTask DisposeAsync() => Host.DisposeAsync();
    }

    // ------------------------------------------------------------------ transport

    [Fact]
    public async Task TlsDowngradeToOlderVersionsIsRefused()
    {
        await using var rig = Rig.Start();
        foreach (var old in new[] { SslProtocols.Tls12, SslProtocols.Tls11 })
        {
            using var tcp = new TcpClient(); await tcp.ConnectAsync(IPAddress.Loopback, rig.Port);
            using var cert = EphemeralCertificate.Create();
            await using var ssl = new SslStream(tcp.GetStream(), false, (_, _, _, _) => true);
            await Assert.ThrowsAnyAsync<Exception>(async () => await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = "x", EnabledSslProtocols = old, ClientCertificates = new() { cert.Certificate },
            }));
        }
        await rig.AssertStillServing();
    }

    [Fact]
    public async Task ClientWithoutACertificateGetsNowhere()
    {
        await using var rig = Rig.Start();
        using var tcp = new TcpClient(); await tcp.ConnectAsync(IPAddress.Loopback, rig.Port);
        await using var ssl = new SslStream(tcp.GetStream(), false, (_, _, _, _) => true);
        var proceeded = false;
        try
        {
            await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions { TargetHost = "x", EnabledSslProtocols = SslProtocols.Tls13 });
            var w = new FrameWriter(ssl);
            await w.WriteAsync(MessageType.Hello, new HelloMessage(ProtocolConstants.Version, "nocert", new byte[32]).Serialize(), default);
            using var cts = new CancellationTokenSource(2000);
            var f = await new FrameReader(ssl, MessageTypes.IsKnownPeer).ReadAsync(cts.Token);
            proceeded = f.Type == (byte)MessageType.AuthChallenge;
        }
        catch (Exception) { /* expected: the host aborts the connection */ }
        Assert.False(proceeded);
        Assert.False(rig.Audit.Has("auth_success"));
        await rig.AssertStillServing();
    }

    // ------------------------------------------------------------------ protocol state machine

    [Theory]
    [InlineData("consent-first")]
    [InlineData("mouse-first")]
    [InlineData("key-first")]
    [InlineData("clipboard-first")]
    [InlineData("file-offer-first")]
    [InlineData("auth-response-first")]
    public async Task SkippingTheHandshakeNeverReachesConsentOrInput(string attack)
    {
        await using var rig = Rig.Start();
        await using (var a = await RawPeer.ConnectAsync(rig.Port))
        {
            switch (attack)
            {
                case "consent-first": await a.W.WriteAsync(MessageType.ConsentRequest, new ConsentRequestMessage(Permissions.All).Serialize(), default); break;
                case "mouse-first": await a.W.WriteAsync(MessageType.MouseEvent, new MouseEventMessage(MouseKind.Down, MouseButton.Left, 1, 1, 0).Serialize(), default); break;
                case "key-first": await a.W.WriteAsync(MessageType.KeyEvent, new KeyEventMessage(65, false, false).Serialize(), default); break;
                case "clipboard-first": await a.W.WriteAsync(MessageType.ClipboardData, new ClipboardDataMessage("pwn").Serialize(), default); break;
                case "file-offer-first": await a.W.WriteAsync(MessageType.FileOffer, new FileOfferMessage(1, "evil.exe", 10, new byte[32]).Serialize(), default); break;
                case "auth-response-first": await a.W.WriteAsync(MessageType.AuthResponse, new AuthResponseMessage(new byte[32]).Serialize(), default); break;
            }
            Assert.True(await a.ConnectionEndsWithinAsync(TimeSpan.FromSeconds(5)), "host must drop a peer that skips authentication");
        }
        Assert.Equal(0, rig.Consent.Calls);
        Assert.Empty(rig.Injector.Events);
        await rig.AssertStillServing();
    }

    [Fact]
    public async Task ConsentCannotBeSkippedByAuthenticatedButUnconsentedPeer()
    {
        await using var rig = Rig.Start();
        rig.Consent.Allow = false;                              // the user clicks Deny
        await using var a = await RawPeer.ConnectAsync(rig.Port);
        var p = await a.AuthAsync(rig.Host.Password);
        Assert.True(p.Result!.Success);
        await a.W.WriteAsync(MessageType.ConsentRequest, new ConsentRequestMessage(Permissions.All).Serialize(), default);
        var denied = ConsentResultMessage.Parse((await a.R.ReadAsync(default)).Payload);
        Assert.False(denied.Granted);
        // now try to act as if allowed
        try   // the host drops the connection after a denial, so these writes may well fail - that is the correct outcome
        {
            await a.W.WriteAsync(MessageType.MouseEvent, new MouseEventMessage(MouseKind.Down, MouseButton.Left, 5, 5, 0).Serialize(), default);
            await a.W.WriteAsync(MessageType.KeyEvent, new KeyEventMessage(13, false, false).Serialize(), default);
        }
        catch (IOException) { }
        await a.ConnectionEndsWithinAsync(TimeSpan.FromSeconds(3));
        Assert.Empty(rig.Injector.Events);
        Assert.False(rig.Audit.Has("session_start"));
    }

    [Fact]
    public async Task CapturedProofCannotBeReplayedOnAnotherConnection()
    {
        await using var rig = Rig.Start();
        // 1) the victim's real login is observed (an attacker on the wire sees nonces and the proof, never the password)
        RawPeer.Proof captured;
        await using (var victim = await RawPeer.ConnectAsync(rig.Port))
        {
            captured = await victim.AuthAsync(rig.Host.Password);
            Assert.True(captured.Result!.Success);
        }
        // 2) the attacker replays the SAME Hello nonce and the SAME proof on a new connection (the password has also been rotated by now)
        var pwNow = rig.Host.Password;
        await using var attacker = await RawPeer.ConnectAsync(rig.Port);
        var replay = await attacker.AuthAsync(pwNow, fixedNonce: captured.NonceV, replayProof: captured.ViewerProof);
        Assert.False(replay.Result!.Success);
        Assert.Equal(AuthFailure.BadPassword, replay.Result.Failure);
    }

    [Fact]
    public async Task ProofForOneRoleOrOneConnectionIsUselessForAnother()
    {
        await using var rig = Rig.Start();
        var pw = rig.Host.Password;
        await using var a = await RawPeer.ConnectAsync(rig.Port);
        var p = await a.AuthAsync(pw, replayProof: new byte[32]);               // forged: all zero proof
        Assert.False(p.Result!.Success);
        // "reflection": use the HOST-role proof formula as the viewer proof
        await using var b = await RawPeer.ConnectAsync(rig.Port);
        var nonceV = RandomNumberGenerator.GetBytes(32);
        await b.W.WriteAsync(MessageType.Hello, new HelloMessage(ProtocolConstants.Version, "refl", PasswordHandshake.Commit(nonceV)).Serialize(), default);
        var ch = AuthChallengeMessage.Parse((await b.R.ReadAsync(default)).Payload);
        var key = PasswordHandshake.DeriveKey(pw, ch.Salt);
        var hostRoleProof = PasswordHandshake.HostProof(key, nonceV, ch.Nonce, b.LocalFp, b.RemoteFp);
        await b.W.WriteAsync(MessageType.AuthResponse, new AuthResponseMessage(hostRoleProof, nonceV).Serialize(), default);
        Assert.False(AuthResultMessage.Parse((await b.R.ReadAsync(default)).Payload).Success);
    }

    [Fact]
    public async Task HostOnlyMessagesFromTheViewerEndTheSessionWithoutInjectingAnything()
    {
        await using var rig = Rig.Start();
        await using (var a = await RawPeer.ConnectAsync(rig.Port))
        {
            Assert.True((await a.LoginAsync(rig.Host.Password)).Granted);
            await a.W.WriteAsync(MessageType.FrameUpdate, new FrameUpdateMessage(0, 1, 8, 8, true, new[] { new TileRect(0, 0, 8, 8, new byte[4]) }).Serialize(), default);
            Assert.True(await a.ConnectionEndsWithinAsync(TimeSpan.FromSeconds(5)));
        }
        await WaitUntil(() => rig.Host.ActiveSession is null);
        Assert.True(rig.Injector.ReleaseAllCalls >= 1);         // and nothing stays pressed
        await rig.AssertStillServing();
    }

    [Fact]
    public async Task HostileViewerNamesAreRejectedOrNeutralised()
    {
        await using var rig = Rig.Start();
        await using (var a = await RawPeer.ConnectAsync(rig.Port))
        {
            // control characters / bidi override in the name that will be shown in the consent dialog
            var bad = new ProtoWriter().U16(ProtocolConstants.Version).U16(8).Fixed(System.Text.Encoding.UTF8.GetBytes("ev\u0007il\r\nx")).Fixed(new byte[32]).U8(0).ToArray();
            await a.W.WriteAsync((byte)MessageType.Hello, bad, default);
            Assert.True(await a.ConnectionEndsWithinAsync(TimeSpan.FromSeconds(5)));
        }
        await using var legit = await RawPeer.ConnectAsync(rig.Port);
        var p = await legit.AuthAsync(rig.Host.Password, name: "Trusted‮IT");   // right-to-left override: allowed on the wire, shown sanitised
        Assert.True(p.Result!.Success);
        await legit.W.WriteAsync(MessageType.ConsentRequest, new ConsentRequestMessage(Permissions.All).Serialize(), default);
        await legit.R.ReadAsync(default);
        Assert.DoesNotContain(rig.Consent.Last!.ViewerName, c => char.IsControl(c) && c != '‮');
    }

    // ------------------------------------------------------------------ resource exhaustion

    [Fact]
    public async Task OversizedFramesBeforeAuthenticationAreDroppedWithoutBufferingThem()
    {
        await using var rig = Rig.Start();
        await using (var a = await RawPeer.ConnectAsync(rig.Port))
        {
            var header = new byte[5];
            System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(header, 200u * 1024 * 1024);   // claims 200 MB
            header[4] = (byte)MessageType.Hello;
            await a.Stream.WriteAsync(header);
            await a.Stream.FlushAsync();
            Assert.True(await a.ConnectionEndsWithinAsync(TimeSpan.FromSeconds(5)));
        }
        await rig.AssertStillServing();
    }

    [Fact]
    public async Task IdleConnectionsFromOneAttackerCannotLockOutOtherUsers_PreAuthSlotExhaustion()
    {
        await using var rig = Rig.Start();
        rig.Host.StopDirectListener();
        var l = new TcpListener(IPAddress.Loopback, 0); l.Start();
        var port = ((IPEndPoint)l.LocalEndpoint).Port;
        var n = 0;
        _ = Task.Run(async () =>
        {
            while (true)
            {
                TcpClient c;
                try { c = await l.AcceptTcpClientAsync(); } catch { return; }
                // the first TCP connections are the attacker's (same source), later ones come from "somebody else"
                var attacker = Interlocked.Increment(ref n) <= 12;
                var origin = new PeerOrigin(attacker ? "ip:6.6.6.6" : "ip:1.2.3.4", attacker ? "6.6.6.6" : "1.2.3.4", false, null);
                _ = rig.Host.HandleConnectionAsync(c.GetStream(), origin);
            }
        });
        var idle = new List<TcpClient>();
        for (var i = 0; i < 12; i++) { var c = new TcpClient(); await c.ConnectAsync(IPAddress.Loopback, port); idle.Add(c); }   // connect and say nothing
        await Task.Delay(300);

        var legit = new TcpClient(); await legit.ConnectAsync(IPAddress.Loopback, port);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(8));
        await using var v = await ViewerSession.ConnectAsync(legit.GetStream(), "real-user", rig.Host.Password, new ListAudit(), Permissions.All, cts.Token);
        Assert.Equal("Target-PC", v.HostName);
        foreach (var c in idle) c.Dispose();
        l.Stop();
    }

    // ------------------------------------------------------------------ fuzzing an authenticated session

    [Fact]
    public async Task AuthenticatedFuzzing_RandomFramesNeverCrashOrWedgeTheHost()
    {
        var unobserved = new List<Exception>();
        EventHandler<UnobservedTaskExceptionEventArgs> h = (_, e) => { lock (unobserved) unobserved.Add(e.Exception); };
        TaskScheduler.UnobservedTaskException += h;
        try
        {
            await using var rig = Rig.Start();
            var rng = new Random(2024);
            for (var round = 0; round < 25; round++)
            {
                await using (var a = await RawPeer.ConnectAsync(rig.Port))
                {
                    var consent = await a.LoginAsync(rig.Host.Password);
                    Assert.True(consent.Granted);
                    for (var i = 0; i < 40; i++)
                    {
                        var payload = new byte[rng.Next(0, 300)]; rng.NextBytes(payload);
                        var type = (byte)rng.Next(1, 23);
                        try { await a.W.WriteAsync(type, payload, default); } catch (IOException) { break; }
                        if (rng.Next(6) == 0)   // sometimes a structurally valid message with hostile values
                            try { await a.W.WriteAsync(MessageType.MouseEvent, new MouseEventMessage(MouseKind.Wheel, MouseButton.None, 65535, 0, int.MaxValue).Serialize(), default); } catch (Exception) { break; }
                    }
                    await a.ConnectionEndsWithinAsync(TimeSpan.FromMilliseconds(300));
                }
                await WaitUntil(() => rig.Host.ActiveSession is null, 8);
            }
            await rig.AssertStillServing();
            Assert.True(rig.Injector.ReleaseAllCalls >= 1);
            GC.Collect(); GC.WaitForPendingFinalizers(); GC.Collect();
            lock (unobserved) Assert.Empty(unobserved);              // no swallowed crashes in background tasks
        }
        finally { TaskScheduler.UnobservedTaskException -= h; }
    }

    [Fact]
    public async Task PreAuthFuzzing_RandomBytesAndFramesOverTls()
    {
        await using var rig = Rig.Start();
        var rng = new Random(77);
        for (var i = 0; i < 40; i++)
        {
            await using var a = await RawPeer.ConnectAsync(rig.Port);
            var junk = new byte[rng.Next(1, 600)]; rng.NextBytes(junk);
            try { await a.Stream.WriteAsync(junk); await a.Stream.FlushAsync(); } catch (IOException) { }
            await a.ConnectionEndsWithinAsync(TimeSpan.FromMilliseconds(250));
        }
        Assert.Equal(0, rig.Consent.Calls);
        await rig.AssertStillServing();
    }

    // ------------------------------------------------------------------ the other direction: a rogue host / rogue LAN neighbour

    [Fact]
    public async Task RogueHostWithoutThePasswordCannotImpersonateTheRealOne()
    {
        // a neighbour answers LAN discovery with the victim's code and the viewer connects to it.
        var l = new TcpListener(IPAddress.Loopback, 0); l.Start();
        var port = ((IPEndPoint)l.LocalEndpoint).Port;
        _ = Task.Run(async () =>
        {
            using var c = await l.AcceptTcpClientAsync();
            using var cert = EphemeralCertificate.Create();
            var ch = await TlsChannel.AcceptAsync(c.GetStream(), cert.Certificate, default);
            var r = new FrameReader(ch.Stream, MessageTypes.IsKnownPeer, ProtocolConstants.MaxFramePayload); var w = new FrameWriter(ch.Stream);
            await r.ReadAsync(default);                                                           // Hello
            await w.WriteAsync(MessageType.AuthChallenge, new AuthChallengeMessage("Target-PC", RandomNumberGenerator.GetBytes(32), RandomNumberGenerator.GetBytes(16)).Serialize(), default);
            await r.ReadAsync(default);                                                           // viewer's proof (an offline-guessing target, see docs)
            await w.WriteAsync(MessageType.AuthResult, new AuthResultMessage(true, AuthFailure.None, RandomNumberGenerator.GetBytes(32)).Serialize(), default);  // "success" with a forged host proof
            await Task.Delay(500);
        });
        var cc = new TcpClient(); await cc.ConnectAsync(IPAddress.Loopback, port);
        var e = await Assert.ThrowsAsync<ConnectFailedException>(async () =>
            await ViewerSession.ConnectAsync(cc.GetStream(), "victim", "ABCD2345", new ListAudit(), Permissions.All, default));
        Assert.Equal(ConnectFailure.PeerAuthenticationFailed, e.Failure);   // the viewer refuses to proceed (never sends consent request / never shows a screen)
        l.Stop();
    }

    [Fact]
    public void HostileGeometryCannotMakeTheViewerAllocateGigabytes()
    {
        // a malicious host announcing an absurd surface / rectangle area
        var huge = new FrameUpdateMessage(0, 1, 65535, 65535, true, new[] { new TileRect(0, 0, 65535, 65535, new byte[8]) }).Serialize();
        Assert.Throws<ProtocolException>(() => FrameUpdateMessage.Parse(huge));
        var hugeVideo = new VideoFrameMessage(0, 1, 65535, 65535, true, new byte[8]).Serialize();
        Assert.Throws<ProtocolException>(() => VideoFrameMessage.Parse(hugeVideo));
        var screen = new ScreenInfoMessage(new[] { new MonitorInfo(0, 0, 0, 65535, 65535, true, "x") }, 0).Serialize();
        Assert.Throws<ProtocolException>(() => ScreenInfoMessage.Parse(screen));
        // many full-frame rectangles in one message (decode-time CPU/memory amplification)
        var rects = Enumerable.Range(0, 200).Select(_ => new TileRect(0, 0, 4000, 4000, new byte[8])).ToArray();
        Assert.Throws<ProtocolException>(() => FrameUpdateMessage.Parse(new FrameUpdateMessage(0, 1, 4000, 4000, true, rects).Serialize()));
    }

    private static async Task WaitUntil(Func<bool> c, int sec = 10) { var t = DateTime.UtcNow.AddSeconds(sec); while (!c() && DateTime.UtcNow < t) await Task.Delay(20); Assert.True(c(), "condition not reached"); }
}
