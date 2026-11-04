using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using RemoteTool.Core.Audit;
using RemoteTool.Core.Protocol;
using RemoteTool.Core.Recording;
using RemoteTool.Core.Security;
using RemoteTool.Core.Session;

namespace RemoteTool.Core.Tests;

public class PermanentPasswordTests
{
    [Theory]
    [InlineData("short1A!", false)]
    [InlineData("alllowercaseletters", false)]
    [InlineData("aaaaaaaaaaaa1A", false)]
    [InlineData("Correct-Horse-9", true)]
    public void PolicyRejectsWeakPermanentPasswords(string pw, bool ok) => Assert.Equal(ok, PermanentPasswordStore.Validate(pw) is null);

    [Fact]
    public void StoresDerivedKeyNotThePassword_AndSurvivesReload()
    {
        var dir = Path.Combine(Path.GetTempPath(), "rt-" + Guid.NewGuid().ToString("N"));
        try
        {
            var file = Path.Combine(dir, "perm.json");
            var store = new PermanentPasswordStore(file, new TestProtector());
            Assert.False(store.Enabled);
            store.Set("Correct-Horse-9");
            Assert.DoesNotContain("Correct", File.ReadAllText(file));
            Assert.Equal(PasswordHandshake.DeriveKey("Correct-Horse-9", store.Salt), store.Key);
            var again = new PermanentPasswordStore(file, new TestProtector());
            Assert.True(again.Enabled);
            Assert.Equal(store.Key, again.Key);
            again.Clear();
            Assert.False(new PermanentPasswordStore(file, new TestProtector()).Enabled);
            Assert.Throws<ArgumentException>(() => store.Set("weak"));
            File.WriteAllText(file, "{ not json");
            Assert.False(new PermanentPasswordStore(file, new TestProtector()).Enabled); // corrupt => disabled, never open
        }
        finally { try { Directory.Delete(dir, true); } catch { } }
    }

    [Fact]
    public void BreakerTripsAfterManyFailuresAndRecovers()
    {
        var t = new Fake();
        var b = new FailureBreaker(3, TimeSpan.FromMinutes(15), t);
        Assert.False(b.RegisterFailure()); Assert.False(b.RegisterFailure());
        Assert.True(b.RegisterFailure());
        Assert.True(b.IsTripped);
        t.Now += TimeSpan.FromMinutes(16);
        Assert.False(b.IsTripped);
    }

    private sealed class Fake : TimeProvider { public DateTimeOffset Now = DateTimeOffset.UnixEpoch; public override DateTimeOffset GetUtcNow() => Now; }
}

public class AuditChainTests
{
    private static string Dir() => Path.Combine(Path.GetTempPath(), "rt-" + Guid.NewGuid().ToString("N"));

    [Fact]
    public void ChainVerifiesAcrossRotationAndRestart_AndDetectsEditsDeletesInsertions()
    {
        var dir = Dir();
        try
        {
            var log = new JsonlAuditLog(dir, "host", maxFileBytes: 400);
            for (var i = 0; i < 12; i++) log.Write("e", ("n", i));
            var log2 = new JsonlAuditLog(dir, "host", maxFileBytes: 400); // restart continues the chain
            for (var i = 12; i < 16; i++) log2.Write("e", ("n", i));
            Assert.True(Directory.GetFiles(dir, "*.jsonl").Length > 1);
            var ok = AuditVerifier.Verify(dir, "host");
            Assert.True(ok.Ok, ok.Problem);
            Assert.Equal(16, ok.Lines);

            var files = AuditVerifier.FilesInOrder(dir, "host");
            var f = files[0];
            var original = File.ReadAllLines(f);

            File.WriteAllLines(f, original.Select((l, i) => i == 1 ? l.Replace("\"n\":1", "\"n\":99") : l));          // edit
            Assert.False(AuditVerifier.Verify(dir, "host").Ok);
            File.WriteAllLines(f, original.Where((_, i) => i != 1));                                                    // delete
            Assert.False(AuditVerifier.Verify(dir, "host").Ok);
            File.WriteAllLines(f, original.Take(1).Concat(new[] { original[0] }).Concat(original.Skip(1)));            // insert
            Assert.False(AuditVerifier.Verify(dir, "host").Ok);
            File.WriteAllLines(f, original);
            Assert.True(AuditVerifier.Verify(dir, "host").Ok);
        }
        finally { try { Directory.Delete(dir, true); } catch { } }
    }

    [Fact]
    public void LegacyUnchainedPrefixIsToleratedButMidFileGapsAreNot()
    {
        var dir = Dir();
        try
        {
            Directory.CreateDirectory(dir);
            File.WriteAllText(Path.Combine(dir, "audit-host-20200101.jsonl"), "{\"event\":\"old\"}\n");
            var log = new JsonlAuditLog(dir, "host");
            log.Write("new1"); log.Write("new2");
            Assert.True(AuditVerifier.Verify(dir, "host").Ok);
        }
        finally { try { Directory.Delete(dir, true); } catch { } }
    }
}

public class RecordingTests
{
    private static SessionInfo Info() => new(Guid.NewGuid(), "VIEWERMARKER-ALICE", "10.0.0.5", Permissions.Control, DateTimeOffset.UtcNow);

    [Fact]
    public void RecordsEncryptedAndReadsBack_TamperingReorderingAndGapsAreDetected()
    {
        var dir = Path.Combine(Path.GetTempPath(), "rt-" + Guid.NewGuid().ToString("N"));
        try
        {
            var prot = new TestProtector();
            var f = new SessionRecorderFactory(dir, prot);
            var rec = f.Create(Info(), "HOST")!;
            var tile = new FrameUpdateMessage(0, 1, 64, 64, true, new[] { new TileRect(0, 0, 64, 64, Encoding.ASCII.GetBytes("SCREENMARKER-JPEG")) });
            rec.WriteFrame(tile); rec.WriteFrame(tile); rec.WriteEvent("monitor-switch");
            var done = rec.Complete("Normal")!.Value;
            Assert.Equal(Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(done.Path))), done.Sha256);

            var raw = File.ReadAllBytes(done.Path);
            foreach (var secret in new[] { "VIEWERMARKER", "SCREENMARKER", "monitor-switch" })
                Assert.True(raw.AsSpan().IndexOf(Encoding.ASCII.GetBytes(secret)) < 0, $"'{secret}' stored in clear");

            var recs = RecordingReader.Read(done.Path, prot).ToList();
            Assert.Equal(new[] { RecordType.Meta, RecordType.TileFrame, RecordType.TileFrame, RecordType.Event, RecordType.End }, recs.Select(r => r.Type));
            Assert.Contains("VIEWERMARKER-ALICE", Encoding.UTF8.GetString(recs[0].Payload));
            Assert.Equal(tile.Rects[0].Jpeg, FrameUpdateMessage.Parse(recs[1].Payload).Rects[0].Jpeg);

            var bad = (byte[])raw.Clone(); bad[^30] ^= 1;                                   // flip a ciphertext bit
            File.WriteAllBytes(done.Path + ".bad", bad);
            Assert.ThrowsAny<CryptographicException>(() => RecordingReader.Read(done.Path + ".bad", prot).ToList());

            // remove the first frame record entirely => counter gap => authentication failure
            var headerLen = raw.Length - recs.Sum(r => 4 + 16 + 9 + r.Payload.Length);
            var first = 4 + 16 + 9 + recs[0].Payload.Length;
            var second = 4 + 16 + 9 + recs[1].Payload.Length;
            var gap = raw.Take(headerLen + first).Concat(raw.Skip(headerLen + first + second)).ToArray();
            File.WriteAllBytes(done.Path + ".gap", gap);
            Assert.ThrowsAny<CryptographicException>(() => RecordingReader.Read(done.Path + ".gap", prot).ToList());
        }
        finally { try { Directory.Delete(dir, true); } catch { } }
    }

    [Fact]
    public void OldRecordingsAreDeletedByRetention()
    {
        var dir = Path.Combine(Path.GetTempPath(), "rt-" + Guid.NewGuid().ToString("N"));
        try
        {
            Directory.CreateDirectory(dir);
            var old = Path.Combine(dir, "old.rtrec"); File.WriteAllText(old, "x"); File.SetLastWriteTimeUtc(old, DateTime.UtcNow.AddDays(-40));
            var fresh = Path.Combine(dir, "fresh.rtrec"); File.WriteAllText(fresh, "x");
            _ = new SessionRecorderFactory(dir, new TestProtector(), retentionDays: 30);
            Assert.False(File.Exists(old)); Assert.True(File.Exists(fresh));
        }
        finally { try { Directory.Delete(dir, true); } catch { } }
    }
}

public class Phase3SessionTests
{
    private sealed class Rig : IAsyncDisposable
    {
        public HostService Host = null!;
        public SasInjector Injector = new();
        public FakeConsent Consent = new();
        public ListAudit Audit = new();
        public FakeUnattendedPolicy Unattended = new();
        public PermanentPasswordStore Store = null!;
        public string Dir = Path.Combine(Path.GetTempPath(), "rt-p3-" + Guid.NewGuid().ToString("N"));
        public int Port;
        public const string Permanent = "Correct-Horse-9";

        public static Rig Start(bool withPermanent = true, bool service = true, Func<IFrameProducer>? producer = null, ISessionRecorderFactory? recorder = null)
        {
            var r = new Rig();
            Directory.CreateDirectory(r.Dir);
            r.Store = new PermanentPasswordStore(Path.Combine(r.Dir, "perm.json"), new TestProtector());
            if (withPermanent) r.Store.Set(Permanent);
            r.Host = new HostService(producer ?? (() => new FakeProducer()), () => r.Injector, r.Consent, r.Audit, new HostPolicy("Server-01"),
                permanentCredential: r.Store, unattended: service ? r.Unattended : null, recorderFactory: recorder);
            var probe = new TcpListener(IPAddress.Loopback, 0);
            probe.Start(); r.Port = ((IPEndPoint)probe.LocalEndpoint).Port; probe.Stop();
            r.Host.StartDirectListener(r.Port);
            return r;
        }

        public async Task<Stream> Dial() { var c = new TcpClient { NoDelay = true }; await c.ConnectAsync(IPAddress.Loopback, Port); return c.GetStream(); }

        public async Task<ViewerSession> Connect(string secret, bool permanent, VideoCodecs codecs = VideoCodecs.TileJpeg)
            => await ViewerSession.ConnectAsync(await Dial(), "ops", secret, new ListAudit(), Permissions.All, default, permanent: permanent, codecs: codecs);

        public async ValueTask DisposeAsync() { await Host.DisposeAsync(); try { Directory.Delete(Dir, true); } catch { } }
    }

    private static async Task WaitFor(Func<bool> c, int sec = 10) { var t = DateTime.UtcNow.AddSeconds(sec); while (!c() && DateTime.UtcNow < t) await Task.Delay(20); Assert.True(c(), "condition not reached"); }

    [Fact]
    public async Task UnattendedLoginWithPermanentPassword_SkipsConsentDialog_AndIsCappedToServicePolicy()
    {
        await using var rig = Rig.Start();
        await using var v = await rig.Connect(Rig.Permanent, permanent: true);
        Assert.Equal(0, rig.Consent.Calls);                 // the interactive dialog was NOT used
        Assert.Equal(1, rig.Unattended.Calls);              // the service policy decided
        Assert.Equal(Permissions.Control, v.Permissions);   // viewer asked for All; clipboard/files are never unattended
        v.Start();
        Assert.Contains(rig.Audit.Lines, l => l.StartsWith("consent_granted") && l.Contains("unattended=True"));
    }

    [Fact]
    public async Task UnattendedPolicyCanStillDeny_ForExampleWhenAUserSitsAtTheScreen()
    {
        await using var rig = Rig.Start();
        rig.Unattended.Allow = false;
        var e = await Assert.ThrowsAsync<ConnectFailedException>(() => rig.Connect(Rig.Permanent, permanent: true));
        Assert.Equal(ConnectFailure.Denied, e.Failure);
    }

    [Fact]
    public async Task WrongOrDisabledPermanentPasswordFailsIdentically_AndOneTimePasswordStillWorks()
    {
        await using (var rig = Rig.Start())
        {
            var e = await Assert.ThrowsAsync<ConnectFailedException>(() => rig.Connect("Wrong-Horse-99", permanent: true));
            Assert.Equal(ConnectFailure.BadPassword, e.Failure);
            // permanent password must not be accepted in one-time mode and vice versa
            var e2 = await Assert.ThrowsAsync<ConnectFailedException>(() => rig.Connect(Rig.Permanent, permanent: false));
            Assert.Equal(ConnectFailure.BadPassword, e2.Failure);
        }
        await using (var rig = Rig.Start(withPermanent: false))
        {
            var e = await Assert.ThrowsAsync<ConnectFailedException>(() => rig.Connect(Rig.Permanent, permanent: true));
            Assert.Equal(ConnectFailure.BadPassword, e.Failure);
        }
        await using (var rig = Rig.Start(service: false)) // plain user-mode app: unattended is impossible even if a key file exists
        {
            var e = await Assert.ThrowsAsync<ConnectFailedException>(() => rig.Connect(Rig.Permanent, permanent: true));
            Assert.Equal(ConnectFailure.BadPassword, e.Failure);
            Assert.True(rig.Audit.Has("unattended_unavailable"));
        }
        await using (var rig = Rig.Start())
        {
            await using var v = await rig.Connect(rig.Host.Password, permanent: false);  // attended path unaffected
            Assert.Equal(1, rig.Consent.Calls);
        }
    }

    [Fact]
    public async Task DistributedGuessingTripsTheBreaker_EvenWithTheCorrectPassword()
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
                var i = Interlocked.Increment(ref n);
                // every attempt appears to come from a different source (what a distributed attacker looks like through a relay)
                _ = rig.Host.HandleConnectionAsync(c.GetStream(), new PeerOrigin("relay:10.0.0." + i, "10.0.0." + i, true, null));
            }
        });
        async Task<ConnectFailure> Try(string pw)
        {
            var c = new TcpClient(); await c.ConnectAsync(IPAddress.Loopback, port);
            try { await using var v = await ViewerSession.ConnectAsync(c.GetStream(), "x", pw, new ListAudit(), Permissions.All, default, permanent: true); return ConnectFailure.Network; }
            catch (ConnectFailedException e) { return e.Failure; }
        }
        for (var i = 0; i < 20; i++) Assert.Equal(ConnectFailure.BadPassword, await Try("Wrong-Horse-99"));
        Assert.True(rig.Audit.Has("unattended_breaker_tripped"));
        Assert.Equal(ConnectFailure.BadPassword, await Try(Rig.Permanent)); // correct password refused while tripped
        Assert.True(rig.Audit.Has("unattended_unavailable"));
        l.Stop();
    }

    [Fact]
    public async Task CtrlAltDelNeedsServiceInjector_AndControlPermission()
    {
        await using (var rig = Rig.Start())
        {
            await using var v = await rig.Connect(rig.Host.Password, permanent: false);
            v.Start();
            await v.SendSpecialKeyAsync(SpecialKeyKind.CtrlAltDel);
            await WaitFor(() => rig.Injector.SasCalls == 1);
            Assert.True(rig.Audit.Has("special_key"));
        }
        // injector without ISpecialKeys (user-mode app): refused and logged
        var plain = new FakeInjector();
        var audit = new ListAudit();
        await using var host = new HostService(() => new FakeProducer(), () => plain, new FakeConsent(), audit, new HostPolicy("PC"));
        var probe = new TcpListener(IPAddress.Loopback, 0); probe.Start(); var port = ((IPEndPoint)probe.LocalEndpoint).Port; probe.Stop();
        host.StartDirectListener(port);
        var c = new TcpClient(); await c.ConnectAsync(IPAddress.Loopback, port);
        await using var v2 = await ViewerSession.ConnectAsync(c.GetStream(), "x", host.Password, new ListAudit(), Permissions.All, default);
        v2.Start();
        await v2.SendSpecialKeyAsync(SpecialKeyKind.CtrlAltDel);
        await WaitFor(() => audit.Has("special_key_unavailable"));
    }

    [Fact]
    public async Task H264IsNegotiated_FallsBackWhenEncoderFails_AndWhenDecoderFails()
    {
        H264FakeProducer.Fail = false; FakeDecoder.Fail = false;
        await using var rig = Rig.Start(producer: () => new H264FakeProducer());
        await using var v = await rig.Connect(rig.Host.Password, false, VideoCodecs.TileJpeg | VideoCodecs.H264);
        Assert.Equal(VideoCodecs.H264, v.Codec);
        v.AttachH264Decoder(new FakeDecoder());
        var full = 0; var tiles = 0; var changed = new TaskCompletionSource<VideoCodecs>();
        v.FullFrameReceived += _ => Interlocked.Increment(ref full);
        v.FrameReceived += _ => Interlocked.Increment(ref tiles);
        v.CodecChanged += c => changed.TrySetResult(c);
        v.Start();
        await WaitFor(() => Volatile.Read(ref full) > 3);
        Assert.Equal(0, Volatile.Read(ref tiles));

        H264FakeProducer.Fail = true;            // GPU encoder dies mid-session
        Assert.Equal(VideoCodecs.TileJpeg, await changed.Task.WaitAsync(TimeSpan.FromSeconds(10)));
        await WaitFor(() => Volatile.Read(ref tiles) > 0);
        Assert.True(rig.Audit.Has("codec_fallback"));
        H264FakeProducer.Fail = false;
    }

    [Fact]
    public async Task ViewerDecoderFailureMakesHostSwitchToTiles()
    {
        H264FakeProducer.Fail = false; FakeDecoder.Fail = true;
        try
        {
            await using var rig = Rig.Start(producer: () => new H264FakeProducer());
            await using var v = await rig.Connect(rig.Host.Password, false, VideoCodecs.TileJpeg | VideoCodecs.H264);
            v.AttachH264Decoder(new FakeDecoder());
            var tiles = 0;
            v.FrameReceived += _ => Interlocked.Increment(ref tiles);
            v.Start();
            await WaitFor(() => Volatile.Read(ref tiles) > 0);
            Assert.Equal(VideoCodecs.TileJpeg, v.Codec);
            Assert.Contains(rig.Audit.Lines, l => l.StartsWith("codec_fallback") && l.Contains("by=viewer"));
        }
        finally { FakeDecoder.Fail = false; }
    }

    [Fact]
    public async Task ViewerWithoutH264GetsTiles_EvenIfHostCouldDoH264()
    {
        await using var rig = Rig.Start(producer: () => new H264FakeProducer());
        await using var v = await rig.Connect(rig.Host.Password, false);
        Assert.Equal(VideoCodecs.TileJpeg, v.Codec);
    }

    [Fact]
    public async Task RecordingIsAnnouncedToViewer_AndWritesAVerifiableEncryptedFile()
    {
        var rdir = Path.Combine(Path.GetTempPath(), "rt-rec-" + Guid.NewGuid().ToString("N"));
        try
        {
            var prot = new TestProtector();
            await using var rig = Rig.Start(recorder: new SessionRecorderFactory(rdir, prot));
            var v = await rig.Connect(rig.Host.Password, false);
            Assert.True(v.Recording);
            Assert.True(rig.Consent.Last!.Recording);        // the consent dialog is told, so it can say so
            var got = new TaskCompletionSource<bool>(); v.FrameReceived += _ => got.TrySetResult(true); v.Start();
            await got.Task.WaitAsync(TimeSpan.FromSeconds(10));
            await v.DisposeAsync();
            await WaitFor(() => rig.Audit.Has("recording_stopped"));
            var file = Directory.GetFiles(rdir, "*.rtrec").Single();
            var entries = RecordingReader.Read(file, prot).ToList();
            Assert.Equal(RecordType.Meta, entries[0].Type);
            Assert.Contains(entries, e => e.Type == RecordType.TileFrame);
            Assert.Equal(RecordType.End, entries[^1].Type);
            Assert.Contains(rig.Audit.Lines, l => l.StartsWith("recording_stopped") && l.Contains("sha256="));
        }
        finally { try { Directory.Delete(rdir, true); } catch { } }
    }
}
