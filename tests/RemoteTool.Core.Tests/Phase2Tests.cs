using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using RemoteTool.Core.Config;
using RemoteTool.Core.Protocol;
using RemoteTool.Core.Session;

namespace RemoteTool.Core.Tests;

public class FileNameSanitizerTests
{
    [Theory]
    [InlineData("..\\..\\Windows\\evil.exe", "evil.exe")]
    [InlineData("../../etc/passwd", "passwd")]
    [InlineData("C:\\temp\\a.txt", "a.txt")]
    [InlineData("report.txt:hidden.exe", "report.txt_hidden.exe")]
    [InlineData("NUL", "_NUL")]
    [InlineData("con.txt", "_con.txt")]
    [InlineData("..", "file")]
    [InlineData("   ", "file")]
    [InlineData("name. . ", "name")]
    [InlineData("a\u202Etxt.exe", "atxt.exe")] // right-to-left override removed
    [InlineData("bad<>|?*name.txt", "bad_____name.txt")]
    public void NamesAreReducedToSafeSingleComponent(string input, string expected) => Assert.Equal(expected, FileNameSanitizer.Sanitize(input));

    [Fact]
    public void LongNamesKeepExtension()
    {
        var n = FileNameSanitizer.Sanitize(new string('a', 500) + ".pdf");
        Assert.True(n.Length <= 120);
        Assert.EndsWith(".pdf", n);
    }

    [Fact]
    public void UniquePathNeverOverwritesAndStaysInside()
    {
        var dir = Path.Combine(Path.GetTempPath(), "rt-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var p1 = FileNameSanitizer.UniquePath(dir, "a.txt");
            File.WriteAllText(p1, "x");
            var p2 = FileNameSanitizer.UniquePath(dir, "a.txt");
            Assert.NotEqual(p1, p2);
            Assert.StartsWith(Path.GetFullPath(dir), p2);
        }
        finally { Directory.Delete(dir, true); }
    }
}

public class AdaptiveQualityTests
{
    [Fact]
    public void SlowLinkLowersQualityThenFrameRate_FastLinkRecoversFrameRateThenQuality()
    {
        var a = new AdaptiveQuality(25);
        var baseInterval = a.Interval;
        for (var i = 0; i < 10; i++) a.Report(TimeSpan.FromSeconds(1));
        Assert.Equal(AdaptiveQuality.MinQuality, a.Quality);
        Assert.True(a.Interval > baseInterval);
        Assert.True(a.Interval <= TimeSpan.FromMilliseconds(200));
        for (var i = 0; i < 200; i++) a.Report(TimeSpan.Zero);
        Assert.Equal(baseInterval, a.Interval);
        Assert.Equal(AdaptiveQuality.MaxQuality, a.Quality);
    }
}

public class ClipboardSyncTests
{
    private static async Task WaitFor(Func<bool> c) { var t = DateTime.UtcNow.AddSeconds(5); while (!c() && DateTime.UtcNow < t) await Task.Delay(10); Assert.True(c()); }

    [Fact]
    public async Task TextSyncsBothWaysWithoutEchoLoops()
    {
        var ca = new FakeClipboard(); var cb = new FakeClipboard();
        ClipboardSync? a = null, b = null;
        var sentByB = 0;
        a = new ClipboardSync(ca, p => { b!.Receive(p); return Task.CompletedTask; }, RemoteTool.Core.Audit.NullAuditLog.Instance);
        b = new ClipboardSync(cb, p => { Interlocked.Increment(ref sentByB); a!.Receive(p); return Task.CompletedTask; }, RemoteTool.Core.Audit.NullAuditLog.Instance);
        a.Start(); b.Start();
        ca.UserCopies("hello\r\nwörld");
        await WaitFor(() => cb.GetText() == "hello\r\nwörld");
        await Task.Delay(200);
        Assert.Equal(0, sentByB); // B setting its clipboard must not bounce the text back
        cb.UserCopies("reply");
        await WaitFor(() => ca.GetText() == "reply");
    }

    [Fact]
    public void OversizedClipboardIsRejectedByParser()
    {
        var big = new ProtoWriter().U8(0).Bytes(new byte[ProtocolConstants.MaxClipboardBytes + 1]).ToArray();
        Assert.Throws<ProtocolException>(() => ClipboardDataMessage.Parse(big));
    }
}

public class FileTransferUnitTests
{
    private sealed class Env : IDisposable
    {
        public string Dir = Path.Combine(Path.GetTempPath(), "rt-" + Guid.NewGuid().ToString("N"));
        public MemoryStream Out = new();
        public ListAudit Audit = new();
        public AutoPrompt Prompt = new();
        public FileTransferService Svc;
        public Env(long max = 1L << 30) { Svc = new FileTransferService(new FrameWriter(Out), Prompt, new FileTransferOptions(Dir, max), Audit, "peer"); }
        public List<FileAckMessage> Acks()
        {
            var r = new FrameReader(new MemoryStream(Out.ToArray()), MessageTypes.IsKnownPeer, 1 << 20);
            var l = new List<FileAckMessage>();
            try { while (true) l.Add(FileAckMessage.Parse(r.ReadAsync(default).AsTask().Result.Payload)); } catch (Exception) { }
            return l;
        }
        public void Dispose() { Svc.Dispose(); try { Directory.Delete(Dir, true); } catch { } }
    }

    private static Frame Offer(uint id, string name, byte[] data, byte[]? hash = null)
        => new((byte)MessageType.FileOffer, new FileOfferMessage(id, name, (ulong)data.Length, hash ?? SHA256.HashData(data)).Serialize());
    private static Frame Chunk(uint id, ulong off, byte[] d) => new((byte)MessageType.FileChunk, new FileChunkMessage(id, off, d).Serialize());

    [Fact]
    public async Task CorruptedDataIsDetectedAndNothingIsKept()
    {
        using var e = new Env();
        var data = RandomNumberGenerator.GetBytes(5000);
        var tampered = (byte[])data.Clone(); tampered[10] ^= 0xFF;
        await e.Svc.HandleAsync(Offer(1, "doc.bin", data), default);
        await e.Svc.PendingOffer;
        await e.Svc.HandleAsync(Chunk(1, 0, tampered), default);
        Assert.Equal(FileStatus.HashMismatch, e.Acks().Last().Status);
        Assert.Empty(Directory.GetFiles(e.Dir)); // neither final file nor .part
    }

    [Fact]
    public async Task TraversalNameIsConfinedToReceiveFolder()
    {
        using var e = new Env();
        var data = new byte[] { 1, 2, 3 };
        await e.Svc.HandleAsync(Offer(1, "..\\..\\..\\evil.dll", data), default);
        await e.Svc.PendingOffer;
        await e.Svc.HandleAsync(Chunk(1, 0, data), default);
        var f = Assert.Single(Directory.GetFiles(e.Dir));
        Assert.Equal("evil.dll", Path.GetFileName(f));
        Assert.Equal("evil.dll", e.Prompt.Seen.Single().FileName);
    }

    [Fact]
    public async Task OutOfOrderChunkAbortsAndRemovesPartFile()
    {
        using var e = new Env();
        var data = new byte[200];
        await e.Svc.HandleAsync(Offer(1, "a.bin", data), default);
        await e.Svc.PendingOffer;
        await e.Svc.HandleAsync(Chunk(1, 0, new byte[50]), default);
        await e.Svc.HandleAsync(Chunk(1, 999, new byte[50]), default);
        Assert.Equal(FileStatus.Error, e.Acks().Last().Status);
        Assert.Empty(Directory.GetFiles(e.Dir));
    }

    [Fact]
    public async Task DisconnectMidTransferRemovesPartFile()
    {
        var e = new Env();
        var data = new byte[1000];
        await e.Svc.HandleAsync(Offer(1, "big.bin", data), default);
        await e.Svc.PendingOffer;
        await e.Svc.HandleAsync(Chunk(1, 0, new byte[100]), default);
        Assert.Single(Directory.GetFiles(e.Dir, "*.part"));
        e.Dispose();
        Assert.False(Directory.Exists(e.Dir) && Directory.GetFiles(e.Dir).Length > 0);
    }

    [Fact]
    public async Task OversizedOfferAndRefusedOfferAreNotStored()
    {
        using var e = new Env(max: 100);
        await e.Svc.HandleAsync(Offer(1, "huge.bin", new byte[500]), default);
        await e.Svc.PendingOffer;
        Assert.Equal(FileStatus.Error, e.Acks().Last().Status);
        Assert.Empty(e.Prompt.Seen); // user is not even asked
        e.Prompt.Answer = false;
        await e.Svc.HandleAsync(Offer(2, "ok.bin", new byte[50]), default);
        await e.Svc.PendingOffer;
        Assert.Equal(FileStatus.Reject, e.Acks().Last().Status);
        Assert.False(Directory.Exists(e.Dir) && Directory.GetFiles(e.Dir).Any());
    }
}

public class Phase2SessionTests
{
    private sealed class Rig : IAsyncDisposable
    {
        public HostService Host = null!;
        public FakeInjector Injector = new();
        public FakeConsent Consent = new();
        public ListAudit HostAudit = new();
        public AutoPrompt HostPrompt = new();
        public FakeClipboard HostClipboard = new();
        public string HostDir = Path.Combine(Path.GetTempPath(), "rt-h-" + Guid.NewGuid().ToString("N"));
        public string ViewerDir = Path.Combine(Path.GetTempPath(), "rt-v-" + Guid.NewGuid().ToString("N"));
        public int Port;

        public static Rig Start(HostPolicy? policy = null, TimeProvider? time = null)
        {
            var r = new Rig();
            r.Host = new HostService(() => new FakeProducer(), () => r.Injector, r.Consent, r.HostAudit, policy ?? new HostPolicy("Test-PC"),
                clipboardFactory: () => r.HostClipboard, filePrompt: r.HostPrompt, receiveDirectory: r.HostDir, time: time);
            var probe = new TcpListener(IPAddress.Loopback, 0);
            probe.Start();
            r.Port = ((IPEndPoint)probe.LocalEndpoint).Port;
            probe.Stop();
            r.Host.StartDirectListener(r.Port);
            return r;
        }

        public Func<CancellationToken, Task<Stream>> Dialer(int? port = null) => async ct =>
        {
            var c = new TcpClient { NoDelay = true };
            await c.ConnectAsync(IPAddress.Loopback, port ?? Port, ct);
            return c.GetStream();
        };

        public async Task<ViewerSession> Connect(AutoPrompt? vp = null, FakeClipboard? vc = null, int? port = null, bool start = true)
        {
            var v = await ViewerSession.ConnectAsync(await Dialer(port)(default), "alice", Host.Password, new ListAudit(), Permissions.All, default);
            if (vp is not null) v.AttachFileTransfer(vp, new FileTransferOptions(ViewerDir));
            if (vc is not null) v.AttachClipboard(vc);
            if (start) v.Start();
            return v;
        }

        public async ValueTask DisposeAsync()
        {
            await Host.DisposeAsync();
            foreach (var d in new[] { HostDir, ViewerDir }) try { Directory.Delete(d, true); } catch { }
        }
    }

    private static async Task WaitFor(Func<bool> c, int sec = 10) { var t = DateTime.UtcNow.AddSeconds(sec); while (!c() && DateTime.UtcNow < t) await Task.Delay(20); Assert.True(c(), "condition not reached"); }

    private static string TempFile(int size, out byte[] hash)
    {
        var p = Path.Combine(Path.GetTempPath(), "rt-src-" + Guid.NewGuid().ToString("N") + ".bin");
        var data = RandomNumberGenerator.GetBytes(size);
        File.WriteAllBytes(p, data);
        hash = SHA256.HashData(data);
        return p;
    }

    [Fact]
    public async Task FileViewerToHost_ArrivesWithMatchingSha256()
    {
        await using var rig = Rig.Start();
        await using var v = await rig.Connect(new AutoPrompt());
        var src = TempFile(1_500_000, out var hash); // > 20 chunks
        try
        {
            var progress = 0L;
            var outcome = await v.SendFileAsync(src, new Progress<long>(p => { lock (this) progress = Math.Max(progress, p); })); // callbacks may arrive out of order
            Assert.Equal(FileSendOutcome.Completed, outcome);
            var saved = Directory.GetFiles(rig.HostDir).Single();
            Assert.Equal(hash, SHA256.HashData(File.ReadAllBytes(saved)));
            Assert.Empty(Directory.GetFiles(rig.HostDir, "*.part"));
            Assert.True(rig.HostAudit.Has("file_received"));
            await WaitFor(() => { lock (this) return progress == 1_500_000; });
        }
        finally { File.Delete(src); }
    }

    [Fact]
    public async Task FileHostToViewer_ArrivesWithMatchingSha256()
    {
        await using var rig = Rig.Start();
        await using var v = await rig.Connect(new AutoPrompt());
        var src = TempFile(300_000, out var hash);
        try
        {
            Assert.Equal(FileSendOutcome.Completed, await rig.Host.SendFileAsync(src));
            Assert.Equal(hash, SHA256.HashData(File.ReadAllBytes(Directory.GetFiles(rig.ViewerDir).Single())));
        }
        finally { File.Delete(src); }
    }

    [Fact]
    public async Task HostUserCanRefuseAFile_AndEmptyFilesWork()
    {
        await using var rig = Rig.Start();
        await using var v = await rig.Connect(new AutoPrompt());
        rig.HostPrompt.Answer = false;
        var src = TempFile(1000, out _);
        Assert.Equal(FileSendOutcome.Rejected, await v.SendFileAsync(src));
        Assert.False(Directory.Exists(rig.HostDir) && Directory.GetFiles(rig.HostDir).Any());
        rig.HostPrompt.Answer = true;
        var empty = Path.Combine(Path.GetTempPath(), "rt-empty-" + Guid.NewGuid().ToString("N"));
        File.WriteAllBytes(empty, Array.Empty<byte>());
        Assert.Equal(FileSendOutcome.Completed, await v.SendFileAsync(empty));
        Assert.Equal(0, new FileInfo(Directory.GetFiles(rig.HostDir).Single()).Length);
        File.Delete(src); File.Delete(empty);
    }

    [Fact]
    public async Task FileTransferDisabledByPolicyIsRefused()
    {
        await using var rig = Rig.Start(new HostPolicy("Test-PC", AllowFileTransfer: false));
        await using var v = await rig.Connect(new AutoPrompt());
        Assert.False(v.CanTransferFiles); // permission not granted => feature not even attached
        Assert.Equal(Permissions.None, v.Permissions & Permissions.FileTransfer);
    }

    [Fact]
    public async Task ClipboardSyncsViewerToHostAndBack_AndIsOffWhenPolicyForbids()
    {
        await using (var rig = Rig.Start())
        {
            var vc = new FakeClipboard();
            await using var v = await rig.Connect(vc: vc);
            vc.UserCopies("from viewer");
            await WaitFor(() => rig.HostClipboard.GetText() == "from viewer");
            rig.HostClipboard.UserCopies("from host");
            await WaitFor(() => vc.GetText() == "from host");
            Assert.True(rig.HostAudit.Has("clipboard_received"));
            Assert.DoesNotContain(rig.HostAudit.Lines, l => l.Contains("from viewer"));
        }
        await using (var rig = Rig.Start(new HostPolicy("Test-PC", AllowClipboard: false)))
        {
            var vc = new FakeClipboard();
            await using var v = await rig.Connect(vc: vc);
            vc.UserCopies("secret");
            await Task.Delay(300);
            Assert.Null(rig.HostClipboard.GetText());
        }
    }

    [Fact]
    public async Task ViewerCanSwitchMonitor_FramesAndSizeFollow()
    {
        await using var rig = Rig.Start();
        await using var v = await rig.Connect(start: false);
        var frames = new System.Collections.Concurrent.ConcurrentQueue<FrameUpdateMessage>();
        v.FrameReceived += f => frames.Enqueue(f);
        v.Start();
        await WaitFor(() => frames.Any(f => f.MonitorIndex == 0));
        Assert.Equal(2, v.Screen!.Monitors.Count);
        await v.SelectMonitorAsync(1);
        await WaitFor(() => frames.Any(f => f.MonitorIndex == 1 && f.Keyframe && f.Width == 32 && f.Height == 48));
        Assert.Equal(1, v.ActiveMonitor);
    }

    [Fact]
    public async Task SessionResumesAfterNetworkDrop_WithoutNewPasswordOrConsent_AndTicketIsSingleUse()
    {
        await using var rig = Rig.Start();
        using var proxy = new SeverableProxy(rig.Port);
        var v1 = await rig.Connect(port: proxy.Port);
        var token1 = v1.ResumeToken;
        Assert.Equal(48, token1.Length);
        var ended = new TaskCompletionSource<ByeReason>();
        v1.Ended += (r, _) => ended.TrySetResult(r);
        Assert.Equal(1, rig.Consent.Calls);

        proxy.SeverAll(); // network drop
        Assert.True(ViewerReconnect.IsRecoverable(await ended.Task.WaitAsync(TimeSpan.FromSeconds(10))));

        await using var v2 = await ViewerReconnect.ResumeAsync(rig.Dialer(proxy.Port), "alice", token1, new ListAudit(), Permissions.All, default, firstDelay: TimeSpan.FromMilliseconds(50));
        var got = new TaskCompletionSource<bool>();
        v2.FrameReceived += _ => got.TrySetResult(true);
        v2.Start();
        Assert.True(await got.Task.WaitAsync(TimeSpan.FromSeconds(10)));
        Assert.Equal(1, rig.Consent.Calls);              // no second consent dialog
        Assert.NotEqual(token1, v2.ResumeToken);         // ticket rotated
        Assert.True(rig.HostAudit.Has("session_resumed"));

        // the old ticket is dead
        var e = await Assert.ThrowsAsync<ConnectFailedException>(async () =>
            await ViewerSession.ConnectAsync(await rig.Dialer()(default), "alice", token1, new ListAudit(), Permissions.All, default, resume: true));
        Assert.Equal(ConnectFailure.BadPassword, e.Failure);

        // a deliberate disconnect invalidates the ticket
        var token2 = v2.ResumeToken;
        await v2.DisposeAsync();
        await WaitFor(() => rig.Host.ActiveSession is null);
        var e2 = await Assert.ThrowsAsync<ConnectFailedException>(async () =>
            await ViewerSession.ConnectAsync(await rig.Dialer()(default), "alice", token2, new ListAudit(), Permissions.All, default, resume: true));
        Assert.Equal(ConnectFailure.BadPassword, e2.Failure);
        await v1.DisposeAsync();
    }

    private sealed class FakeTime : TimeProvider
    {
        public DateTimeOffset Now = DateTimeOffset.UtcNow;
        public override DateTimeOffset GetUtcNow() => Now;
    }

    [Fact]
    public async Task ResumeTicketExpiresAfterTwoMinutes()
    {
        var time = new FakeTime();
        await using var rig = Rig.Start(time: time);
        using var proxy = new SeverableProxy(rig.Port);
        var v1 = await rig.Connect(port: proxy.Port);
        var ended = new TaskCompletionSource<ByeReason>();
        v1.Ended += (r, _) => ended.TrySetResult(r);
        var token = v1.ResumeToken;
        proxy.SeverAll();
        await ended.Task.WaitAsync(TimeSpan.FromSeconds(10));
        await WaitFor(() => rig.Host.ActiveSession is null);
        time.Now += TimeSpan.FromMinutes(3);
        var e = await Assert.ThrowsAsync<ConnectFailedException>(async () =>
            await ViewerSession.ConnectAsync(await rig.Dialer()(default), "alice", token, new ListAudit(), Permissions.All, default, resume: true));
        Assert.Equal(ConnectFailure.BadPassword, e.Failure);
    }

    [Fact]
    public Task AddressBookStoresNicknamesButNoSecrets()
    {
        var dir = Path.Combine(Path.GetTempPath(), "rt-" + Guid.NewGuid().ToString("N"));
        try
        {
            var f = Path.Combine(dir, "settings.json");
            var s = new SettingsStore(f); s.Load();
            s.UpsertAddress("482 913 756", "Reception PC");
            s.UpsertAddress("10.0.0.5:21118", "Lab");
            s.UpsertAddress("482 913 756", "Front desk");
            Assert.Equal(2, s.Current.AddressBook.Count);
            var reloaded = new SettingsStore(f); reloaded.Load();
            Assert.Contains(reloaded.Current.AddressBook, a => a.Nickname == "Front desk");
            Assert.DoesNotContain("password", File.ReadAllText(f), StringComparison.OrdinalIgnoreCase);
            Assert.True(s.RemoveAddress("10.0.0.5:21118"));
            Assert.Single(s.Current.AddressBook);
            return Task.CompletedTask;
        }
        finally { try { Directory.Delete(dir, true); } catch { } }
    }
}
