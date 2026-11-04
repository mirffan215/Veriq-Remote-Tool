using RemoteTool.Capture;
using RemoteTool.Core.Config;
using RemoteTool.Core.Protocol;
using RemoteTool.Core.Recording;
using RemoteTool.Core.Session;
using RemoteTool.Video;

namespace RemoteTool.Capture.Tests;

public class ColorConvertTests
{
    [Fact]
    public void BgraToNv12AndBack_StaysCloseForSmoothContent()
    {
        const int w = 64, h = 48;
        var src = new byte[w * h * 4];
        for (var y = 0; y < h; y++) for (var x = 0; x < w; x++) { var p = (y * w + x) * 4; src[p] = (byte)(x * 3); src[p + 1] = (byte)(y * 4); src[p + 2] = (byte)(100 + x + y); src[p + 3] = 255; }
        var nv12 = new byte[ColorConvert.Nv12Size(w, h)];
        ColorConvert.BgraToNv12(src, w * 4, w, h, nv12);
        var back = ColorConvert.Nv12ToBgra(nv12, w, w * h, w, h);
        double err = 0;
        for (var i = 0; i < src.Length; i += 4) err += Math.Abs(src[i] - back[i]) + Math.Abs(src[i + 1] - back[i + 1]) + Math.Abs(src[i + 2] - back[i + 2]);
        Assert.True(err / (w * h * 3) < 6, $"mean error {err / (w * h * 3):F2}");
    }

    [Fact]
    public void KnownColoursMapToBt601Limited()
    {
        var black = new byte[2 * 2 * 4]; for (var i = 3; i < black.Length; i += 4) black[i] = 255;
        var nv = new byte[ColorConvert.Nv12Size(2, 2)];
        ColorConvert.BgraToNv12(black, 8, 2, 2, nv);
        Assert.Equal(16, nv[0]);                 // Y of black
        Assert.Equal(128, nv[4]);                // U/V of neutral
        var white = Enumerable.Repeat((byte)255, 16).ToArray();
        ColorConvert.BgraToNv12(white, 8, 2, 2, nv);
        Assert.InRange(nv[0], 234, 236);
    }

    [Fact]
    public void RejectsOddSizesAndShortBuffers()
    {
        Assert.Throws<ArgumentException>(() => ColorConvert.BgraToNv12(new byte[100], 12, 3, 3, new byte[100]));
        Assert.Throws<ArgumentException>(() => ColorConvert.Nv12ToBgra(new byte[10], 4, 8, 4, 4));
    }

    [Fact]
    public void AnnexBNalScanning()
    {
        var sps = new byte[] { 0, 0, 0, 1, 0x67, 1, 2 }; var pps = new byte[] { 0, 0, 0, 1, 0x68, 3 }; var idr = new byte[] { 0, 0, 1, 0x65, 9, 9 };
        var all = sps.Concat(pps).Concat(idr).ToArray();
        Assert.Equal(new[] { 7, 8, 5 }, AnnexB.NalTypes(all));
        Assert.True(AnnexB.HasParameterSets(all)); Assert.True(AnnexB.IsKeyframe(all));
        Assert.False(AnnexB.IsKeyframe(new byte[] { 0, 0, 0, 1, 0x41, 1 }));
    }
}

public class H264FrameProducerTests
{
    private sealed class FakeGrabber : IScreenGrabber
    {
        public int W = 100, H = 60;
        public byte[] Pixels = new byte[100 * 60 * 4];
        public IReadOnlyList<MonitorInfo> GetMonitors() => new[] { new MonitorInfo(0, 0, 0, W, H, true, "m") };
        public bool TryGrab(MonitorInfo m, out ReadOnlySpan<byte> bgra, out int stride) { bgra = Pixels; stride = W * 4; return true; }
        public CursorShape GetCursorShape() => CursorShape.Arrow;
        public void Dispose() { }
    }

    private sealed class FakeEncoder : IH264Encoder
    {
        public int Frames; public bool? LastForce; public int LastLen; public bool Throw;
        public string Name => "fake"; public bool IsHardware => false;
        public void SetBitrate(int kbps) { }
        public byte[]? Encode(ReadOnlySpan<byte> nv12, bool force)
        {
            if (Throw) throw new CodecUnavailableException("boom");
            Frames++; LastForce = force; LastLen = nv12.Length;
            return force ? new byte[] { 0, 0, 0, 1, 0x67, 1, 0, 0, 0, 1, 0x68, 1, 0, 0, 0, 1, 0x65, 1 } : new byte[] { 0, 0, 0, 1, 0x41, 1 };
        }
        public void Dispose() { }
    }

    [Fact]
    public void EncodesOnlyChangedFrames_FirstIsKeyframe_NV12SizeIsRight()
    {
        var g = new FakeGrabber(); FakeEncoder? enc = null;
        using var p = new H264FrameProducer(g, (int w, int h, int fps, int kbps, out string? err) => { err = null; return enc = new FakeEncoder(); });
        Assert.True(p.H264Available);
        var f1 = p.NextH264(0, false, 2000)!;
        Assert.True(f1.Keyframe); Assert.Equal(100, f1.Width);
        Assert.Equal(100 * 60 * 3 / 2, enc!.LastLen);
        Assert.Null(p.NextH264(0, false, 2000));            // nothing changed => nothing sent, no encoder work
        Assert.Equal(1, enc.Frames);
        g.Pixels[4000] = 255;
        var f2 = p.NextH264(0, false, 2000)!;
        Assert.False(f2.Keyframe);
        var f3 = p.NextH264(0, true, 2000)!;                // viewer asked for a keyframe
        Assert.True(f3.Keyframe);
    }

    [Fact]
    public void SizeChangeRecreatesEncoder_AndMissingEncoderMeansCodecUnavailable()
    {
        var g = new FakeGrabber(); var created = 0;
        using (var p = new H264FrameProducer(g, (int w, int h, int fps, int kbps, out string? err) => { err = null; created++; return new FakeEncoder(); }))
        {
            p.NextH264(0, false, 1000);
            g.W = 80; g.H = 40; g.Pixels = new byte[80 * 40 * 4];
            p.GetMonitors();                                // a resolution change is picked up when the monitor list is refreshed
            p.NextH264(0, false, 1000);
            Assert.Equal(3, created);                       // probe + first size + new size
        }
        using var none = new H264FrameProducer(g, (int w, int h, int fps, int kbps, out string? err) => { err = "no encoder"; return null; });
        Assert.False(none.H264Available);
        Assert.Throws<CodecUnavailableException>(() => none.NextH264(0, true, 1000));
    }

    [Fact]
    public void EncoderFailurePropagatesAsCodecUnavailable()
    {
        var g = new FakeGrabber(); FakeEncoder? enc = null;
        using var p = new H264FrameProducer(g, (int w, int h, int fps, int kbps, out string? err) => { err = null; return enc = new FakeEncoder(); });
        p.NextH264(0, false, 1000);
        enc!.Throw = true; g.Pixels[10] = 9;
        Assert.Throws<CodecUnavailableException>(() => p.NextH264(0, false, 1000));
    }

    [Fact]
    public void NonWindowsHasNoMediaFoundationEncoder()
    {
        if (OperatingSystem.IsWindows()) return;
        Assert.Null(H264Support.CreateEncoder(1280, 720, 30, 2000, out var err));
        Assert.Contains("Windows", err);
    }
}

public class RecordingExportTests
{
    private sealed class P : ISecretProtector { public string Protect(string s) => "x" + s; public string Unprotect(string s) => s[1..]; }

    [Fact]
    public void ExportsFramesToPng_AndRawH264Stream()
    {
        var dir = Path.Combine(Path.GetTempPath(), "rt-exp-" + Guid.NewGuid().ToString("N"));
        try
        {
            const int w = 128, h = 64;
            var px = new byte[w * h * 4];
            for (var i = 0; i < px.Length; i += 4) { px[i] = 200; px[i + 1] = 50; px[i + 2] = 20; px[i + 3] = 255; }
            var jpeg = JpegCodec.Encode(px, w * 4, new PixelRect(0, 0, w, h), 90);
            var rec = new SessionRecorderFactory(Path.Combine(dir, "rec"), new P()).Create(new SessionInfo(Guid.NewGuid(), "alice", "src", Permissions.Control, DateTimeOffset.UtcNow), "HOST")!;
            rec.WriteFrame(new FrameUpdateMessage(0, 1, w, h, true, new[] { new TileRect(0, 0, w, h, jpeg) }));
            rec.WriteVideo(new VideoFrameMessage(0, 2, w, h, true, new byte[] { 0, 0, 0, 1, 0x65, 1, 2, 3 }));
            var done = rec.Complete("Normal")!.Value;

            var summary = RecordingExporter.Export(done.Path, new P(), Path.Combine(dir, "out"), TimeSpan.FromSeconds(1));
            Assert.Equal("alice", summary.Viewer);
            Assert.Equal("Normal", summary.Reason);
            Assert.Equal(8, summary.H264Bytes);
            Assert.True(File.Exists(Path.Combine(dir, "out", "final.png")));
            using var png = SkiaSharp.SKBitmap.Decode(Path.Combine(dir, "out", "final.png"));
            Assert.Equal((w, h), (png.Width, png.Height));
            var c = png.GetPixel(10, 10);
            Assert.InRange(c.Blue, 180, 220);   // JPEG-lossy, but clearly the recorded colour
        }
        finally { try { Directory.Delete(dir, true); } catch { } }
    }
}

public class LargeFrameDiffTests
{
    [Fact]
    public void ParallelHashingPathGivesTheSameAnswer()
    {
        const int w = 1920, h = 1080;
        var d = new TileDiffer();
        var f = new byte[w * h * 4];
        d.Diff(f, w, h, w * 4, false);
        Assert.Empty(d.Diff(f, w, h, w * 4, false));
        f[(1000 * w + 1900) * 4] = 7;                         // bottom-right area, partial edge tile
        var r = Assert.Single(d.Diff(f, w, h, w * 4, false));
        Assert.Equal(new PixelRect(1856, 960, 64, 64), r);
        f[0] = 1; f[(500 * w + 500) * 4] = 1;
        Assert.Equal(2, d.Diff(f, w, h, w * 4, false).Count);
    }
}
