using RemoteTool.Capture;
using RemoteTool.Core.Protocol;
using RemoteTool.Input;

namespace RemoteTool.Capture.Tests;

public class TileDifferTests
{
    private static byte[] Frame(int w, int h, byte fill = 40) { var b = new byte[w * h * 4]; Array.Fill(b, fill); return b; }
    private static void Paint(byte[] f, int w, PixelRect r, byte v)
    {
        for (var y = r.Y; y < r.Y + r.Height; y++) for (var x = r.X; x < r.X + r.Width; x++) f[(y * w + x) * 4] = v;
    }

    [Fact]
    public void FirstFrameIsFullScreen_ThenUnchangedIsEmpty()
    {
        var d = new TileDiffer();
        var f = Frame(200, 150);
        var first = d.Diff(f, 200, 150, 800, false);
        Assert.True(d.WasReset);
        Assert.Equal(200 * 150, first.Sum(r => r.Width * r.Height));
        Assert.Empty(d.Diff(f, 200, 150, 800, false));
    }

    [Fact]
    public void SingleChangedPixelProducesOneTileSizedRect()
    {
        var d = new TileDiffer();
        var f = Frame(640, 480);
        d.Diff(f, 640, 480, 2560, false);
        Paint(f, 640, new PixelRect(130, 70, 1, 1), 255);
        var rects = d.Diff(f, 640, 480, 2560, false);
        var r = Assert.Single(rects);
        Assert.Equal(new PixelRect(128, 64, 64, 64), r);
    }

    [Fact]
    public void AdjacentTilesAreMerged_EdgeTilesAreClipped()
    {
        var d = new TileDiffer();
        var f = Frame(300, 200);
        d.Diff(f, 300, 200, 1200, false);
        Paint(f, 300, new PixelRect(70, 10, 200, 100), 7); // spans 4 tile columns and 2 tile rows incl. right edge (300 not multiple of 64)
        var rects = d.Diff(f, 300, 200, 1200, false);
        var r = Assert.Single(rects);
        Assert.Equal(new PixelRect(64, 0, 236, 128), r);
    }

    [Fact]
    public void ResolutionChangeForcesFullFrame()
    {
        var d = new TileDiffer();
        d.Diff(Frame(100, 100), 100, 100, 400, false);
        var rects = d.Diff(Frame(120, 90), 120, 90, 480, false);
        Assert.True(d.WasReset);
        Assert.Equal(120 * 90, rects.Sum(r => r.Width * r.Height));
    }

    [Fact]
    public void RejectsBadGeometry() => Assert.Throws<ArgumentException>(() => new TileDiffer().Diff(new byte[10], 100, 100, 400, false));
}

public class EncoderTests
{
    [Fact]
    public void JpegRoundTripIsCloseToOriginal()
    {
        const int w = 96, h = 64;
        var px = new byte[w * h * 4];
        for (var y = 0; y < h; y++)
            for (var x = 0; x < w; x++) { var i = (y * w + x) * 4; px[i] = (byte)(x * 2); px[i + 1] = (byte)(y * 3); px[i + 2] = 128; px[i + 3] = 255; }
        var jpeg = JpegCodec.Encode(px, w * 4, new PixelRect(0, 0, w, h), 85);
        var back = JpegCodec.Decode(jpeg, out var bw, out var bh);
        Assert.Equal((w, h), (bw, bh));
        double err = 0;
        for (var i = 0; i < px.Length; i += 4) { err += Math.Abs(px[i] - back[i]) + Math.Abs(px[i + 1] - back[i + 1]) + Math.Abs(px[i + 2] - back[i + 2]); }
        Assert.True(err / (w * h * 3) < 6, $"mean error {err / (w * h * 3)}");
    }

    [Fact]
    public void DecodeRejectsGarbage() => Assert.Throws<InvalidDataException>(() => JpegCodec.Decode(new byte[] { 1, 2, 3, 4 }, out _, out _));

    [Fact]
    public void EncoderSendsKeyframeThenOnlyDeltas_AndSurvivesMessageRoundTrip()
    {
        const int w = 256, h = 128;
        var f = new byte[w * h * 4];
        var enc = new TileEncoder();
        var first = enc.Encode(0, f, w, h, w * 4, 70, keyframe: false)!;
        Assert.True(first.Keyframe);
        Assert.Equal(1u, first.Sequence);
        Assert.Null(enc.Encode(0, f, w, h, w * 4, 70, false));
        for (var i = 0; i < 64 * 4; i += 4) f[i] = 200;
        var delta = enc.Encode(0, f, w, h, w * 4, 70, false)!;
        Assert.False(delta.Keyframe);
        Assert.Single(delta.Rects);
        var parsed = FrameUpdateMessage.Parse(delta.Serialize());
        Assert.Equal(delta.Rects[0].Jpeg, parsed.Rects[0].Jpeg);
    }
}

public class HostileImageTests
{
    private static byte[] TinyJpeg(int w = 16, int h = 16)
    {
        var px = new byte[w * h * 4]; for (var i = 3; i < px.Length; i += 4) px[i] = 255;
        return JpegCodec.Encode(px, w * 4, new PixelRect(0, 0, w, h), 80);
    }

    [Fact]
    public void JpegWhoseHeaderClaimsHugeDimensionsIsRejectedBeforeAnyAllocation()
    {
        var jpeg = TinyJpeg();
        var sof = Enumerable.Range(0, jpeg.Length - 9).First(i => jpeg[i] == 0xFF && jpeg[i + 1] == 0xC0);   // SOF0: FF C0 len(2) precision(1) height(2) width(2)
        jpeg[sof + 5] = 0xFD; jpeg[sof + 6] = 0xE8;     // height = 65000
        jpeg[sof + 7] = 0xFD; jpeg[sof + 8] = 0xE8;     // width  = 65000
        var before = GC.GetTotalAllocatedBytes(true);
        Assert.Throws<InvalidDataException>(() => JpegCodec.DecodeExpecting(jpeg, 16, 16));
        Assert.True(GC.GetTotalAllocatedBytes(true) - before < 64 * 1024 * 1024, "must not allocate for a lying header");
    }

    [Fact]
    public void ValidTileDecodesAndMismatchedSizeIsRefused()
    {
        var jpeg = TinyJpeg(32, 16);
        Assert.Equal(32 * 16 * 4, JpegCodec.DecodeExpecting(jpeg, 32, 16).Length);
        Assert.Throws<InvalidDataException>(() => JpegCodec.DecodeExpecting(jpeg, 16, 16));
        Assert.Throws<InvalidDataException>(() => JpegCodec.DecodeExpecting(new byte[] { 1, 2, 3 }, 8, 8));
        Assert.Throws<InvalidDataException>(() => JpegCodec.DecodeExpecting(jpeg, 70000, 70000));
    }

    [Fact]
    public void TruncatedAndRandomJpegDataNeverCrashesTheDecoder()
    {
        var good = TinyJpeg(48, 48);
        var rng = new Random(3);
        for (var i = 0; i < 300; i++)
        {
            var d = (byte[])good.Clone();
            var cut = rng.Next(2, d.Length);
            d = d[..cut];
            if (rng.Next(2) == 0) d[rng.Next(d.Length)] ^= (byte)rng.Next(1, 255);
            try { JpegCodec.DecodeExpecting(d, 48, 48); } catch (InvalidDataException) { }
        }
    }
}

public class CoordinateMapperTests
{
    [Fact]
    public void MapsCornersOfSecondMonitorOnVirtualDesktopWithNegativeOrigin()
    {
        // Left monitor at (-1920,0) 1920x1080, primary at (0,0) 2560x1440 => virtual desktop (-1920,0) 4480x1440
        var vs = new VirtualScreen(-1920, 0, 4480, 1440);
        var primary = new MonitorInfo(0, 0, 0, 2560, 1440, true, "P");
        var left = new MonitorInfo(1, -1920, 0, 1920, 1080, false, "L");
        Assert.Equal((0, 0), CoordinateMapper.ToVirtualDesk(left, 0, 0, vs));
        Assert.Equal((65535, 65535), CoordinateMapper.ToVirtualDesk(primary, 65535, 65535, vs));
        var (x, y) = CoordinateMapper.ToVirtualDesk(primary, 0, 0, vs);
        Assert.InRange(x, (int)(1920.0 / 4479 * 65535) - 1, (int)(1920.0 / 4479 * 65535) + 1);
        Assert.Equal(0, y);
    }
}
