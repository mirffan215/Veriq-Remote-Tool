using System.Diagnostics;
using RemoteTool.Capture;

namespace RemoteTool.Video;

/// <summary>
/// Reproducible bandwidth / CPU comparison of the two codecs on synthetic desktop-like content. Run on the Windows 11 target
/// (<c>RemoteTool.exe --bench-codec</c>) to see what H.264 actually saves on YOUR hardware; the tile numbers also run anywhere.
/// </summary>
public static class CodecBenchmark
{
    public sealed record Result(string Scenario, string Codec, double KbpsAt15Fps, double MsPerFrame, double BytesPerFrame);

    private static readonly bool Hd = Environment.GetEnvironmentVariable("BENCH_1080") is not null;
    private static readonly int W = Hd ? 1920 : 1280, H = Hd ? 1080 : 720;
    private const int Frames = 45, Fps = 15;
    public static string Resolution => $"{W}x{H}";

    public static IReadOnlyList<Result> Run(Func<IH264Encoder?>? h264, TextWriter? log = null)
    {
        var results = new List<Result>();
        foreach (var (name, gen) in Scenarios().Take(1)) { MeasureTiles(name, gen); MeasureTiles(name, gen); } // warm-up: JIT + thread pool, not measured
        foreach (var (name, gen) in Scenarios())
        {
            results.Add(MeasureTiles(name, gen));
            if (h264 is not null)
            {
                var enc = h264();
                if (enc is not null) { using (enc) results.Add(MeasureH264(name, gen, enc)); }
            }
        }
        if (log is not null) Print(results, log);
        return results;
    }

    public static void Print(IEnumerable<Result> results, TextWriter w)
    {
        w.WriteLine("| Scenario | Codec | kbit/s @15 fps | ms / frame | bytes / frame |");
        w.WriteLine("|---|---|---:|---:|---:|");
        foreach (var r in results) w.WriteLine($"| {r.Scenario} | {r.Codec} | {r.KbpsAt15Fps:N0} | {r.MsPerFrame:N1} | {r.BytesPerFrame:N0} |");
    }

    private static Result MeasureTiles(string name, Func<int, byte[]> gen)
    {
        var enc = new TileEncoder();
        long bytes = 0;
        var inputs = Enumerable.Range(0, Frames).Select(gen).ToArray();     // generation cost must not be measured
        enc.Encode(0, inputs[0], W, H, W * 4, 70, keyframe: false);          // initial keyframe: a one-off, excluded from steady state
        var sw = Stopwatch.StartNew();
        for (var i = 1; i < Frames; i++)
        {
            var frame = enc.Encode(0, inputs[i], W, H, W * 4, 70, keyframe: false);
            if (frame is not null) bytes += frame.Rects.Sum(r => r.Jpeg.Length) + 24;
        }
        sw.Stop();
        return Summarize(name, "Tile-JPEG", bytes, sw);
    }

    private static Result MeasureH264(string name, Func<int, byte[]> gen, IH264Encoder enc)
    {
        long bytes = 0;
        var inputs = Enumerable.Range(0, Frames).Select(gen).ToArray();
        var nv12 = new byte[ColorConvert.Nv12Size(W, H)];
        ColorConvert.BgraToNv12(inputs[0], W * 4, W, H, nv12);
        enc.Encode(nv12, forceKeyframe: true);                               // initial keyframe excluded (same as the tile codec)
        var sw = Stopwatch.StartNew();
        for (var i = 1; i < Frames; i++)
        {
            ColorConvert.BgraToNv12(inputs[i], W * 4, W, H, nv12);
            var data = enc.Encode(nv12, forceKeyframe: false);
            if (data is not null) bytes += data.Length + 24;
        }
        sw.Stop();
        return Summarize(name, enc.IsHardware ? "H.264 (hardware)" : "H.264 (software)", bytes, sw);
    }

    private static Result Summarize(string scenario, string codec, long bytes, Stopwatch sw)
        => new(scenario, codec, bytes * 8.0 / 1000 * Fps / (Frames - 1), sw.Elapsed.TotalMilliseconds / (Frames - 1), (double)bytes / (Frames - 1));

    // ---- synthetic content ---------------------------------------------------------------------

    private static byte[] TextPage(int seed, int shiftY = 0)
    {
        var f = new byte[W * H * 4];
        Array.Fill(f, (byte)245);
        var rng = new Random(seed);
        for (var line = 0; line < 60; line++)
        {
            var y0 = line * 12 - shiftY % 12 + (shiftY / 12 * 0);
            for (var x = 20; x < W - 20; x += 8)
            {
                if (rng.Next(5) == 0) continue;
                var shade = (byte)rng.Next(20, 90);
                for (var dy = 0; dy < 8; dy++)
                    for (var dx = 0; dx < 5; dx++)
                    {
                        var y = y0 + dy; if (y < 0 || y >= H) continue;
                        var p = (y * W + x + dx) * 4;
                        f[p] = f[p + 1] = f[p + 2] = shade; f[p + 3] = 255;
                    }
            }
        }
        return f;
    }

    private static IEnumerable<(string, Func<int, byte[]>)> Scenarios()
    {
        var page = TextPage(1);
        yield return ("Idle desktop", _ => page);
        yield return ("Typing (one glyph per frame)", i =>
        {
            var f = (byte[])page.Clone();
            for (var dy = 0; dy < 14; dy++) for (var dx = 0; dx < 8; dx++) { var p = ((100 + dy) * W + 40 + i * 9 + dx) * 4; f[p] = f[p + 1] = f[p + 2] = 0; }
            return f;
        });
        yield return ("Window drag (400x300 block)", i =>
        {
            var f = (byte[])page.Clone();
            for (var y = 200; y < 500; y++) for (var x = 100 + i * 8; x < 500 + i * 8 && x < W; x++) { var p = (y * W + x) * 4; f[p] = 230; f[p + 1] = 120; f[p + 2] = 40; f[p + 3] = 255; }
            return f;
        });
        yield return ("Scrolling text page", i => TextPage(1 + i / 6, i * 5));
        yield return ("Video playback (640x360 motion)", i =>
        {
            var f = (byte[])page.Clone();
            var r = new Random(i);
            for (var y = 180; y < 540; y++) for (var x = 300; x < 940; x++)
            { var p = (y * W + x) * 4; var v = (byte)((x * 3 + y * 2 + i * 17 + r.Next(24)) & 255); f[p] = v; f[p + 1] = (byte)(255 - v); f[p + 2] = (byte)(v / 2 + 40); f[p + 3] = 255; }
            return f;
        });
    }
}
