using System.IO.Hashing;

namespace RemoteTool.Capture;

public readonly record struct PixelRect(int X, int Y, int Width, int Height);

/// <summary>
/// Hashes the screen in 64x64 tiles and reports which regions changed since the previous call.
/// Adjacent changed tiles are merged into larger rectangles to keep the number of JPEG blocks small.
/// </summary>
public sealed class TileDiffer
{
    public const int TileSize = 64;
    private const int MaxBandHeight = 256;
    private ulong[]? _hashes;
    private int _w, _h;
    private readonly XxHash64 _hasher = new();

    /// <summary>True when the last <see cref="Diff"/> call had to restart from scratch (first frame or resolution change).</summary>
    public bool WasReset { get; private set; }

    public IReadOnlyList<PixelRect> Diff(ReadOnlySpan<byte> bgra, int width, int height, int stride, bool force)
    {
        if (width <= 0 || height <= 0 || stride < width * 4) throw new ArgumentException("invalid frame geometry");
        if (bgra.Length < (long)stride * (height - 1) + width * 4L) throw new ArgumentException("buffer too small");
        var tx = (width + TileSize - 1) / TileSize;
        var ty = (height + TileSize - 1) / TileSize;
        WasReset = _hashes is null || _w != width || _h != height;
        var previous = WasReset ? null : _hashes;
        var current = new ulong[tx * ty];
        var changed = new bool[tx * ty];
        var changedCount = 0;
        for (var j = 0; j < ty; j++)
        {
            var y0 = j * TileSize;
            var rows = Math.Min(TileSize, height - y0);
            for (var i = 0; i < tx; i++)
            {
                var x0 = i * TileSize;
                var bytes = Math.Min(TileSize, width - x0) * 4;
                _hasher.Reset();
                for (var r = 0; r < rows; r++) _hasher.Append(bgra.Slice((y0 + r) * stride + x0 * 4, bytes));
                var h = _hasher.GetCurrentHashAsUInt64();
                current[j * tx + i] = h;
                if (previous is null || previous[j * tx + i] != h) { changed[j * tx + i] = true; changedCount++; }
            }
        }
        _hashes = current;
        _w = width;
        _h = height;

        if (changedCount == 0 && !force && !WasReset) return Array.Empty<PixelRect>();
        if (force || WasReset || changedCount * 2 > tx * ty) return FullBands(width, height);
        return Merge(changed, tx, ty, width, height);
    }

    /// <summary>Forget previous frame so the next Diff returns the whole screen.</summary>
    public void Reset() { _hashes = null; }

    private static List<PixelRect> FullBands(int w, int h)
    {
        var list = new List<PixelRect>();
        for (var y = 0; y < h; y += MaxBandHeight) list.Add(new PixelRect(0, y, w, Math.Min(MaxBandHeight, h - y)));
        return list;
    }

    private static List<PixelRect> Merge(bool[] changed, int tx, int ty, int width, int height)
    {
        var done = new List<PixelRect>();
        var open = new Dictionary<(int x, int w), PixelRect>();
        for (var j = 0; j < ty; j++)
        {
            var y0 = j * TileSize;
            var th = Math.Min(TileSize, height - y0);
            var next = new Dictionary<(int x, int w), PixelRect>();
            var i = 0;
            while (i < tx)
            {
                if (!changed[j * tx + i]) { i++; continue; }
                var start = i;
                while (i < tx && changed[j * tx + i]) i++;
                var x = start * TileSize;
                var w = Math.Min(i * TileSize, width) - x;
                if (open.Remove((x, w), out var above)) next[(x, w)] = above with { Height = above.Height + th };
                else next[(x, w)] = new PixelRect(x, y0, w, th);
            }
            foreach (var kv in open) done.Add(kv.Value);
            open = next;
        }
        done.AddRange(open.Values);
        return done;
    }
}
