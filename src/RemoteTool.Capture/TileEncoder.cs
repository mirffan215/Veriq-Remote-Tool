using RemoteTool.Core.Protocol;

namespace RemoteTool.Capture;

/// <summary>Turns raw BGRA frames of ONE monitor into <see cref="FrameUpdateMessage"/>s containing only changed regions.</summary>
public sealed class TileEncoder
{
    private readonly TileDiffer _differ = new();
    private uint _seq;

    public FrameUpdateMessage? Encode(byte monitor, ReadOnlySpan<byte> bgra, int width, int height, int stride, int quality, bool keyframe)
    {
        var rects = _differ.Diff(bgra, width, height, stride, keyframe);
        if (rects.Count == 0) return null;
        var tiles = new List<TileRect>(rects.Count);
        foreach (var r in rects)
            tiles.Add(new TileRect(r.X, r.Y, r.Width, r.Height, JpegCodec.Encode(bgra, stride, r, quality)));
        return new FrameUpdateMessage(monitor, ++_seq, width, height, keyframe || _differ.WasReset, tiles);
    }
}
