using RemoteTool.Core.Protocol;

namespace RemoteTool.Capture;

/// <summary>Turns raw BGRA frames of ONE monitor into <see cref="FrameUpdateMessage"/>s containing only changed regions.</summary>
public sealed class TileEncoder
{
    private readonly TileDiffer _differ = new();
    private uint _seq;

    public unsafe FrameUpdateMessage? Encode(byte monitor, ReadOnlySpan<byte> bgra, int width, int height, int stride, int quality, bool keyframe)
    {
        var rects = _differ.Diff(bgra, width, height, stride, keyframe);
        if (rects.Count == 0) return null;
        var tiles = new TileRect[rects.Count];
        fixed (byte* p = bgra)
        {
            var bits = (IntPtr)p;
            // Independent JPEG encodes: spread them over the cores (a full-screen change is the expensive case).
            if (rects.Count > 1 && Environment.ProcessorCount > 1)
                Parallel.For(0, rects.Count, i => { var r = rects[i]; tiles[i] = new TileRect(r.X, r.Y, r.Width, r.Height, JpegCodec.EncodeAt(bits, stride, r, quality)); });
            else
                for (var i = 0; i < rects.Count; i++) { var r = rects[i]; tiles[i] = new TileRect(r.X, r.Y, r.Width, r.Height, JpegCodec.EncodeAt(bits, stride, r, quality)); }
        }
        return new FrameUpdateMessage(monitor, ++_seq, width, height, keyframe || _differ.WasReset, tiles);
    }
}
