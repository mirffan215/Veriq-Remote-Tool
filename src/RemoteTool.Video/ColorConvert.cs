namespace RemoteTool.Video;

/// <summary>BT.601 limited-range conversions between BGRA32 and NV12 (the pixel format H.264 MFTs use). Parallel over rows.</summary>
public static class ColorConvert
{
    public static int Nv12Size(int width, int height) => width * height + width * (height / 2);

    /// <summary>Width and height must be even. <paramref name="nv12"/> must hold <see cref="Nv12Size"/> bytes.</summary>
    public static void BgraToNv12(ReadOnlySpan<byte> bgra, int stride, int width, int height, Span<byte> nv12)
    {
        if ((width & 1) != 0 || (height & 1) != 0) throw new ArgumentException("even dimensions required");
        if (nv12.Length < Nv12Size(width, height)) throw new ArgumentException("nv12 buffer too small");
        var src = bgra.ToArray(); // spans cannot be captured by lambdas; this copy is cheaper than the conversion it enables
        var dst = nv12.ToArray();
        var uvBase = width * height;
        Parallel.For(0, height / 2, rowPair =>
        {
            for (var dy = 0; dy < 2; dy++)
            {
                var y = rowPair * 2 + dy;
                var s = y * stride;
                var d = y * width;
                for (var x = 0; x < width; x++, s += 4)
                {
                    int b = src[s], g = src[s + 1], r = src[s + 2];
                    dst[d + x] = (byte)(((66 * r + 129 * g + 25 * b + 128) >> 8) + 16);
                }
            }
            var s0 = rowPair * 2 * stride;
            var s1 = s0 + stride;
            var u = uvBase + rowPair * width;
            for (var x = 0; x < width; x += 2)
            {
                var p0 = s0 + x * 4; var p1 = s1 + x * 4;
                int b = (src[p0] + src[p0 + 4] + src[p1] + src[p1 + 4]) >> 2;
                int g = (src[p0 + 1] + src[p0 + 5] + src[p1 + 1] + src[p1 + 5]) >> 2;
                int r = (src[p0 + 2] + src[p0 + 6] + src[p1 + 2] + src[p1 + 6]) >> 2;
                dst[u + x] = (byte)(((-38 * r - 74 * g + 112 * b + 128) >> 8) + 128);
                dst[u + x + 1] = (byte)(((112 * r - 94 * g - 18 * b + 128) >> 8) + 128);
            }
        });
        dst.AsSpan(0, Nv12Size(width, height)).CopyTo(nv12);
    }

    /// <param name="yStride">Bytes per row of the Y plane in the source (may exceed width).</param>
    /// <param name="uvOffset">Byte offset of the interleaved UV plane.</param>
    public static byte[] Nv12ToBgra(byte[] nv12, int yStride, int uvOffset, int width, int height)
    {
        if (uvOffset + yStride * ((height + 1) / 2) > nv12.Length || yStride < width) throw new ArgumentException("bad NV12 geometry");
        var bgra = new byte[width * height * 4];
        Parallel.For(0, height, y =>
        {
            var yRow = y * yStride;
            var uvRow = uvOffset + (y >> 1) * yStride;
            var o = y * width * 4;
            for (var x = 0; x < width; x++, o += 4)
            {
                int c = nv12[yRow + x] - 16;
                int d = nv12[uvRow + (x & ~1)] - 128;
                int e = nv12[uvRow + (x & ~1) + 1] - 128;
                int r = (298 * c + 409 * e + 128) >> 8;
                int g = (298 * c - 100 * d - 208 * e + 128) >> 8;
                int b = (298 * c + 516 * d + 128) >> 8;
                bgra[o] = (byte)Math.Clamp(b, 0, 255);
                bgra[o + 1] = (byte)Math.Clamp(g, 0, 255);
                bgra[o + 2] = (byte)Math.Clamp(r, 0, 255);
                bgra[o + 3] = 255;
            }
        });
        return bgra;
    }
}

/// <summary>Tiny Annex-B helpers.</summary>
public static class AnnexB
{
    /// <summary>Returns the NAL unit types present (low 5 bits of the byte after each start code).</summary>
    public static IReadOnlyList<int> NalTypes(ReadOnlySpan<byte> data)
    {
        var list = new List<int>();
        for (var i = 0; i + 3 < data.Length; i++)
        {
            if (data[i] == 0 && data[i + 1] == 0 && (data[i + 2] == 1 || (data[i + 2] == 0 && i + 4 < data.Length && data[i + 3] == 1)))
            {
                var hdr = data[i + 2] == 1 ? i + 3 : i + 4;
                if (hdr < data.Length) list.Add(data[hdr] & 0x1F);
                i = hdr;
            }
        }
        return list;
    }

    public static bool HasParameterSets(ReadOnlySpan<byte> data) { var t = NalTypes(data); return t.Contains(7) && t.Contains(8); }
    public static bool IsKeyframe(ReadOnlySpan<byte> data) => NalTypes(data).Contains(5);
}
