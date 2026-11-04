using SkiaSharp;

namespace RemoteTool.Capture;

/// <summary>JPEG encode/decode of BGRA32 regions (SkiaSharp).</summary>
public static class JpegCodec
{
    public static byte[] Encode(ReadOnlySpan<byte> bgra, int stride, PixelRect r, int quality)
    {
        // Copy the region into a tight buffer so Skia never reads past the sub-rectangle.
        var tight = new byte[r.Width * r.Height * 4];
        for (var row = 0; row < r.Height; row++)
            bgra.Slice((r.Y + row) * stride + r.X * 4, r.Width * 4).CopyTo(tight.AsSpan(row * r.Width * 4, r.Width * 4));
        using var image = SKImage.FromPixelCopy(new SKImageInfo(r.Width, r.Height, SKColorType.Bgra8888, SKAlphaType.Opaque), tight, r.Width * 4);
        using var data = image.Encode(SKEncodedImageFormat.Jpeg, Math.Clamp(quality, 10, 100));
        return data.ToArray();
    }

    /// <summary>Decodes to tight BGRA32 (stride = width*4). Throws <see cref="InvalidDataException"/> on bad input.</summary>
    public static byte[] Decode(byte[] jpeg, out int width, out int height)
    {
        SKBitmap? bmp;
        try { bmp = SKBitmap.Decode(jpeg); }
        catch (ArgumentException) { throw new InvalidDataException("not a decodable image"); }
        using var _ = bmp;
        if (bmp is null) throw new InvalidDataException("not a decodable image");
        SKBitmap src = bmp;
        SKBitmap? converted = null;
        if (bmp.ColorType != SKColorType.Bgra8888)
        {
            converted = bmp.Copy(SKColorType.Bgra8888);
            if (converted is null) throw new InvalidDataException("unsupported pixel format");
            src = converted;
        }
        try
        {
            width = src.Width;
            height = src.Height;
            return src.Bytes;
        }
        finally { converted?.Dispose(); }
    }
}
