using SkiaSharp;

namespace RemoteTool.Capture;

/// <summary>JPEG encode/decode of BGRA32 regions (SkiaSharp).</summary>
public static class JpegCodec
{
    public static unsafe byte[] Encode(ReadOnlySpan<byte> bgra, int stride, PixelRect r, int quality)
    {
        if (r.X < 0 || r.Y < 0 || r.Width <= 0 || r.Height <= 0 || r.X + r.Width > stride / 4 || bgra.Length < (long)(r.Y + r.Height - 1) * stride + (r.X + r.Width) * 4L)
            throw new ArgumentException("region outside buffer");
        fixed (byte* p = bgra) return EncodeAt((IntPtr)p, stride, r, quality);
    }

    /// <summary>Encodes a sub-rectangle straight from the capture buffer (no copy); the caller guarantees the pointer covers the region.</summary>
    public static byte[] EncodeAt(IntPtr bits, int stride, PixelRect r, int quality)
    {
        var info = new SKImageInfo(r.Width, r.Height, SKColorType.Bgra8888, SKAlphaType.Opaque);
        using var pixmap = new SKPixmap(info, bits + r.Y * stride + r.X * 4, stride);
        using var image = SKImage.FromPixels(pixmap);
        using var data = image.Encode(SKEncodedImageFormat.Jpeg, Math.Clamp(quality, 10, 100));
        return data.ToArray();
    }

    /// <summary>
    /// Decodes a tile, but first reads only the JPEG header and refuses anything whose declared size differs from the rectangle the protocol
    /// announced - a hostile host cannot make the viewer allocate a huge bitmap by lying in the JPEG header.
    /// </summary>
    public static byte[] DecodeExpecting(byte[] jpeg, int expectedWidth, int expectedHeight)
    {
        if (expectedWidth <= 0 || expectedHeight <= 0 || (long)expectedWidth * expectedHeight > RemoteTool.Core.Protocol.ProtocolConstants.MaxFramePixels)
            throw new InvalidDataException("unreasonable tile size");
        SKCodec? codec;
        try { codec = SKCodec.Create(new SKMemoryStream(jpeg)); }
        catch (ArgumentException) { throw new InvalidDataException("not a decodable image"); }
        using (codec)
        {
            if (codec is null) throw new InvalidDataException("not a decodable image");
            if (codec.Info.Width != expectedWidth || codec.Info.Height != expectedHeight)
                throw new InvalidDataException($"tile header says {codec.Info.Width}x{codec.Info.Height}, protocol says {expectedWidth}x{expectedHeight}");
        }
        return Decode(jpeg, out _, out _);
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
