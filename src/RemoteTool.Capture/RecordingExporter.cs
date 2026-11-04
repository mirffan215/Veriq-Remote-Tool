using RemoteTool.Core.Config;
using RemoteTool.Core.Protocol;
using RemoteTool.Core.Recording;
using SkiaSharp;

namespace RemoteTool.Capture;

public sealed record ExportSummary(int ImagesWritten, int TileFrames, long H264Bytes, string? Viewer, string? Reason);

/// <summary>
/// Turns an encrypted .rtrec into something reviewable: replays the tile updates onto a canvas and writes a PNG every N seconds
/// of session time (plus the final picture). H.264 recordings are exported as a raw Annex-B stream (<c>stream.h264</c>, play with
/// ffplay/VLC). Decrypting needs the same machine/user secret store that wrote the file - that is the access control.
/// </summary>
public static class RecordingExporter
{
    public static ExportSummary Export(string rtrecPath, ISecretProtector protector, string outputDirectory, TimeSpan interval)
    {
        Directory.CreateDirectory(outputDirectory);
        byte[]? canvas = null;
        int w = 0, h = 0, images = 0, frames = 0;
        long h264 = 0;
        var next = TimeSpan.Zero;
        string? viewer = null, reason = null;
        FileStream? raw = null;
        try
        {
            foreach (var rec in RecordingReader.Read(rtrecPath, protector))
            {
                switch (rec.Type)
                {
                    case RecordType.Meta:
                        try { using var d = System.Text.Json.JsonDocument.Parse(rec.Payload); viewer = d.RootElement.GetProperty("viewer").GetString(); } catch (System.Text.Json.JsonException) { }
                        break;
                    case RecordType.TileFrame:
                        var f = FrameUpdateMessage.Parse(rec.Payload);
                        if (canvas is null || f.Width != w || f.Height != h) { w = f.Width; h = f.Height; canvas = new byte[w * h * 4]; }
                        foreach (var r in f.Rects)
                        {
                            var px = JpegCodec.Decode(r.Jpeg, out var rw, out var rh);
                            for (var y = 0; y < rh; y++) Buffer.BlockCopy(px, y * rw * 4, canvas, ((r.Y + y) * w + r.X) * 4, rw * 4);
                        }
                        frames++;
                        if (rec.Time >= next) { WritePng(canvas, w, h, Path.Combine(outputDirectory, $"frame-{(int)rec.Time.TotalSeconds:D6}s.png")); images++; next = rec.Time + interval; }
                        break;
                    case RecordType.H264Frame:
                        raw ??= new FileStream(Path.Combine(outputDirectory, "stream.h264"), FileMode.Create, FileAccess.Write);
                        var v = VideoFrameMessage.Parse(rec.Payload);
                        raw.Write(v.Data);
                        h264 += v.Data.Length;
                        break;
                    case RecordType.End:
                        reason = System.Text.Encoding.UTF8.GetString(rec.Payload);
                        break;
                }
            }
        }
        finally { raw?.Dispose(); }
        if (canvas is not null) { WritePng(canvas, w, h, Path.Combine(outputDirectory, "final.png")); images++; }
        return new ExportSummary(images, frames, h264, viewer, reason);
    }

    private static void WritePng(byte[] bgra, int w, int h, string path)
    {
        using var img = SKImage.FromPixelCopy(new SKImageInfo(w, h, SKColorType.Bgra8888, SKAlphaType.Opaque), bgra, w * 4);
        using var data = img.Encode(SKEncodedImageFormat.Png, 100);
        using var fs = File.Create(path);
        data.SaveTo(fs);
    }
}
