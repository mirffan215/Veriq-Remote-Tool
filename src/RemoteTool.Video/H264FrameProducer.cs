using RemoteTool.Capture;
using RemoteTool.Core.Protocol;
using RemoteTool.Core.Session;

namespace RemoteTool.Video;

/// <summary>
/// Screen source that can speak both codecs: tile-JPEG (always) and H.264 (when an encoder can be created). H.264 frames are only produced
/// when the picture changed. Any encoder problem is reported as <see cref="CodecUnavailableException"/> so the host falls back to tiles.
/// </summary>
public sealed class H264FrameProducer : IFrameProducer, IH264Source
{
    public delegate IH264Encoder? EncoderFactory(int width, int height, int fps, int kbps, out string? error);

    private readonly IScreenGrabber _grabber;
    private readonly ScreenFrameProducer _tiles;
    private readonly EncoderFactory _factory;
    private readonly Dictionary<int, TileDiffer> _differs = new();
    private IReadOnlyList<MonitorInfo>? _monitors;
    private IH264Encoder? _encoder;
    private int _encW, _encH, _encMonitor = -1;
    private byte[] _nv12 = Array.Empty<byte>();
    private uint _seq;
    private bool? _available;
    private bool _needKey = true;

    public H264FrameProducer(IScreenGrabber grabber, EncoderFactory factory)
    {
        _grabber = grabber;
        _tiles = new ScreenFrameProducer(grabber);
        _factory = factory;
    }

    public string? LastError { get; private set; }
    public string? EncoderName => _encoder?.Name;
    public bool EncoderIsHardware => _encoder?.IsHardware ?? false;

    public bool H264Available
    {
        get
        {
            if (_available is { } a) return a;
            using var probe = _factory(256, 144, 30, 1000, out var err);
            LastError = err;
            return (_available = probe is not null).Value;
        }
    }

    public IReadOnlyList<MonitorInfo> GetMonitors() => _monitors = _tiles.GetMonitors();
    public FrameUpdateMessage? NextFrame(int monitorIndex, int quality, bool keyframe) => _tiles.NextFrame(monitorIndex, quality, keyframe);
    public CursorShape GetCursorShape() => _grabber.GetCursorShape();

    public VideoFrameMessage? NextH264(int monitorIndex, bool keyframe, int bitrateKbps)
    {
        var monitors = _monitors ?? GetMonitors();
        var m = monitors.FirstOrDefault(x => x.Index == monitorIndex);
        if (m is null || !_grabber.TryGrab(m, out var pixels, out var stride)) return null;
        var w = m.Width & ~1;
        var h = m.Height & ~1;

        if (!_differs.TryGetValue(monitorIndex, out var differ)) _differs[monitorIndex] = differ = new TileDiffer();
        var changed = differ.Diff(pixels, m.Width, m.Height, stride, force: keyframe).Count > 0;
        if (!changed && !keyframe && !_needKey) return null;

        if (_encoder is null || _encW != w || _encH != h || _encMonitor != monitorIndex)
        {
            _encoder?.Dispose();
            _encoder = _factory(w, h, 30, Math.Max(500, bitrateKbps), out var err);
            LastError = err;
            if (_encoder is null) throw new CodecUnavailableException(err ?? "no H.264 encoder");
            (_encW, _encH, _encMonitor) = (w, h, monitorIndex);
            _needKey = true;
        }

        var need = ColorConvert.Nv12Size(w, h);
        if (_nv12.Length != need) _nv12 = new byte[need];
        ColorConvert.BgraToNv12(pixels, stride, w, h, _nv12);
        _encoder.SetBitrate(bitrateKbps);
        var force = keyframe || _needKey;
        var data = _encoder.Encode(_nv12, force);
        if (data is null || data.Length == 0) return null;
        _needKey = false;
        return new VideoFrameMessage(m.Index, ++_seq, w, h, force || AnnexB.IsKeyframe(data), data);
    }

    public void Dispose()
    {
        _encoder?.Dispose();
        _tiles.Dispose();
    }
}

public static class H264Support
{
    /// <summary>Default factory: hardware MFT first, Microsoft software MFT second; null elsewhere (non-Windows, or Media Feature Pack missing).</summary>
    public static IH264Encoder? CreateEncoder(int width, int height, int fps, int kbps, out string? error)
    {
        if (!OperatingSystem.IsWindows()) { error = "H.264 via Media Foundation is Windows-only"; return null; }
        try { return MfH264Encoder.TryCreate(width, height, fps, kbps, preferHardware: true, out error); }
        catch (Exception e) { error = e.Message; return null; }
    }

    public static IH264Decoder? CreateDecoder()
        => OperatingSystem.IsWindows() ? MfH264Decoder.Create() : null;
}
