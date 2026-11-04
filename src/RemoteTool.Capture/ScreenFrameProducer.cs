using RemoteTool.Core.Protocol;
using RemoteTool.Core.Session;

namespace RemoteTool.Capture;

public sealed class ScreenFrameProducer : IFrameProducer
{
    private readonly IScreenGrabber _grabber;
    private readonly Dictionary<int, TileEncoder> _encoders = new();
    private IReadOnlyList<MonitorInfo>? _monitors;

    public ScreenFrameProducer(IScreenGrabber grabber) { _grabber = grabber; }

    public IReadOnlyList<MonitorInfo> GetMonitors() => _monitors = _grabber.GetMonitors();

    public FrameUpdateMessage? NextFrame(int monitorIndex, int quality, bool keyframe)
    {
        var monitors = _monitors ?? GetMonitors();
        var m = monitors.FirstOrDefault(x => x.Index == monitorIndex);
        if (m is null) return null;
        if (!_grabber.TryGrab(m, out var pixels, out var stride)) return null; // e.g. secure desktop: nothing to send
        if (!_encoders.TryGetValue(monitorIndex, out var enc)) _encoders[monitorIndex] = enc = new TileEncoder();
        return enc.Encode(m.Index, pixels, m.Width, m.Height, stride, quality, keyframe);
    }

    public CursorShape GetCursorShape() => _grabber.GetCursorShape();
    public void Dispose() => _grabber.Dispose();
}
