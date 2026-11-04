using RemoteTool.Core.Protocol;

namespace RemoteTool.Capture;

/// <summary>Raw screen source. The pixel span returned by <see cref="TryGrab"/> is valid until the next call.</summary>
public interface IScreenGrabber : IDisposable
{
    IReadOnlyList<MonitorInfo> GetMonitors();
    bool TryGrab(MonitorInfo monitor, out ReadOnlySpan<byte> bgra, out int stride);
    CursorShape GetCursorShape();
}
