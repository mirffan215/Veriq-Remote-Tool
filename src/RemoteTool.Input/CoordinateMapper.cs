using RemoteTool.Core.Protocol;

namespace RemoteTool.Input;

public readonly record struct VirtualScreen(int X, int Y, int Width, int Height);

public static class CoordinateMapper
{
    /// <summary>
    /// Maps a position normalised (0..65535) within <paramref name="monitor"/> to the 0..65535 range of the whole
    /// virtual desktop, as required by MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK.
    /// </summary>
    public static (int X, int Y) ToVirtualDesk(MonitorInfo monitor, ushort nx, ushort ny, VirtualScreen vs)
    {
        var px = monitor.X + nx / 65535.0 * (monitor.Width - 1);
        var py = monitor.Y + ny / 65535.0 * (monitor.Height - 1);
        var ax = (px - vs.X) * 65535.0 / Math.Max(1, vs.Width - 1);
        var ay = (py - vs.Y) * 65535.0 / Math.Max(1, vs.Height - 1);
        return ((int)Math.Round(Math.Clamp(ax, 0, 65535)), (int)Math.Round(Math.Clamp(ay, 0, 65535)));
    }
}
