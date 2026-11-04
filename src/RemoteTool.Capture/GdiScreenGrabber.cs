using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using RemoteTool.Core.Protocol;

namespace RemoteTool.Capture;

/// <summary>
/// GDI BitBlt capture (works on every supported Windows version, no GPU dependency). Requires a per-monitor-DPI-aware
/// process so coordinates are physical pixels. See docs/DECISIONS.md D-08 for why DXGI/WGC is deferred.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class GdiScreenGrabber : IScreenGrabber
{
    private IntPtr _memDc, _dib, _oldBitmap, _bits;
    private int _w, _h;
    private readonly Dictionary<IntPtr, CursorShape> _cursorMap = new();

    public GdiScreenGrabber()
    {
        foreach (var (idc, shape) in new[] {
            (32512, CursorShape.Arrow), (32513, CursorShape.IBeam), (32514, CursorShape.Wait), (32515, CursorShape.Cross),
            (32649, CursorShape.Hand), (32645, CursorShape.SizeNS), (32644, CursorShape.SizeWE), (32642, CursorShape.SizeNWSE),
            (32643, CursorShape.SizeNESW), (32646, CursorShape.SizeAll), (32648, CursorShape.No), (32650, CursorShape.AppStarting),
            (32651, CursorShape.Help) })
        {
            var h = LoadCursor(IntPtr.Zero, (IntPtr)idc);
            if (h != IntPtr.Zero) _cursorMap[h] = shape;
        }
    }

    public IReadOnlyList<MonitorInfo> GetMonitors()
    {
        var list = new List<(RECT rect, bool primary, string name)>();
        EnumDisplayMonitors(IntPtr.Zero, IntPtr.Zero, (IntPtr hMon, IntPtr _, ref RECT _, IntPtr _) =>
        {
            var mi = new MONITORINFOEX { cbSize = Marshal.SizeOf<MONITORINFOEX>() };
            if (GetMonitorInfo(hMon, ref mi)) list.Add((mi.rcMonitor, (mi.dwFlags & 1) != 0, mi.szDevice));
            return true;
        }, IntPtr.Zero);
        // Primary first, then left-to-right, so index 0 is stable and intuitive.
        return list.OrderByDescending(x => x.primary).ThenBy(x => x.rect.Left).ThenBy(x => x.rect.Top).Take(ProtocolConstants.MaxMonitors)
            .Select((x, i) => new MonitorInfo((byte)i, x.rect.Left, x.rect.Top, x.rect.Right - x.rect.Left, x.rect.Bottom - x.rect.Top, x.primary, x.name.TrimStart('\\', '.')))
            .ToList();
    }

    public unsafe bool TryGrab(MonitorInfo m, out ReadOnlySpan<byte> bgra, out int stride)
    {
        bgra = default;
        stride = m.Width * 4;
        if (!EnsureSurface(m.Width, m.Height)) return false;
        var screen = GetDC(IntPtr.Zero);
        if (screen == IntPtr.Zero) return false;
        try
        {
            // SRCCOPY | CAPTUREBLT: include layered (transparent) windows.
            if (!BitBlt(_memDc, 0, 0, m.Width, m.Height, screen, m.X, m.Y, 0x00CC0020 | 0x40000000)) return false;
        }
        finally { ReleaseDC(IntPtr.Zero, screen); }
        GdiFlush();
        bgra = new ReadOnlySpan<byte>((void*)_bits, stride * m.Height);
        return true;
    }

    private bool EnsureSurface(int w, int h)
    {
        if (_dib != IntPtr.Zero && _w == w && _h == h) return true;
        FreeSurface();
        var screen = GetDC(IntPtr.Zero);
        try
        {
            _memDc = CreateCompatibleDC(screen);
            var bmi = new BITMAPINFO { biSize = 40, biWidth = w, biHeight = -h /* top-down */, biPlanes = 1, biBitCount = 32, biCompression = 0 };
            _dib = CreateDIBSection(_memDc, ref bmi, 0, out _bits, IntPtr.Zero, 0);
            if (_dib == IntPtr.Zero) { FreeSurface(); return false; }
            _oldBitmap = SelectObject(_memDc, _dib);
            _w = w;
            _h = h;
            return true;
        }
        finally { ReleaseDC(IntPtr.Zero, screen); }
    }

    private void FreeSurface()
    {
        if (_memDc != IntPtr.Zero && _oldBitmap != IntPtr.Zero) SelectObject(_memDc, _oldBitmap);
        if (_dib != IntPtr.Zero) DeleteObject(_dib);
        if (_memDc != IntPtr.Zero) DeleteDC(_memDc);
        _memDc = _dib = _oldBitmap = _bits = IntPtr.Zero;
        _w = _h = 0;
    }

    public CursorShape GetCursorShape()
    {
        var ci = new CURSORINFO { cbSize = Marshal.SizeOf<CURSORINFO>() };
        if (!GetCursorInfo(ref ci) || (ci.flags & 1) == 0) return CursorShape.Hidden;
        return _cursorMap.TryGetValue(ci.hCursor, out var s) ? s : CursorShape.Arrow;
    }

    public void Dispose() => FreeSurface();

    // ---- Win32 -----------------------------------------------------------------------------------
    [StructLayout(LayoutKind.Sequential)] private struct RECT { public int Left, Top, Right, Bottom; }
    [StructLayout(LayoutKind.Sequential)] private struct POINT { public int X, Y; }
    [StructLayout(LayoutKind.Sequential)] private struct CURSORINFO { public int cbSize, flags; public IntPtr hCursor; public POINT ptScreenPos; }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct MONITORINFOEX { public int cbSize; public RECT rcMonitor, rcWork; public int dwFlags; [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)] public string szDevice; }
    [StructLayout(LayoutKind.Sequential)]
    private struct BITMAPINFO { public int biSize, biWidth, biHeight; public short biPlanes, biBitCount; public int biCompression, biSizeImage, biXPelsPerMeter, biYPelsPerMeter, biClrUsed, biClrImportant; }
    private delegate bool MonitorEnumProc(IntPtr hMonitor, IntPtr hdc, ref RECT rect, IntPtr data);

    [DllImport("user32.dll")] private static extern bool EnumDisplayMonitors(IntPtr hdc, IntPtr clip, MonitorEnumProc proc, IntPtr data);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern bool GetMonitorInfo(IntPtr hMonitor, ref MONITORINFOEX mi);
    [DllImport("user32.dll")] private static extern IntPtr GetDC(IntPtr hwnd);
    [DllImport("user32.dll")] private static extern int ReleaseDC(IntPtr hwnd, IntPtr hdc);
    [DllImport("user32.dll")] private static extern bool GetCursorInfo(ref CURSORINFO ci);
    [DllImport("user32.dll")] private static extern IntPtr LoadCursor(IntPtr hInstance, IntPtr name);
    [DllImport("gdi32.dll")] private static extern IntPtr CreateCompatibleDC(IntPtr hdc);
    [DllImport("gdi32.dll")] private static extern IntPtr CreateDIBSection(IntPtr hdc, ref BITMAPINFO bmi, uint usage, out IntPtr bits, IntPtr section, uint offset);
    [DllImport("gdi32.dll")] private static extern IntPtr SelectObject(IntPtr hdc, IntPtr obj);
    [DllImport("gdi32.dll")] private static extern bool DeleteObject(IntPtr obj);
    [DllImport("gdi32.dll")] private static extern bool DeleteDC(IntPtr hdc);
    [DllImport("gdi32.dll")] private static extern bool BitBlt(IntPtr dst, int x, int y, int w, int h, IntPtr src, int sx, int sy, uint rop);
    [DllImport("gdi32.dll")] private static extern bool GdiFlush();
}
