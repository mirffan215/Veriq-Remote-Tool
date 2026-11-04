using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using RemoteTool.Core.Protocol;
using RemoteTool.Core.Session;

namespace RemoteTool.Service.Windows;

/// <summary>Attaches the calling thread to whichever desktop currently receives input (user desktop, or the secure Winlogon desktop).</summary>
public interface IDesktopSwitch
{
    /// <summary>Returns the input desktop's name; <paramref name="changed"/> is true if this thread had to move to a different desktop.</summary>
    string EnsureInputDesktop(out bool changed);
}

/// <summary>
/// Win32 implementation. Must run on the SAME thread that captures/injects (the helper's dedicated endpoint thread), and the process
/// must be SYSTEM to open the Winlogon desktop. Untested outside Windows: see docs/SERVICE.md.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class Win32DesktopSwitch : IDesktopSwitch
{
    private const uint MAXIMUM_ALLOWED = 0x02000000;
    [ThreadStatic] private static IntPtr _attached;
    [ThreadStatic] private static string? _attachedName;

    public string EnsureInputDesktop(out bool changed)
    {
        changed = false;
        var h = OpenInputDesktop(0, false, MAXIMUM_ALLOWED);
        if (h == IntPtr.Zero) return _attachedName ?? "Default"; // transitional moment (e.g. during a desktop switch): keep what we have
        var name = NameOf(h);
        if (name == _attachedName) { CloseDesktop(h); return name; }
        if (SetThreadDesktop(h))
        {
            var old = _attached;
            _attached = h;
            _attachedName = name;
            if (old != IntPtr.Zero) CloseDesktop(old);
            changed = true;
        }
        else CloseDesktop(h);
        return _attachedName ?? name;
    }

    private static string NameOf(IntPtr desktop)
    {
        var buf = new byte[512];
        return GetUserObjectInformation(desktop, 2 /* UOI_NAME */, buf, buf.Length, out var needed) && needed > 2
            ? System.Text.Encoding.Unicode.GetString(buf, 0, (int)needed - 2) : "Default";
    }

    [DllImport("user32.dll", SetLastError = true)] private static extern IntPtr OpenInputDesktop(uint flags, bool inherit, uint access);
    [DllImport("user32.dll", SetLastError = true)] private static extern bool SetThreadDesktop(IntPtr desktop);
    [DllImport("user32.dll", SetLastError = true)] private static extern bool CloseDesktop(IntPtr desktop);
    [DllImport("user32.dll", SetLastError = true)] private static extern bool GetUserObjectInformation(IntPtr obj, int index, byte[] info, int length, out uint needed);
}

/// <summary>Screen capture that follows the input desktop; recreates the capture surface and forces a keyframe after a desktop change.</summary>
public sealed class DesktopAwareProducer : IFrameProducer, IH264Source
{
    private readonly IDesktopSwitch _switch;
    private readonly Func<IFrameProducer> _create;
    private IFrameProducer _inner;
    private bool _forceKey;

    public DesktopAwareProducer(IDesktopSwitch desktopSwitch, Func<IFrameProducer> create)
    {
        _switch = desktopSwitch;
        _create = create;
        _switch.EnsureInputDesktop(out _);
        _inner = create();
    }

    public string CurrentDesktop { get; private set; } = "Default";
    public bool H264Available => _inner is IH264Source { H264Available: true };

    private void Follow()
    {
        CurrentDesktop = _switch.EnsureInputDesktop(out var changed);
        if (!changed) return;
        _inner.Dispose();   // monitors, DIB surfaces and encoders belong to the old desktop
        _inner = _create();
        _forceKey = true;
    }

    public IReadOnlyList<MonitorInfo> GetMonitors() { Follow(); return _inner.GetMonitors(); }

    public FrameUpdateMessage? NextFrame(int monitorIndex, int quality, bool keyframe)
    {
        Follow();
        var key = keyframe || _forceKey;
        _forceKey = false;
        return _inner.NextFrame(monitorIndex, quality, key);
    }

    public VideoFrameMessage? NextH264(int monitorIndex, bool keyframe, int bitrateKbps)
    {
        Follow();
        if (_inner is not IH264Source s) throw new CodecUnavailableException("no H.264 source");
        var key = keyframe || _forceKey;
        _forceKey = false;
        return s.NextH264(monitorIndex, key, bitrateKbps);
    }

    public CursorShape GetCursorShape() => _inner.GetCursorShape();
    public void Dispose() => _inner.Dispose();
}

/// <summary>Input injection that first moves the thread to the current input desktop (so clicks reach the UAC prompt / login screen).</summary>
public sealed class DesktopAwareInjector : IInputInjector
{
    private readonly IDesktopSwitch _switch;
    private readonly IInputInjector _inner;
    public DesktopAwareInjector(IDesktopSwitch desktopSwitch, IInputInjector inner) { _switch = desktopSwitch; _inner = inner; }

    public void Mouse(MonitorInfo monitor, MouseEventMessage e) { _switch.EnsureInputDesktop(out _); _inner.Mouse(monitor, e); }
    public void Key(KeyEventMessage e) { _switch.EnsureInputDesktop(out _); _inner.Key(e); }
    public void ReleaseAll() { _switch.EnsureInputDesktop(out _); _inner.ReleaseAll(); }
    public void Dispose() => _inner.Dispose();
}
