using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using RemoteTool.Core.Protocol;
using RemoteTool.Core.Session;

namespace RemoteTool.Input;

/// <summary>
/// Injects remote mouse/keyboard input with SendInput. Keys are sent as hardware scan codes translated on the
/// HOST using its own keyboard layout, so layout differences between viewer and host do not garble input.
/// Every pressed key/button is tracked and released on <see cref="ReleaseAll"/> (disconnect) to avoid stuck input.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsInputInjector : IInputInjector
{
    private readonly object _gate = new();
    private readonly HashSet<(ushort vk, bool ext)> _keysDown = new();
    private readonly HashSet<MouseButton> _buttonsDown = new();

    public void Mouse(MonitorInfo monitor, MouseEventMessage e)
    {
        lock (_gate)
        {
            var vs = new VirtualScreen(GetSystemMetrics(76), GetSystemMetrics(77), GetSystemMetrics(78), GetSystemMetrics(79));
            var (ax, ay) = CoordinateMapper.ToVirtualDesk(monitor, e.X, e.Y, vs);
            uint flags = 0x8000 /*ABSOLUTE*/ | 0x4000 /*VIRTUALDESK*/ | 0x0001 /*MOVE*/;
            uint data = 0;
            switch (e.Kind)
            {
                case MouseKind.Down: flags |= ButtonFlag(e.Button, down: true, out data); _buttonsDown.Add(e.Button); break;
                case MouseKind.Up: flags |= ButtonFlag(e.Button, down: false, out data); _buttonsDown.Remove(e.Button); break;
                case MouseKind.Wheel: flags |= 0x0800; data = (uint)e.WheelDelta; break;
                case MouseKind.HWheel: flags |= 0x1000; data = (uint)e.WheelDelta; break;
            }
            Send(new INPUT { type = 0, U = new InputUnion { mi = new MOUSEINPUT { dx = ax, dy = ay, mouseData = data, dwFlags = flags } } });
        }
    }

    public void Key(KeyEventMessage e)
    {
        lock (_gate)
        {
            SendKey(e.VirtualKey, e.Extended, e.KeyUp);
            if (e.KeyUp) _keysDown.Remove((e.VirtualKey, e.Extended)); else _keysDown.Add((e.VirtualKey, e.Extended));
        }
    }

    public void ReleaseAll()
    {
        lock (_gate)
        {
            foreach (var (vk, ext) in _keysDown.ToList()) SendKey(vk, ext, up: true);
            _keysDown.Clear();
            foreach (var b in _buttonsDown.ToList())
            {
                var flags = ButtonFlag(b, down: false, out var data);
                Send(new INPUT { type = 0, U = new InputUnion { mi = new MOUSEINPUT { mouseData = data, dwFlags = flags } } });
            }
            _buttonsDown.Clear();
        }
    }

    private static uint ButtonFlag(MouseButton b, bool down, out uint data)
    {
        data = 0;
        switch (b)
        {
            case MouseButton.Left: return down ? 0x0002u : 0x0004u;
            case MouseButton.Right: return down ? 0x0008u : 0x0010u;
            case MouseButton.Middle: return down ? 0x0020u : 0x0040u;
            case MouseButton.X1: data = 1; return down ? 0x0080u : 0x0100u;
            case MouseButton.X2: data = 2; return down ? 0x0080u : 0x0100u;
            default: return 0;
        }
    }

    private static void SendKey(ushort vk, bool extended, bool up)
    {
        var scan = MapVirtualKey(vk, 4 /*MAPVK_VK_TO_VSC_EX*/);
        uint flags = up ? 0x0002u : 0u;
        var ki = new KEYBDINPUT();
        if (scan != 0)
        {
            ki.wScan = (ushort)(scan & 0xFF);
            flags |= 0x0008; // KEYEVENTF_SCANCODE
            if (extended || (scan & 0xFF00) == 0xE000) flags |= 0x0001; // KEYEVENTF_EXTENDEDKEY
        }
        else
        {
            ki.wVk = vk; // no scan code known: fall back to a virtual-key event
            if (extended) flags |= 0x0001;
        }
        ki.dwFlags = flags;
        Send(new INPUT { type = 1, U = new InputUnion { ki = ki } });
    }

    private static void Send(INPUT input)
    {
        var sent = SendInput(1, new[] { input }, Marshal.SizeOf<INPUT>());
        // sent == 0 means blocked (UIPI: target is elevated / secure desktop). Phase 3 service helper addresses this.
        _ = sent;
    }

    public void Dispose() => ReleaseAll();

    [StructLayout(LayoutKind.Sequential)] private struct MOUSEINPUT { public int dx, dy; public uint mouseData, dwFlags, time; public UIntPtr dwExtraInfo; }
    [StructLayout(LayoutKind.Sequential)] private struct KEYBDINPUT { public ushort wVk, wScan; public uint dwFlags, time; public UIntPtr dwExtraInfo; }
    [StructLayout(LayoutKind.Explicit)] private struct InputUnion { [FieldOffset(0)] public MOUSEINPUT mi; [FieldOffset(0)] public KEYBDINPUT ki; }
    [StructLayout(LayoutKind.Sequential)] private struct INPUT { public uint type; public InputUnion U; }

    [DllImport("user32.dll", SetLastError = true)] private static extern uint SendInput(uint n, INPUT[] inputs, int size);
    [DllImport("user32.dll")] private static extern uint MapVirtualKey(uint code, uint mapType);
    [DllImport("user32.dll")] private static extern int GetSystemMetrics(int index);
}
