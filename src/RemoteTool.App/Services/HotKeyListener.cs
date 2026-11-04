using System.Runtime.InteropServices;
using System.Windows.Interop;

namespace RemoteTool.App.Services;

/// <summary>Registers the emergency hotkey Ctrl+Alt+Shift+Q on a hidden message-only window.</summary>
public sealed class HotKeyListener : IDisposable
{
    private const int WM_HOTKEY = 0x0312;
    private const int Id = 0x5254; // "RT"
    private readonly HwndSource _source;
    private readonly Action _onPressed;

    public bool Registered { get; }

    public HotKeyListener(Action onPressed)
    {
        _onPressed = onPressed;
        var p = new HwndSourceParameters("RemoteToolHotKey") { ParentWindow = new IntPtr(-3) /* HWND_MESSAGE */, Width = 0, Height = 0 };
        _source = new HwndSource(p);
        _source.AddHook(Hook);
        // MOD_ALT=1, MOD_CONTROL=2, MOD_SHIFT=4, MOD_NOREPEAT=0x4000; 'Q' = 0x51
        Registered = RegisterHotKey(_source.Handle, Id, 1 | 2 | 4 | 0x4000, 0x51);
    }

    private IntPtr Hook(IntPtr hwnd, int msg, IntPtr wParam, IntPtr lParam, ref bool handled)
    {
        if (msg == WM_HOTKEY && wParam.ToInt32() == Id) { handled = true; _onPressed(); }
        return IntPtr.Zero;
    }

    public void Dispose()
    {
        if (Registered) UnregisterHotKey(_source.Handle, Id);
        _source.Dispose();
    }

    [DllImport("user32.dll", SetLastError = true)] private static extern bool RegisterHotKey(IntPtr hWnd, int id, uint modifiers, uint vk);
    [DllImport("user32.dll")] private static extern bool UnregisterHotKey(IntPtr hWnd, int id);
}
