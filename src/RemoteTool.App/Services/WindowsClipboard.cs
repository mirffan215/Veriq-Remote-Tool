using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Threading;
using RemoteTool.Core.Session;

namespace RemoteTool.App.Services;

/// <summary>Plain-text clipboard access with change notifications (WM_CLIPBOARDUPDATE on a hidden message-only window).</summary>
public sealed class WindowsClipboard : IClipboardAccess
{
    private const int WM_CLIPBOARDUPDATE = 0x031D;
    private readonly Dispatcher _ui = Application.Current.Dispatcher;
    private HwndSource? _source;

    public event Action? Changed;

    public WindowsClipboard()
    {
        _ui.Invoke(() =>
        {
            _source = new HwndSource(new HwndSourceParameters("RemoteToolClipboard") { ParentWindow = new IntPtr(-3) /* HWND_MESSAGE */, Width = 0, Height = 0 });
            _source.AddHook(Hook);
            AddClipboardFormatListener(_source.Handle);
        });
    }

    private IntPtr Hook(IntPtr hwnd, int msg, IntPtr wParam, IntPtr lParam, ref bool handled)
    {
        if (msg == WM_CLIPBOARDUPDATE) Changed?.Invoke();
        return IntPtr.Zero;
    }

    public string? GetText() => _ui.Invoke(() => Retry(() => Clipboard.ContainsText() ? Clipboard.GetText() : null));

    public void SetText(string text) => _ui.Invoke(() => Retry<object?>(() => { Clipboard.SetText(text); return null; }));

    /// <summary>The clipboard is a shared resource; another process may hold it for a few milliseconds.</summary>
    private static T Retry<T>(Func<T> action)
    {
        for (var i = 0; ; i++)
        {
            try { return action(); }
            catch (COMException) when (i < 5) { Thread.Sleep(20); }
        }
    }

    public void Dispose()
    {
        try
        {
            _ui.Invoke(() =>
            {
                if (_source is null) return;
                RemoveClipboardFormatListener(_source.Handle);
                _source.Dispose();
                _source = null;
            });
        }
        catch (Exception e) when (e is TaskCanceledException or InvalidOperationException) { /* app shutting down */ }
    }

    [DllImport("user32.dll", SetLastError = true)] private static extern bool AddClipboardFormatListener(IntPtr hwnd);
    [DllImport("user32.dll", SetLastError = true)] private static extern bool RemoveClipboardFormatListener(IntPtr hwnd);
}
