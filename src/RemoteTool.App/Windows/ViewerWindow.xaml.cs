using System.Diagnostics;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using RemoteTool.App.Localization;
using RemoteTool.Capture;
using RemoteTool.Core.Protocol;
using RemoteTool.Core.Session;

namespace RemoteTool.App.Windows;

/// <summary>Remote screen view: decodes tile updates into a WriteableBitmap and forwards mouse/keyboard to the host.</summary>
public partial class ViewerWindow : Window
{
    private readonly ViewerSession _session;
    private readonly HashSet<(ushort vk, bool ext)> _keysDown = new();
    private readonly DispatcherTimer _statsTimer = new() { Interval = TimeSpan.FromSeconds(1) };
    private WriteableBitmap? _bitmap;
    private bool _fit = true;
    private bool _closing;
    private int _frames;
    private long _lastBytes;
    private long _lastMove;

    public ViewerWindow(ViewerSession session)
    {
        InitializeComponent();
        FlowDirection = Loc.Flow;
        _session = session;
        Title = $"{session.HostName} - RemoteTool";
        ViewOnlyLabel.Visibility = (session.Permissions & Permissions.Control) == 0 ? Visibility.Visible : Visibility.Collapsed;
        session.FrameReceived += OnFrame;
        session.CursorChanged += OnCursor;
        session.Ended += OnEnded;
        _statsTimer.Tick += (_, _) => UpdateStats();
        _statsTimer.Start();
        Deactivated += (_, _) => ReleaseAllKeys(); // never leave a key held on the remote machine
        Closing += OnClosing;
        session.Start(); // after all subscriptions: the first keyframe must not be missed
    }

    // ---- rendering ----------------------------------------------------------------------------

    private void OnFrame(FrameUpdateMessage f)
    {
        // Decode off the UI thread, then apply synchronously: natural back-pressure instead of unbounded queues.
        var decoded = new List<(TileRect rect, byte[] pixels)>(f.Rects.Count);
        try
        {
            foreach (var r in f.Rects)
            {
                var px = JpegCodec.Decode(r.Jpeg, out var w, out var h);
                if (w != r.Width || h != r.Height) throw new InvalidDataException("tile size mismatch");
                decoded.Add((r, px));
            }
        }
        catch (InvalidDataException)
        {
            Dispatcher.InvokeAsync(() => EndLocally("invalid image data"));
            return;
        }
        try { Dispatcher.Invoke(() => Apply(f, decoded), DispatcherPriority.Render); }
        catch (TaskCanceledException) { }
    }

    private void Apply(FrameUpdateMessage f, List<(TileRect rect, byte[] pixels)> tiles)
    {
        if (_closing) return;
        if (_bitmap is null || _bitmap.PixelWidth != f.Width || _bitmap.PixelHeight != f.Height)
        {
            _bitmap = new WriteableBitmap(f.Width, f.Height, 96, 96, PixelFormats.Bgra32, null);
            Screen.Source = _bitmap;
            UpdateImageSize();
        }
        foreach (var (r, px) in tiles)
            _bitmap.WritePixels(new Int32Rect(r.X, r.Y, r.Width, r.Height), px, r.Width * 4, 0);
        _frames++;
    }

    private void UpdateImageSize()
    {
        if (_bitmap is null) return;
        double bw = _bitmap.PixelWidth, bh = _bitmap.PixelHeight;
        if (_fit)
        {
            var scale = Math.Min(Scroller.ViewportWidth / bw, Scroller.ViewportHeight / bh);
            if (double.IsNaN(scale) || scale <= 0 || double.IsInfinity(scale)) return;
            Screen.Width = bw * scale;
            Screen.Height = bh * scale;
        }
        else
        {
            var dpi = VisualTreeHelper.GetDpi(this);
            Screen.Width = bw / dpi.DpiScaleX; // 1 remote pixel = 1 physical pixel
            Screen.Height = bh / dpi.DpiScaleY;
        }
    }

    private void Scroller_SizeChanged(object sender, SizeChangedEventArgs e) => UpdateImageSize();

    private void Fit_Click(object sender, RoutedEventArgs e)
    {
        _fit = !_fit;
        FitButton.Content = Loc.T(_fit ? "Viewer_Actual" : "Viewer_Fit");
        UpdateImageSize();
    }

    private void Full_Click(object sender, RoutedEventArgs e)
    {
        if (WindowState == WindowState.Maximized && WindowStyle == WindowStyle.None) { WindowStyle = WindowStyle.SingleBorderWindow; WindowState = WindowState.Normal; }
        else { WindowStyle = WindowStyle.None; WindowState = WindowState.Maximized; }
    }

    private void Disconnect_Click(object sender, RoutedEventArgs e) => Close();

    private void OnCursor(CursorShape s) => Dispatcher.InvokeAsync(() => Screen.Cursor = s switch
    {
        CursorShape.IBeam => Cursors.IBeam, CursorShape.Wait => Cursors.Wait, CursorShape.Cross => Cursors.Cross, CursorShape.Hand => Cursors.Hand,
        CursorShape.SizeNS => Cursors.SizeNS, CursorShape.SizeWE => Cursors.SizeWE, CursorShape.SizeNWSE => Cursors.SizeNWSE,
        CursorShape.SizeNESW => Cursors.SizeNESW, CursorShape.SizeAll => Cursors.SizeAll, CursorShape.No => Cursors.No,
        CursorShape.AppStarting => Cursors.AppStarting, CursorShape.Help => Cursors.Help, CursorShape.Hidden => Cursors.None,
        _ => Cursors.Arrow,
    });

    private void UpdateStats()
    {
        var bytes = _session.BytesReceived;
        var kbps = (bytes - _lastBytes) / 1024;
        _lastBytes = bytes;
        StatsText.Text = Loc.F("Viewer_Stats", _frames, (int)_session.Latency.TotalMilliseconds, kbps);
        _frames = 0;
    }

    // ---- input --------------------------------------------------------------------------------

    private bool Normalize(MouseEventArgs e, out ushort nx, out ushort ny)
    {
        nx = ny = 0;
        if (Screen.ActualWidth < 1 || Screen.ActualHeight < 1) return false;
        var p = e.GetPosition(Screen);
        nx = (ushort)Math.Round(Math.Clamp(p.X / Screen.ActualWidth, 0, 1) * 65535);
        ny = (ushort)Math.Round(Math.Clamp(p.Y / Screen.ActualHeight, 0, 1) * 65535);
        return true;
    }

    private void Screen_MouseMove(object sender, MouseEventArgs e)
    {
        var now = Stopwatch.GetTimestamp();
        if (Stopwatch.GetElapsedTime(_lastMove, now) < TimeSpan.FromMilliseconds(8)) return; // ~120 Hz cap
        _lastMove = now;
        if (Normalize(e, out var x, out var y)) _ = _session.SendMouseAsync(new MouseEventMessage(MouseKind.Move, MouseButton.None, x, y, 0));
    }

    private void Screen_MouseButton(object sender, MouseButtonEventArgs e)
    {
        var down = e.ButtonState == MouseButtonState.Pressed;
        var button = e.ChangedButton switch
        {
            System.Windows.Input.MouseButton.Left => Core.Protocol.MouseButton.Left,
            System.Windows.Input.MouseButton.Right => Core.Protocol.MouseButton.Right,
            System.Windows.Input.MouseButton.Middle => Core.Protocol.MouseButton.Middle,
            System.Windows.Input.MouseButton.XButton1 => Core.Protocol.MouseButton.X1,
            System.Windows.Input.MouseButton.XButton2 => Core.Protocol.MouseButton.X2,
            _ => Core.Protocol.MouseButton.None,
        };
        if (button == Core.Protocol.MouseButton.None || !Normalize(e, out var x, out var y)) return;
        if (down) { Focus(); Screen.CaptureMouse(); } else Screen.ReleaseMouseCapture();
        _ = _session.SendMouseAsync(new MouseEventMessage(down ? MouseKind.Down : MouseKind.Up, button, x, y, 0));
        e.Handled = true;
    }

    private void Screen_MouseWheel(object sender, MouseWheelEventArgs e)
    {
        if (Normalize(e, out var x, out var y))
            _ = _session.SendMouseAsync(new MouseEventMessage(MouseKind.Wheel, Core.Protocol.MouseButton.None, x, y, Math.Clamp(e.Delta, -12000, 12000)));
        e.Handled = true;
    }

    private static readonly HashSet<Key> ExtendedKeys = new()
    {
        Key.Up, Key.Down, Key.Left, Key.Right, Key.Insert, Key.Delete, Key.Home, Key.End, Key.PageUp, Key.PageDown,
        Key.RightCtrl, Key.RightAlt, Key.Divide, Key.LWin, Key.RWin, Key.Apps, Key.PrintScreen, Key.NumLock,
    };

    protected override void OnPreviewKeyDown(KeyEventArgs e) { Forward(e, up: false); base.OnPreviewKeyDown(e); }
    protected override void OnPreviewKeyUp(KeyEventArgs e) { Forward(e, up: true); base.OnPreviewKeyUp(e); }

    private void Forward(KeyEventArgs e, bool up)
    {
        var key = e.Key switch { Key.System => e.SystemKey, Key.ImeProcessed => e.ImeProcessedKey, Key.DeadCharProcessed => e.DeadCharProcessedKey, _ => e.Key };
        var vk = KeyInterop.VirtualKeyFromKey(key);
        if (vk is <= 0 or > 254) return;
        var ext = ExtendedKeys.Contains(key);
        if (up) _keysDown.Remove(((ushort)vk, ext)); else _keysDown.Add(((ushort)vk, ext));
        _ = _session.SendKeyAsync(new KeyEventMessage((ushort)vk, up, ext));
        e.Handled = true; // keep Alt/F10/Tab etc. from acting on the viewer's own window
    }

    private void ReleaseAllKeys()
    {
        foreach (var (vk, ext) in _keysDown.ToList()) _ = _session.SendKeyAsync(new KeyEventMessage(vk, true, ext));
        _keysDown.Clear();
    }

    // ---- lifetime -----------------------------------------------------------------------------

    private void OnEnded(ByeReason reason, string text) => Dispatcher.InvokeAsync(() => EndLocally(reason.ToString()));

    private void EndLocally(string reason)
    {
        if (_closing) return;
        _closing = true;
        _statsTimer.Stop();
        MessageBox.Show(this, Loc.F("Session_Ended", reason), Loc.T("App_Title"), MessageBoxButton.OK, MessageBoxImage.Information);
        Close();
    }

    private void OnClosing(object? sender, System.ComponentModel.CancelEventArgs e)
    {
        _closing = true;
        _statsTimer.Stop();
        ReleaseAllKeys();
        _ = _session.DisposeAsync().AsTask();
    }
}
