using System.Diagnostics;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using RemoteTool.App.Localization;
using RemoteTool.App.Services;
using RemoteTool.Capture;
using RemoteTool.Core.Protocol;
using RemoteTool.Core.Session;

namespace RemoteTool.App.Windows;

/// <summary>Remote screen view: decodes tile updates into a WriteableBitmap and forwards mouse/keyboard to the host.</summary>
public partial class ViewerWindow : Window
{
    private ViewerSession _session;
    private readonly ViewerContext _ctx;
    private readonly CancellationTokenSource _lifetime = new();
    private readonly HashSet<(ushort vk, bool ext)> _keysDown = new();
    private readonly DispatcherTimer _statsTimer = new() { Interval = TimeSpan.FromSeconds(1) };
    private WriteableBitmap? _bitmap;
    private bool _fit = true;
    private bool _closing;
    private int _frames;
    private long _lastBytes;
    private long _lastMove;
    private ScreenInfoMessage? _screen;

    public ViewerWindow(ViewerSession session, ViewerContext ctx)
    {
        InitializeComponent();
        FlowDirection = Loc.Flow;
        _ctx = ctx;
        _session = session;
        _statsTimer.Tick += (_, _) => UpdateStats();
        _statsTimer.Start();
        Deactivated += (_, _) => ReleaseAllKeys(); // never leave a key held on the remote machine
        Closing += OnClosing;
        Attach(session); // subscribes to every event, then starts the session: the first keyframe cannot be missed
    }

    /// <summary>Wires a (new or resumed) session into this window.</summary>
    private void Attach(ViewerSession s)
    {
        _session = s;
        Title = $"{s.HostName} - RemoteTool";
        ViewOnlyLabel.Visibility = (s.Permissions & Permissions.Control) == 0 ? Visibility.Visible : Visibility.Collapsed;
        s.FrameReceived += OnFrame;
        s.FullFrameReceived += OnFullFrame;
        RecLabel.Visibility = s.Recording ? Visibility.Visible : Visibility.Collapsed;
        CadButton.IsEnabled = (s.Permissions & Permissions.Control) != 0;
        if (s.Codec == VideoCodecs.H264 && _ctx.DecoderFactory() is { } decoder) s.AttachH264Decoder(decoder); // no decoder => the session itself asks the host for tiles
        s.CursorChanged += OnCursor;
        s.ScreenInfoReceived += info => Dispatcher.InvokeAsync(() => OnScreenInfo(info));
        s.Ended += (reason, _) => Dispatcher.InvokeAsync(() => OnSessionEnded(s, reason));
        s.FileReceived += path => Dispatcher.InvokeAsync(() => StatusText.Text = Loc.F("File_Received", System.IO.Path.GetFileName(path)));
        if ((s.Permissions & Permissions.Clipboard) != 0) s.AttachClipboard(_ctx.ClipboardFactory());
        s.AttachFileTransfer(_ctx.Prompt, _ctx.FileOptions);
        SendFileButton.IsEnabled = s.CanTransferFiles;
        s.Start();
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

    /// <summary>H.264 path: the session already decoded a whole BGRA frame.</summary>
    private void OnFullFrame(DecodedFrame f)
    {
        try { Dispatcher.Invoke(() => ApplyFull(f), DispatcherPriority.Render); }
        catch (TaskCanceledException) { }
    }

    private void ApplyFull(DecodedFrame f)
    {
        if (_closing) return;
        if (_bitmap is null || _bitmap.PixelWidth != f.Width || _bitmap.PixelHeight != f.Height)
        {
            _bitmap = new WriteableBitmap(f.Width, f.Height, 96, 96, PixelFormats.Bgra32, null);
            Screen.Source = _bitmap;
            UpdateImageSize();
        }
        _bitmap.WritePixels(new Int32Rect(0, 0, f.Width, f.Height), f.Bgra, f.Width * 4, 0);
        _frames++;
    }

    private void Cad_Click(object sender, RoutedEventArgs e) => _ = _session.SendSpecialKeyAsync(SpecialKeyKind.CtrlAltDel);

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
        StatsText.Text = Loc.F("Viewer_Stats", _frames, (int)_session.Latency.TotalMilliseconds, kbps) + (_session.Codec == VideoCodecs.H264 ? " · H.264" : "");
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
        if (Normalize(e, out var x, out var y)) _ = _session.SendMouseAsync(new MouseEventMessage(MouseKind.Move, Core.Protocol.MouseButton.None, x, y, 0));
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

    // ---- monitors, files ----------------------------------------------------------------------

    private void OnScreenInfo(ScreenInfoMessage info)
    {
        _screen = info;
        MonitorButton.Visibility = info.Monitors.Count > 1 ? Visibility.Visible : Visibility.Collapsed;
        MonitorButton.Content = Loc.F("Viewer_Monitor", info.ActiveMonitor + 1);
    }

    private void Monitor_Click(object sender, RoutedEventArgs e)
    {
        if (_screen is null) return;
        var menu = new System.Windows.Controls.ContextMenu { PlacementTarget = MonitorButton };
        foreach (var m in _screen.Monitors)
        {
            var index = m.Index;
            var item = new System.Windows.Controls.MenuItem { Header = Loc.F("Viewer_MonitorItem", m.Index + 1, m.Width, m.Height), IsChecked = m.Index == _screen.ActiveMonitor };
            item.Click += (_, _) => _ = _session.SelectMonitorAsync(index);
            menu.Items.Add(item);
        }
        menu.IsOpen = true;
    }

    private async void SendFile_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new Microsoft.Win32.OpenFileDialog();
        if (dlg.ShowDialog(this) != true) return;
        SendFileButton.IsEnabled = false;
        var progress = new Progress<long>(p => StatusText.Text = $"{p / 1024:N0} KB");
        try
        {
            var outcome = await _session.SendFileAsync(dlg.FileName, progress, _lifetime.Token);
            StatusText.Text = Loc.T(outcome switch
            {
                FileSendOutcome.Completed => "File_Sent", FileSendOutcome.Rejected => "File_Declined", FileSendOutcome.HashMismatch => "File_Hash",
                FileSendOutcome.Cancelled => "File_Cancelled", _ => "File_Failed",
            });
        }
        finally { if (!_closing) SendFileButton.IsEnabled = _session.CanTransferFiles; }
    }

    // ---- lifetime / reconnect -----------------------------------------------------------------

    private async void OnSessionEnded(ViewerSession ended, ByeReason reason)
    {
        if (_closing || !ReferenceEquals(ended, _session)) return; // stale event from a replaced session
        if (ViewerReconnect.IsRecoverable(reason) && ended.ResumeToken.Length > 0) { await TryReconnectAsync(ended); return; }
        EndLocally(reason.ToString());
    }

    private async Task TryReconnectAsync(ViewerSession lost)
    {
        ReleaseAllKeysLocal();
        ReconnectText.Visibility = Visibility.Visible;
        ReconnectText.Text = Loc.F("Viewer_Reconnecting", 1);
        try
        {
            var next = await ViewerReconnect.ResumeAsync(_ctx.Redial, _ctx.ViewerName, lost.ResumeToken, _ctx.Audit, Permissions.All, _lifetime.Token,
                onAttempt: n => Dispatcher.InvokeAsync(() => ReconnectText.Text = Loc.F("Viewer_Reconnecting", n)));
            if (_closing) { await next.DisposeAsync(); return; }
            _ = lost.DisposeAsync().AsTask();
            Attach(next);
            ReconnectText.Visibility = Visibility.Collapsed;
        }
        catch (ConnectFailedException) { EndLocally("connection lost"); }
        catch (OperationCanceledException) { }
    }

    private void EndLocally(string reason)
    {
        if (_closing) return;
        _closing = true;
        _statsTimer.Stop();
        MessageBox.Show(this, Loc.F("Session_Ended", reason), Loc.T("App_Title"), MessageBoxButton.OK, MessageBoxImage.Information);
        Close();
    }

    private void ReleaseAllKeysLocal() => _keysDown.Clear(); // connection is gone; the host already released its side

    private void OnClosing(object? sender, System.ComponentModel.CancelEventArgs e)
    {
        _closing = true;
        _statsTimer.Stop();
        _lifetime.Cancel();
        ReleaseAllKeys();
        _ = _session.DisposeAsync().AsTask();
    }
}
