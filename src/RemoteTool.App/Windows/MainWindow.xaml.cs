using System.Windows;
using System.Windows.Input;
using RemoteTool.App.Localization;
using RemoteTool.App.Services;
using RemoteTool.Core.Config;
using RemoteTool.Core.Relay;
using RemoteTool.Core.Session;

namespace RemoteTool.App.Windows;

public partial class MainWindow : Window
{
    private readonly SettingsStore _store;
    private readonly ISecretProtector _protector;
    private readonly HostController _host;
    private readonly ViewerLauncher _viewer;
    private CancellationTokenSource? _connectCts;

    public MainWindow(SettingsStore store, ISecretProtector protector, HostController host, ViewerLauncher viewer)
    {
        InitializeComponent();
        FlowDirection = Loc.Flow;
        _store = store;
        _protector = protector;
        _host = host;
        _viewer = viewer;
        LoadSettingsIntoUi();
        RefreshState();
        _host.StateChanged += RefreshState;
        Closing += (_, _) => _connectCts?.Cancel();
    }

    private void LoadSettingsIntoUi()
    {
        var s = _store.Current;
        DisplayNameBox.Text = s.DisplayName;
        ViewOnlyBox.IsChecked = s.ViewOnly;
        ClipboardBox.IsChecked = s.AllowClipboard;
        FilesBox.IsChecked = s.AllowFileTransfer;
        RelayAddressBox.Text = s.RelayAddress;
        RelayFingerprintBox.Text = s.RelayFingerprint;
        DirectBox.IsChecked = s.DirectListenerEnabled;
        DirectPortBox.Text = s.DirectPort.ToString();
        AllowListBox.Text = string.Join(", ", s.IpAllowList);
        ThemeSystem.IsChecked = s.Theme == "System";
        ThemeLight.IsChecked = s.Theme == "Light";
        ThemeDark.IsChecked = s.Theme == "Dark";
        RefreshRecent();
    }

    private void RefreshRecent() => RecentList.ItemsSource = _store.Current.Recent.Select(r => r.Target).ToList();

    private void RefreshState()
    {
        IdText.Text = ConnectionId.Format(_store.Current.Id);
        PasswordText.Text = _host.Service.Password;
        var (text, color) = _host.Service.RelayStatus switch
        {
            RelayStatus.Online => (Loc.T("Relay_Online"), System.Windows.Media.Brushes.LimeGreen),
            RelayStatus.Connecting => (Loc.T("Relay_Connecting"), System.Windows.Media.Brushes.Orange),
            RelayStatus.AccessDenied => (Loc.T("Relay_Denied"), System.Windows.Media.Brushes.Red),
            RelayStatus.Offline => (Loc.T("Relay_Offline"), System.Windows.Media.Brushes.Red),
            _ => (Loc.T("Relay_Disabled"), System.Windows.Media.Brushes.Gray),
        };
        RelayStatusText.Text = text;
        StatusDot.Fill = color;
        DirectStatusText.Text = _host.Service.DirectListening ? $"Direct (Mode A): listening on port {_store.Current.DirectPort}" : "";
        if (_host.LastError is { } err) SettingsStatus.Text = Loc.F("Err_Listen", err);
    }

    private static void ToClipboard(string text)
    {
        try { Clipboard.SetText(text); } catch (System.Runtime.InteropServices.COMException) { }
    }

    private void CopyId_Click(object sender, RoutedEventArgs e) => ToClipboard(ConnectionId.Format(_store.Current.Id));
    private void CopyPassword_Click(object sender, RoutedEventArgs e) => ToClipboard(_host.Service.Password);
    private void RefreshPassword_Click(object sender, RoutedEventArgs e) => _host.Service.RotatePassword();
    private void ClearKey_Click(object sender, RoutedEventArgs e) { _store.Current.RelayAccessKeyProtected = ""; RelayKeyBox.Clear(); _store.Save(); _host.ApplySettings(); }

    private void GenerateId_Click(object sender, RoutedEventArgs e)
    {
        if (MessageBox.Show(this, Loc.T("New_Id_Confirm"), Loc.T("App_Title"), MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes) return;
        _store.RegenerateId();
        _host.RestartRelayRegistration();
        RefreshState();
    }

    private void Save_Click(object sender, RoutedEventArgs e)
    {
        var s = _store.Current;
        if (!int.TryParse(DirectPortBox.Text, out var port) || port is < 1 or > 65535) { SettingsStatus.Text = Loc.T("Err_Port"); return; }
        var relay = RelayAddressBox.Text.Trim();
        if (relay.Length > 0 && !RelayEndpoint.TryParse(relay, "", "", out _)) { SettingsStatus.Text = Loc.T("Err_Relay"); return; }

        var portChanged = port != s.DirectPort;
        s.DisplayName = NameSanitizer.Clean(DisplayNameBox.Text, Environment.MachineName);
        s.ViewOnly = ViewOnlyBox.IsChecked == true;
        s.AllowClipboard = ClipboardBox.IsChecked == true;
        s.AllowFileTransfer = FilesBox.IsChecked == true;
        s.RelayAddress = relay;
        s.RelayFingerprint = RelayFingerprintBox.Text.Trim();
        if (RelayKeyBox.Password.Length > 0) s.RelayAccessKeyProtected = _protector.Protect(RelayKeyBox.Password);
        RelayKeyBox.Clear();
        s.DirectListenerEnabled = DirectBox.IsChecked == true;
        s.DirectPort = port;
        s.IpAllowList = AllowListBox.Text.Split(new[] { ',', ';', ' ' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();
        s.Theme = ThemeDark.IsChecked == true ? "Dark" : ThemeLight.IsChecked == true ? "Light" : "System";
        _store.Save();
        ThemeManager.Apply(s.Theme);
        _host.AuditSettingsChanged();
        if (portChanged) _host.RestartDirectListener(); else _host.ApplySettings();
        SettingsStatus.Text = _host.LastError is { } err ? Loc.F("Err_Listen", err) : Loc.T("Saved");
        RefreshState();
    }

    private void Recent_DoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (RecentList.SelectedItem is string t) { TargetBox.Text = t; ConnectPasswordBox.Focus(); }
    }

    private async void Connect_Click(object sender, RoutedEventArgs e)
    {
        if (!ConnectTarget.TryParse(TargetBox.Text, out var target)) { ConnectStatus.Text = Loc.T("Err_BadTarget"); return; }
        var password = ConnectPasswordBox.Password;
        ConnectPasswordBox.Clear(); // never keep the password around, never store it
        ConnectButton.IsEnabled = false;
        ConnectStatus.Text = Loc.T("Connecting");
        _connectCts = new CancellationTokenSource();
        try
        {
            var session = await _viewer.ConnectAsync(target!, password, _connectCts.Token);
            _store.AddRecent(target is ConnectTarget.ById b ? ConnectionId.Format(b.Id) : TargetBox.Text.Trim());
            RefreshRecent();
            ConnectStatus.Text = "";
            new ViewerWindow(session).Show();
        }
        catch (ConnectFailedException ex) { ConnectStatus.Text = Loc.F("Err_Failed", ex.Message); }
        catch (OperationCanceledException) { ConnectStatus.Text = ""; }
        finally { ConnectButton.IsEnabled = true; }
    }
}
