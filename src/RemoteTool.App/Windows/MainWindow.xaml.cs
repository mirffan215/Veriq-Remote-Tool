using RemoteTool.Service;
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
        H264Box.IsChecked = s.EnableH264;
        LangSystem.IsChecked = s.Language == "System" || (s.Language != "en" && s.Language != "ar");
        LangEn.IsChecked = s.Language == "en";
        LangAr.IsChecked = s.Language == "ar";
        RelayAddressBox.Text = s.RelayAddress;
        RelayFingerprintBox.Text = s.RelayFingerprint;
        DirectBox.IsChecked = s.DirectListenerEnabled;
        LanVisibleBox.IsChecked = s.LanVisible;
        LanFirstBox.IsChecked = s.LanFirst;
        DirectPortBox.Text = s.DirectPort.ToString();
        AllowListBox.Text = string.Join(", ", s.IpAllowList);
        ThemeSystem.IsChecked = s.Theme == "System";
        ThemeLight.IsChecked = s.Theme == "Light";
        ThemeDark.IsChecked = s.Theme == "Dark";
        RefreshRecent();
        RefreshAddresses();
    }

    private sealed record LanItem(string Endpoint, string Label) { public override string ToString() => Label; }

    private async void LanFind_Click(object sender, RoutedEventArgs e)
    {
        LanFindButton.IsEnabled = false;
        LanStatus.Text = "  " + Loc.T("Lan_Searching");
        try
        {
            var hosts = await _viewer.FindLanHostsAsync(CancellationToken.None);
            LanList.ItemsSource = hosts.Select(h => new LanItem(h.Endpoint, Loc.F("Lan_Item", h.Name, ConnectionId.Format(h.Id), h.Endpoint))).ToList();
            LanStatus.Text = hosts.Count == 0 ? "  " + Loc.T("Lan_None") : "";
        }
        finally { LanFindButton.IsEnabled = true; }
    }

    /// <summary>Discovery results are hints only: choosing one just fills in ip:port - the password handshake still decides.</summary>
    private void LanList_DoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (LanList.SelectedItem is LanItem i) { TargetBox.Text = i.Endpoint; ConnectPasswordBox.Focus(); }
    }

    private sealed record AddrItem(string Target, string Nickname, string Label) { public override string ToString() => Label; }

    private void RefreshAddresses() => AddressList.ItemsSource = _store.Current.AddressBook
        .Select(a => new AddrItem(a.Target, a.Nickname, a.Nickname.Length > 0 ? $"{a.Nickname}  -  {a.Target}" : a.Target)).ToList();

    private void Address_DoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (AddressList.SelectedItem is not AddrItem i) return;
        TargetBox.Text = i.Target;
        NicknameBox.Text = i.Nickname;
        ConnectPasswordBox.Focus();
    }

    private void AddrSave_Click(object sender, RoutedEventArgs e)
    {
        if (!ConnectTarget.TryParse(TargetBox.Text, out var t)) { ConnectStatus.Text = Loc.T("Err_BadTarget"); return; }
        _store.UpsertAddress(t is ConnectTarget.ById b ? ConnectionId.Format(b.Id) : TargetBox.Text.Trim(), NicknameBox.Text);
        RefreshAddresses();
    }

    private void AddrRemove_Click(object sender, RoutedEventArgs e)
    {
        if (AddressList.SelectedItem is AddrItem i && _store.RemoveAddress(i.Target)) RefreshAddresses();
    }

    private void RefreshRecent() => RecentList.ItemsSource = _store.Current.Recent.Select(r => r.Target).ToList();

    private void RefreshState()
    {
        var svc = _host.ServiceManaged ? ServiceStatus.Read() : null;
        if (svc is not null)
        {
            // The Windows service owns this PC's identity: show ITS ID; there is no one-time password in service mode.
            IdText.Text = ConnectionId.Format(svc.Id);
            PasswordText.Text = "—";
            ServiceNote.Text = Loc.F("Svc_Managed", ConnectionId.Format(svc.Id), Loc.T(svc.UnattendedEnabled ? "Svc_On" : "Svc_Off"));
            RelayStatusText.Text = "Relay: " + svc.Relay;
            StatusDot.Fill = svc.Relay == "Online" ? System.Windows.Media.Brushes.LimeGreen : System.Windows.Media.Brushes.Orange;
            DirectStatusText.Text = "";
            return;
        }
        ServiceNote.Text = "";
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
    /// <summary>Relaunches this exe elevated (UAC) in service-setup mode. The normal UI never runs with admin rights.</summary>
    private void ServiceSetup_Click(object sender, RoutedEventArgs e)
    {
        try { System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(Environment.ProcessPath!, "--service-setup") { UseShellExecute = true, Verb = "runas" }); }
        catch (System.ComponentModel.Win32Exception) { /* user declined the UAC prompt */ }
    }

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
        if (relay.Length > 0 && !RelayEndpoint.TryParseList(relay, "", "", out _)) { SettingsStatus.Text = Loc.T("Err_Relay"); return; }

        var portChanged = port != s.DirectPort;
        s.DisplayName = NameSanitizer.Clean(DisplayNameBox.Text, Environment.MachineName);
        s.ViewOnly = ViewOnlyBox.IsChecked == true;
        s.AllowClipboard = ClipboardBox.IsChecked == true;
        s.AllowFileTransfer = FilesBox.IsChecked == true;
        s.EnableH264 = H264Box.IsChecked == true;
        s.Language = LangAr.IsChecked == true ? "ar" : LangEn.IsChecked == true ? "en" : "System";
        s.RelayAddress = relay;
        s.RelayFingerprint = RelayFingerprintBox.Text.Trim();
        if (RelayKeyBox.Password.Length > 0) s.RelayAccessKeyProtected = _protector.Protect(RelayKeyBox.Password);
        RelayKeyBox.Clear();
        s.DirectListenerEnabled = DirectBox.IsChecked == true;
        s.LanVisible = LanVisibleBox.IsChecked == true && s.DirectListenerEnabled;   // visibility needs the listener
        s.LanFirst = LanFirstBox.IsChecked == true;
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
            var (session, ctx) = await _viewer.ConnectAsync(target!, password, UnattendedBox.IsChecked == true, _connectCts.Token);
            _store.AddRecent(target is ConnectTarget.ById b ? ConnectionId.Format(b.Id) : TargetBox.Text.Trim());
            RefreshRecent();
            ConnectStatus.Text = "";
            new ViewerWindow(session, ctx).Show();
        }
        catch (ConnectFailedException ex) { ConnectStatus.Text = Loc.F("Err_Failed", ex.Message); }
        catch (OperationCanceledException) { ConnectStatus.Text = ""; }
        finally { ConnectButton.IsEnabled = true; }
    }
}
