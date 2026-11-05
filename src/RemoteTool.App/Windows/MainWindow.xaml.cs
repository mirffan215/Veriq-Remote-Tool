using System.Windows;
using System.Windows.Input;
using RemoteTool.App.Localization;
using RemoteTool.App.Services;
using RemoteTool.Core.Config;
using RemoteTool.Core.Relay;
using RemoteTool.Core.Security;
using RemoteTool.Core.Session;
using RemoteTool.Service;

namespace RemoteTool.App.Windows;

/// <summary>
/// The everyday screen: "Your Address" at the top, a box for the other side's address, Connect. The person at the other end gets an Accept prompt;
/// a password is only for the (optional) case where someone gave you one. Everything technical lives behind the Settings button.
/// </summary>
public partial class MainWindow : Window
{
    private readonly SettingsStore _store;
    private readonly ISecretProtector _protector;
    private readonly PermanentPasswordStore _access;
    private readonly HostController _host;
    private readonly ViewerLauncher _viewer;
    private CancellationTokenSource? _connectCts;

    public MainWindow(SettingsStore store, ISecretProtector protector, HostController host, ViewerLauncher viewer, PermanentPasswordStore access)
    {
        InitializeComponent();
        FlowDirection = Loc.Flow;
        _store = store;
        _protector = protector;
        _host = host;
        _viewer = viewer;
        _access = access;
        RefreshRecent();
        RefreshAddresses();
        RefreshState();
        _host.StateChanged += RefreshState;
        Closing += (_, _) => _connectCts?.Cancel();
        Loaded += (_, _) => TargetBox.Focus();
    }

    // ---- "Your address" card ------------------------------------------------------------------------------

    private void RefreshState()
    {
        var svc = _host.ServiceManaged ? ServiceStatus.Read() : null;
        if (svc is not null)
        {
            IdText.Text = ConnectionId.Format(svc.Id);
            StatusText.Text = Loc.F("Svc_Managed", ConnectionId.Format(svc.Id), Loc.T(svc.UnattendedEnabled ? "Svc_On" : "Svc_Off"));
            StatusDot.Fill = svc.Relay == "Online" ? System.Windows.Media.Brushes.LimeGreen : System.Windows.Media.Brushes.Orange;
            return;
        }
        IdText.Text = ConnectionId.Format(_store.Current.Id);
        var (text, color) = _host.Service.RelayStatus switch
        {
            RelayStatus.Online => (Loc.T("Status_Ready"), System.Windows.Media.Brushes.LimeGreen),
            RelayStatus.Connecting => (Loc.T("Status_Connecting"), System.Windows.Media.Brushes.Orange),
            RelayStatus.AccessDenied => (Loc.T("Status_Denied"), System.Windows.Media.Brushes.Red),
            RelayStatus.Offline => (Loc.T("Status_Offline"), System.Windows.Media.Brushes.Red),
            _ => _host.Service.DirectListening ? (Loc.T("Status_LanOnly"), System.Windows.Media.Brushes.LimeGreen) : (Loc.T("Status_NotConfigured"), System.Windows.Media.Brushes.Orange),
        };
        StatusText.Text = text;
        StatusDot.Fill = color;
    }

    private void CopyId_Click(object sender, RoutedEventArgs e)
    {
        try { Clipboard.SetText(ConnectionId.Format(_store.Current.Id)); } catch (System.Runtime.InteropServices.COMException) { }
    }

    private void Settings_Click(object sender, RoutedEventArgs e)
    {
        new SettingsWindow(_store, _protector, _host, _access) { Owner = this }.ShowDialog();
        RefreshState();
    }

    // ---- connecting ---------------------------------------------------------------------------------------

    private async void Connect_Click(object sender, RoutedEventArgs e)
    {
        if (!ConnectTarget.TryParse(TargetBox.Text, out var target)) { ConnectStatus.Text = Loc.T("Err_BadTarget"); return; }
        var password = ConnectPasswordBox.Password;
        ConnectPasswordBox.Clear();                                    // never keep, never store a password
        var mode = password.Length > 0 ? ConnectMode.Password : ConnectMode.Request;

        ConnectButton.Visibility = Visibility.Collapsed;
        CancelButton.Visibility = Visibility.Visible;
        ConnectStatus.Text = Loc.T("Connecting");
        _connectCts = new CancellationTokenSource();
        try
        {
            var (session, ctx) = await _viewer.ConnectAsync(target!, password, mode,
                code => Dispatcher.InvokeAsync(() => ConnectStatus.Text = Loc.F("Waiting_Accept", code)), _connectCts.Token);
            _store.AddRecent(target is ConnectTarget.ById b ? ConnectionId.Format(b.Id) : TargetBox.Text.Trim());
            RefreshRecent();
            ConnectStatus.Text = "";
            new ViewerWindow(session, ctx).Show();
        }
        catch (ConnectFailedException ex) when (ex.Failure == ConnectFailure.PasswordRequired)
        {
            PasswordExpander.IsExpanded = true;                         // this PC wants a password: open the box and say so
            ConnectPasswordBox.Focus();
            ConnectStatus.Text = Loc.T("Err_PasswordNeeded");
        }
        catch (ConnectFailedException ex) { ConnectStatus.Text = Loc.F("Err_Failed", ex.Message); }
        catch (OperationCanceledException) { ConnectStatus.Text = ""; }
        finally
        {
            CancelButton.Visibility = Visibility.Collapsed;
            ConnectButton.Visibility = Visibility.Visible;
        }
    }

    private void Cancel_Click(object sender, RoutedEventArgs e) => _connectCts?.Cancel();

    // ---- recent / address book / this network -------------------------------------------------------------

    private void RefreshRecent() => RecentList.ItemsSource = _store.Current.Recent.Select(r => r.Target).ToList();

    private void Recent_DoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (RecentList.SelectedItem is string t) { TargetBox.Text = t; TargetBox.Focus(); }
    }

    private sealed record AddrItem(string Target, string Nickname, string Label) { public override string ToString() => Label; }

    private void RefreshAddresses() => AddressList.ItemsSource = _store.Current.AddressBook
        .Select(a => new AddrItem(a.Target, a.Nickname, a.Nickname.Length > 0 ? $"{a.Nickname}  -  {a.Target}" : a.Target)).ToList();

    private void Address_DoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (AddressList.SelectedItem is not AddrItem i) return;
        TargetBox.Text = i.Target;
        NicknameBox.Text = i.Nickname;
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

    /// <summary>Discovery results are hints only: choosing one just fills in ip:port - the other person still has to accept (or you need a password).</summary>
    private void LanList_DoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (LanList.SelectedItem is LanItem i) { TargetBox.Text = i.Endpoint; TargetBox.Focus(); }
    }
}
