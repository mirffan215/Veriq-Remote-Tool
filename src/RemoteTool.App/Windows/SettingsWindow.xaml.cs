using System.Windows;
using RemoteTool.App.Localization;
using RemoteTool.App.Services;
using RemoteTool.Core.Config;
using RemoteTool.Core.Relay;
using RemoteTool.Core.Security;
using RemoteTool.Core.Session;

namespace RemoteTool.App.Windows;

/// <summary>Everything that is NOT part of the everyday "enter address, connect" flow. Nothing here is required for normal use.</summary>
public partial class SettingsWindow : Window
{
    private readonly SettingsStore _store;
    private readonly ISecretProtector _protector;
    private readonly HostController _host;
    private readonly PermanentPasswordStore _access;

    public SettingsWindow(SettingsStore store, ISecretProtector protector, HostController host, PermanentPasswordStore access)
    {
        InitializeComponent();
        FlowDirection = Loc.Flow;
        _store = store;
        _protector = protector;
        _host = host;
        _access = access;
        var s = _store.Current;
        DisplayNameBox.Text = s.DisplayName;
        ViewOnlyBox.IsChecked = s.ViewOnly;
        ClipboardBox.IsChecked = s.AllowClipboard;
        FilesBox.IsChecked = s.AllowFileTransfer;
        H264Box.IsChecked = s.EnableH264;
        LangSystem.IsChecked = s.Language != "en" && s.Language != "ar";
        LangEn.IsChecked = s.Language == "en";
        LangAr.IsChecked = s.Language == "ar";
        RelayAddressBox.Text = s.RelayAddress;
        RelayFingerprintBox.Text = s.RelayFingerprint;
        DirectBox.IsChecked = s.DirectListenerEnabled;
        LanVisibleBox.IsChecked = s.LanVisible;
        LanFirstBox.IsChecked = s.LanFirst;
        DirectPortBox.Text = s.DirectPort.ToString();
        AllowListBox.Text = string.Join(", ", s.IpAllowList);
        ThemeSystem.IsChecked = s.Theme != "Light" && s.Theme != "Dark";
        ThemeLight.IsChecked = s.Theme == "Light";
        ThemeDark.IsChecked = s.Theme == "Dark";
        PasswordText.Text = _host.Service.Password;
        RefreshAccess();
    }

    private void RefreshAccess()
    {
        AccessState.Text = Loc.T(_access.Enabled ? "Access_On" : "Access_Off");
        AccessClearButton.IsEnabled = _access.Enabled;
    }

    private void AccessSet_Click(object sender, RoutedEventArgs e)
    {
        var pw = AccessPwBox.Password;
        var problem = PermanentPasswordStore.Validate(pw);
        if (problem is not null) { SettingsStatus.Text = problem; return; }
        _access.Set(pw);
        AccessPwBox.Clear();
        _host.AuditSettingsChanged();
        RefreshAccess();
        SettingsStatus.Text = Loc.T("Saved");
    }

    private void AccessClear_Click(object sender, RoutedEventArgs e)
    {
        _access.Clear();
        _host.AuditSettingsChanged();
        RefreshAccess();
    }

    private void CopyPassword_Click(object sender, RoutedEventArgs e)
    {
        try { Clipboard.SetText(_host.Service.Password); } catch (System.Runtime.InteropServices.COMException) { }
    }

    private void RefreshPassword_Click(object sender, RoutedEventArgs e)
    {
        _host.Service.RotatePassword();
        PasswordText.Text = _host.Service.Password;
    }

    /// <summary>Relaunches this exe elevated (UAC) in service-setup mode. The normal UI never runs with admin rights.</summary>
    private void ServiceSetup_Click(object sender, RoutedEventArgs e)
    {
        try { System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(Environment.ProcessPath!, "--service-setup") { UseShellExecute = true, Verb = "runas" }); }
        catch (System.ComponentModel.Win32Exception) { /* user declined the UAC prompt */ }
    }

    /// <summary>Starts this exe elevated (UAC) to add/remove the Windows Firewall rules. The arguments are fixed words and a validated port number, never user text.</summary>
    private void RunFirewall(string action)
    {
        var args = $"--firewall {action}" + (action == "add" && FirewallWideBox.IsChecked == true ? " --wide" : "") + $" --port {_store.Current.DirectPort}";
        try { System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(Environment.ProcessPath!, args) { UseShellExecute = true, Verb = "runas" }); }
        catch (System.ComponentModel.Win32Exception) { /* user declined the UAC prompt */ }
    }

    private void FirewallAdd_Click(object sender, RoutedEventArgs e) => RunFirewall("add");
    private void FirewallRemove_Click(object sender, RoutedEventArgs e) => RunFirewall("remove");

    private void ClearKey_Click(object sender, RoutedEventArgs e) { _store.Current.RelayAccessKeyProtected = ""; RelayKeyBox.Clear(); _store.Save(); _host.ApplySettings(); }

    private void GenerateId_Click(object sender, RoutedEventArgs e)
    {
        if (MessageBox.Show(this, Loc.T("New_Id_Confirm"), Loc.T("App_Title"), MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes) return;
        _store.RegenerateId();
        _host.RestartRelayRegistration();
    }

    private void Close_Click(object sender, RoutedEventArgs e) => Close();

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
        s.LanVisible = LanVisibleBox.IsChecked == true && s.DirectListenerEnabled;
        s.LanFirst = LanFirstBox.IsChecked == true;
        s.DirectPort = port;
        s.IpAllowList = AllowListBox.Text.Split(new[] { ',', ';', ' ' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();
        s.Theme = ThemeDark.IsChecked == true ? "Dark" : ThemeLight.IsChecked == true ? "Light" : "System";
        _store.Save();
        ThemeManager.Apply(s.Theme);
        _host.AuditSettingsChanged();
        if (portChanged) _host.RestartDirectListener(); else _host.ApplySettings();
        SettingsStatus.Text = _host.LastError is { } err ? Loc.F("Err_Listen", err) : Loc.T("Saved");
    }
}
