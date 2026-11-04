using System.Windows;
using RemoteTool.App.Localization;
using RemoteTool.App.Services;
using RemoteTool.Core.Security;
using RemoteTool.Service;
using RemoteTool.Service.Windows;

namespace RemoteTool.App.Windows;

/// <summary>Runs elevated (<c>--service-setup</c>). Everything it writes lands in ACL-protected machine folders.</summary>
public partial class ServiceSetupWindow : Window
{
    public ServiceSetupWindow()
    {
        InitializeComponent();
        FlowDirection = Loc.Flow;
        LoadCurrent();
    }

    private void LoadCurrent()
    {
        var paths = ServicePaths.Default();
        try
        {
            var cfg = new ServiceConfigStore(paths.ConfigFile).Load();
            NameBox.Text = cfg.DisplayName; RelayBox.Text = cfg.RelayAddress; FingerprintBox.Text = cfg.RelayFingerprint;
            EnabledBox.IsChecked = cfg.UnattendedEnabled; ConsentBox.IsChecked = cfg.ConsentWhenUserPresent;
            RecordBox.IsChecked = cfg.RecordSessions; RetentionBox.Text = cfg.RecordingRetentionDays.ToString();
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { NameBox.Text = Environment.MachineName; }
        var state = ServiceInstaller.IsInstalled() ? (ServiceInstaller.IsRunning() ? Loc.T("Svc_Running") : Loc.T("Svc_Stopped")) : Loc.T("Svc_NotInstalled");
        StatusText.Text = Loc.F("Svc_Status", state);
    }

    private async void Apply_Click(object sender, RoutedEventArgs e)
    {
        if (Pw1Box.Password != Pw2Box.Password) { ResultText.Text = Loc.T("Svc_Mismatch"); return; }
        if (Pw1Box.Password.Length > 0 && PermanentPasswordStore.Validate(Pw1Box.Password) is { } problem) { ResultText.Text = problem; return; }
        var input = new ServiceSetupInput(RelayBox.Text, KeyBox.Password, FingerprintBox.Text, NameBox.Text, EnabledBox.IsChecked == true,
            ConsentBox.IsChecked == true, RecordBox.IsChecked == true, int.TryParse(RetentionBox.Text, out var d) ? d : 30, Pw1Box.Password);
        ApplyButton.IsEnabled = false;
        ResultText.Text = "…";
        try
        {
            await Task.Run(() => ServiceSetup.Apply(input, _ => { }));
            Pw1Box.Clear(); Pw2Box.Clear(); KeyBox.Clear();
            ResultText.Text = Loc.T("Svc_Done");
            LoadCurrent();
        }
        catch (Exception ex) when (ex is InvalidOperationException or UnauthorizedAccessException or IOException or ArgumentException)
        {
            ResultText.Text = ex.Message;
        }
        finally { ApplyButton.IsEnabled = true; }
    }

    private async void Uninstall_Click(object sender, RoutedEventArgs e)
    {
        if (MessageBox.Show(this, Loc.T("Svc_Confirm_Uninstall"), Loc.T("App_Title"), MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No) != MessageBoxResult.Yes) return;
        var purge = PurgeBox.IsChecked == true;
        try
        {
            await Task.Run(() => ServiceInstaller.Uninstall(ServicePaths.Default(), purge, _ => { }));
            ResultText.Text = Loc.T("Svc_Done");
            LoadCurrent();
        }
        catch (Exception ex) when (ex is InvalidOperationException or UnauthorizedAccessException or IOException) { ResultText.Text = ex.Message; }
    }
}
