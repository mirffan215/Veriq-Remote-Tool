using System.Windows;
using System.Windows.Threading;
using RemoteTool.App.Localization;

namespace RemoteTool.App.Windows;

/// <summary>Always-on-top "being controlled" indicator (requirement 2.6).</summary>
public partial class BannerWindow : Window
{
    private readonly Action _disconnect;
    private readonly DispatcherTimer _keepOnTop = new() { Interval = TimeSpan.FromSeconds(2) };

    public BannerWindow(string viewerName, Action disconnect)
    {
        InitializeComponent();
        FlowDirection = Loc.Flow;
        _disconnect = disconnect;
        Message.Text = Loc.F("Banner_Text", viewerName);
        SizeChanged += (_, _) => { Left = (SystemParameters.PrimaryScreenWidth - ActualWidth) / 2; Top = 0; };
        // Re-assert Topmost so another topmost window cannot permanently cover the indicator.
        _keepOnTop.Tick += (_, _) => { Topmost = false; Topmost = true; };
        Loaded += (_, _) => _keepOnTop.Start();
        Closed += (_, _) => _keepOnTop.Stop();
    }

    private void Disconnect_Click(object sender, RoutedEventArgs e) => _disconnect();
}
