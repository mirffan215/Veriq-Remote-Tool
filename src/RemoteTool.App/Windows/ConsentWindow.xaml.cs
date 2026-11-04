using System.Windows;
using RemoteTool.App.Localization;
using RemoteTool.Core.Protocol;
using RemoteTool.Core.Session;

namespace RemoteTool.App.Windows;

public partial class ConsentWindow : Window
{
    public ConsentDecision Decision { get; private set; } = new(false, Permissions.None);

    public ConsentWindow(ConsentRequestInfo info)
    {
        InitializeComponent();
        FlowDirection = Loc.Flow;
        Headline.Text = Loc.F("Consent_Text", info.ViewerName);
        SourceText.Text = Loc.F("Consent_Source", info.Source);
        RelayNote.Visibility = info.ViaRelay ? Visibility.Visible : Visibility.Collapsed;
        RecNote.Visibility = info.Recording ? Visibility.Visible : Visibility.Collapsed;
        Configure(ControlBox, info, Permissions.Control);
        Configure(ClipboardBox, info, Permissions.Clipboard);
        Configure(FilesBox, info, Permissions.FileTransfer);
        Loaded += (_, _) => { Activate(); DenyButton.Focus(); }; // Deny is the default action
    }

    private static void Configure(System.Windows.Controls.CheckBox box, ConsentRequestInfo info, Permissions p)
    {
        var offered = (info.Requested & p) != 0 && (info.Allowed & p) != 0;
        box.Visibility = offered ? Visibility.Visible : Visibility.Collapsed;
        box.IsChecked = offered;
    }

    private void Allow_Click(object sender, RoutedEventArgs e)
    {
        var p = Permissions.None;
        if (ControlBox.IsChecked == true && ControlBox.Visibility == Visibility.Visible) p |= Permissions.Control;
        if (ClipboardBox.IsChecked == true && ClipboardBox.Visibility == Visibility.Visible) p |= Permissions.Clipboard;
        if (FilesBox.IsChecked == true && FilesBox.Visibility == Visibility.Visible) p |= Permissions.FileTransfer;
        // View-only is still a grant: nothing selected means the viewer sees the screen but cannot act.
        Decision = new ConsentDecision(true, p);
        DialogResult = true;
    }

    private void Deny_Click(object sender, RoutedEventArgs e) { Decision = new ConsentDecision(false, Permissions.None); DialogResult = false; }
}
