using System.Windows;
using System.Windows.Threading;
using RemoteTool.App.Localization;
using RemoteTool.Core.Session;

namespace RemoteTool.App.Services;

/// <summary>Per-transfer confirmation dialog. The default (and Esc) answer is "No".</summary>
public sealed class UiFilePrompt : IFileTransferPrompt
{
    private readonly Dispatcher _ui;
    public UiFilePrompt(Dispatcher ui) { _ui = ui; }

    public Task<bool> ConfirmAsync(FileOfferInfo info, CancellationToken ct)
        => _ui.InvokeAsync(() =>
        {
            // A tiny topmost owner window makes sure the question is not hidden behind other windows.
            var owner = new Window { Width = 0, Height = 0, WindowStyle = WindowStyle.None, ShowInTaskbar = false, Topmost = true, ShowActivated = true, Left = -10000, Top = -10000 };
            owner.Show();
            try
            {
                return MessageBox.Show(owner, Loc.F("File_Confirm", info.PeerName, info.FileName, FormatSize(info.Size)), Loc.T("File_Title"),
                    MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No) == MessageBoxResult.Yes;
            }
            finally { owner.Close(); }
        }).Task;

    public static string FormatSize(long bytes) => bytes switch
    {
        < 1024 => $"{bytes} B",
        < 1024 * 1024 => $"{bytes / 1024.0:F1} KB",
        < 1024L * 1024 * 1024 => $"{bytes / 1048576.0:F1} MB",
        _ => $"{bytes / 1073741824.0:F2} GB",
    };
}
