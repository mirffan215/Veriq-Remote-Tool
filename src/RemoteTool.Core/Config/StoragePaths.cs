namespace RemoteTool.Core.Config;

/// <summary>
/// Where settings and logs live. Normal mode: settings in %AppData%\RemoteTool, logs in %ProgramData%\RemoteTool\logs
/// (falling back to %LocalAppData% if not writable). Portable mode (a <c>portable.flag</c> file next to the exe):
/// everything next to the exe under <c>data\</c>.
/// </summary>
public sealed record StoragePaths(string SettingsDirectory, string LogDirectory, bool Portable)
{
    public string SettingsFile => Path.Combine(SettingsDirectory, "settings.json");
    /// <summary>Dedicated folder for received files: next to the exe in portable mode, otherwise under Documents (easy for users to find).</summary>
    public string ReceivedFilesDirectory => Portable
        ? Path.Combine(SettingsDirectory, "RemoteTool Received")
        : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "RemoteTool Received");

    public static StoragePaths Detect(string exeDirectory)
    {
        if (File.Exists(Path.Combine(exeDirectory, "portable.flag")))
        {
            var data = Path.Combine(exeDirectory, "data");
            return new StoragePaths(data, Path.Combine(data, "logs"), true);
        }
        var appData = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "RemoteTool");
        var logs = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "RemoteTool", "logs");
        if (!CanWrite(logs))
            logs = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "RemoteTool", "logs");
        return new StoragePaths(appData, logs, false);
    }

    private static bool CanWrite(string dir)
    {
        try
        {
            Directory.CreateDirectory(dir);
            var probe = Path.Combine(dir, $".probe-{Guid.NewGuid():N}");
            File.WriteAllText(probe, "x");
            File.Delete(probe);
            return true;
        }
        catch { return false; }
    }
}
