using System.Text.Json;
using RemoteTool.Core.Config;
using RemoteTool.Core.Relay;

namespace RemoteTool.Service;

/// <summary>Machine-wide settings of the unattended-access service. Lives in an ACL-restricted ProgramData folder (SYSTEM + Administrators).</summary>
public sealed class ServiceConfig
{
    public string Id { get; set; } = "";
    public string DisplayName { get; set; } = Environment.MachineName;
    public string RelayAddress { get; set; } = "";
    public string RelayFingerprint { get; set; } = "";
    public string RelayAccessKeyProtected { get; set; } = "";
    /// <summary>Master opt-in. Even with a stored permanent password nothing unattended works while this is false.</summary>
    public bool UnattendedEnabled { get; set; }
    /// <summary>If someone is logged in and looking at their desktop, ask them first (default). Disable only for kiosks/servers.</summary>
    public bool ConsentWhenUserPresent { get; set; } = true;
    public bool RecordSessions { get; set; }
    public int RecordingRetentionDays { get; set; } = 30;
    public bool DirectListenerEnabled { get; set; }
    public int DirectPort { get; set; } = ConnectTarget.DefaultDirectPort;
    public List<string> IpAllowList { get; set; } = new();
}

public sealed record ServicePaths(string Root)
{
    public string ServiceDir => Path.Combine(Root, "service");
    public string ConfigFile => Path.Combine(ServiceDir, "config.json");
    public string PermanentFile => Path.Combine(ServiceDir, "permanent.json");
    public string LogDir => Path.Combine(ServiceDir, "logs");
    public string RecordingDir => Path.Combine(ServiceDir, "recordings");
    /// <summary>World-readable, non-sensitive status for the user-mode UI (ID, online state).</summary>
    public string PublicDir => Path.Combine(Root, "public");
    public string PublicStatusFile => Path.Combine(PublicDir, "service-status.json");

    public static ServicePaths Default() => new(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "RemoteTool"));
}

public sealed class ServiceConfigStore
{
    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true };
    private readonly string _file;
    private readonly object _gate = new();

    public ServiceConfigStore(string file) { _file = file; }

    public ServiceConfig Load()
    {
        lock (_gate)
        {
            ServiceConfig? c = null;
            try { if (File.Exists(_file)) c = JsonSerializer.Deserialize<ServiceConfig>(File.ReadAllText(_file), Json); }
            catch (JsonException) { File.Move(_file, _file + $".corrupt-{DateTime.UtcNow:yyyyMMddHHmmss}", true); }
            c ??= new ServiceConfig();
            if (!ConnectionId.IsValid(c.Id)) { c.Id = ConnectionId.Generate(); SaveLocked(c); }
            return c;
        }
    }

    public void Save(ServiceConfig c) { lock (_gate) SaveLocked(c); }

    private void SaveLocked(ServiceConfig c)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_file)!);
        var tmp = _file + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(c, Json));
        File.Move(tmp, _file, true);
    }
}

public sealed class ConfigIdProvider : IIdProvider
{
    private readonly ServiceConfigStore _store;
    private ServiceConfig _cfg;
    public ConfigIdProvider(ServiceConfigStore store, ServiceConfig cfg) { _store = store; _cfg = cfg; }
    public string Id => _cfg.Id;
    public string Regenerate() { _cfg.Id = ConnectionId.Generate(); _store.Save(_cfg); return _cfg.Id; }
}
