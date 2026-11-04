using System.Text.Json;
using System.Text.Json.Serialization;

namespace RemoteTool.Core.Config;

public sealed class RecentConnection
{
    public string Target { get; set; } = "";
    public string? Nickname { get; set; }
    public DateTimeOffset LastUsed { get; set; }
}

/// <summary>Persistent settings. Never contains passwords. Secrets (relay key) are stored protected (DPAPI on Windows).</summary>
public sealed class AppSettings
{
    public string Id { get; set; } = "";
    public string DisplayName { get; set; } = Environment.MachineName;
    public string RelayAddress { get; set; } = "";
    public string RelayFingerprint { get; set; } = "";
    public string RelayAccessKeyProtected { get; set; } = "";
    public bool DirectListenerEnabled { get; set; }
    public int DirectPort { get; set; } = ConnectTarget.DefaultDirectPort;
    public List<string> IpAllowList { get; set; } = new();
    public bool ViewOnly { get; set; }
    public bool AllowClipboard { get; set; } = true;
    public bool AllowFileTransfer { get; set; } = true;
    public string Theme { get; set; } = "System";
    public List<RecentConnection> Recent { get; set; } = new();
}

public interface ISecretProtector
{
    string Protect(string plaintext);
    string Unprotect(string protectedText);
}

/// <summary>Atomic JSON settings store; also owns the persistent ID.</summary>
public sealed class SettingsStore
{
    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true, DefaultIgnoreCondition = JsonIgnoreCondition.Never };
    private readonly string _file;
    private readonly object _gate = new();

    public SettingsStore(string file) { _file = file; }

    public AppSettings Current { get; private set; } = new();

    public AppSettings Load()
    {
        lock (_gate)
        {
            AppSettings? s = null;
            if (File.Exists(_file))
            {
                try { s = JsonSerializer.Deserialize<AppSettings>(File.ReadAllText(_file), Json); }
                catch (JsonException)
                {
                    File.Move(_file, _file + $".corrupt-{DateTime.UtcNow:yyyyMMddHHmmss}", true);
                }
            }
            s ??= new AppSettings();
            if (!ConnectionId.IsValid(s.Id)) s.Id = ConnectionId.Generate();
            Current = s;
            SaveLocked();
            return s;
        }
    }

    /// <summary>Replaces the persisted ID with a fresh random one.</summary>
    public string RegenerateId()
    {
        lock (_gate)
        {
            Current.Id = ConnectionId.Generate();
            SaveLocked();
            return Current.Id;
        }
    }

    public void Save() { lock (_gate) SaveLocked(); }

    public void AddRecent(string target)
    {
        lock (_gate)
        {
            Current.Recent.RemoveAll(r => string.Equals(r.Target, target, StringComparison.OrdinalIgnoreCase));
            Current.Recent.Insert(0, new RecentConnection { Target = target, LastUsed = DateTimeOffset.UtcNow });
            if (Current.Recent.Count > 10) Current.Recent.RemoveRange(10, Current.Recent.Count - 10);
            SaveLocked();
        }
    }

    private void SaveLocked()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_file)!);
        var tmp = _file + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(Current, Json));
        File.Move(tmp, _file, true);
    }
}
