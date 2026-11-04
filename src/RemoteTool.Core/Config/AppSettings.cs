using System.Text.Json;
using System.Text.Json.Serialization;

namespace RemoteTool.Core.Config;

public sealed class AddressBookEntry
{
    public string Target { get; set; } = "";
    public string Nickname { get; set; } = "";
}

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
    /// <summary>"System", "en" or "ar". Applied at the next start.</summary>
    public string Language { get; set; } = "System";
    /// <summary>Offer/use H.264 (hardware when possible) instead of tile-JPEG. Falls back automatically if it fails.</summary>
    public bool EnableH264 { get; set; } = true;
    public List<RecentConnection> Recent { get; set; } = new();
    /// <summary>Saved IDs / addresses with nicknames. Never contains passwords.</summary>
    public List<AddressBookEntry> AddressBook { get; set; } = new();
    public int MaxFileTransferMb { get; set; } = 1024;
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

    public void UpsertAddress(string target, string nickname)
    {
        lock (_gate)
        {
            var nick = nickname.Trim();
            if (nick.Length > 64) nick = nick[..64];
            var e = Current.AddressBook.FirstOrDefault(a => string.Equals(a.Target, target, StringComparison.OrdinalIgnoreCase));
            if (e is null) Current.AddressBook.Add(new AddressBookEntry { Target = target, Nickname = nick });
            else e.Nickname = nick;
            Current.AddressBook = Current.AddressBook.OrderBy(a => a.Nickname.Length == 0 ? a.Target : a.Nickname, StringComparer.CurrentCultureIgnoreCase).ToList();
            SaveLocked();
        }
    }

    public bool RemoveAddress(string target)
    {
        lock (_gate)
        {
            var removed = Current.AddressBook.RemoveAll(a => string.Equals(a.Target, target, StringComparison.OrdinalIgnoreCase)) > 0;
            if (removed) SaveLocked();
            return removed;
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
