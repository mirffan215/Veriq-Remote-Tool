using System.Text;
using System.Text.Json;

namespace RemoteTool.Core.Audit;

public interface IAuditLog
{
    /// <summary>Appends one event. <paramref name="fields"/> must never contain secrets or screen content.</summary>
    void Write(string eventName, params (string Key, object? Value)[] fields);
}

public sealed class NullAuditLog : IAuditLog
{
    public static readonly NullAuditLog Instance = new();
    public void Write(string eventName, params (string Key, object? Value)[] fields) { }
}

/// <summary>
/// JSON-lines audit log with size-based rotation and age-based retention. Append-only from the app's point of view.
/// Keys that look like secrets are refused so a coding mistake cannot leak a password into the log.
/// </summary>
public sealed class JsonlAuditLog : IAuditLog
{
    private static readonly string[] ForbiddenKeyParts = { "password", "secret", "key", "token", "screen", "pixel", "frame" };
    private readonly string _dir;
    private readonly string _role;
    private readonly long _maxBytes;
    private readonly TimeProvider _time;
    private readonly object _gate = new();

    public JsonlAuditLog(string directory, string role, long maxFileBytes = 5 * 1024 * 1024, int retentionDays = 180, TimeProvider? time = null)
    {
        _dir = directory;
        _role = role;
        _maxBytes = maxFileBytes;
        _time = time ?? TimeProvider.System;
        Directory.CreateDirectory(_dir);
        Prune(retentionDays);
    }

    public void Write(string eventName, params (string Key, object? Value)[] fields)
    {
        using var ms = new MemoryStream();
        using (var w = new Utf8JsonWriter(ms))
        {
            w.WriteStartObject();
            w.WriteString("ts", _time.GetUtcNow().UtcDateTime.ToString("O"));
            w.WriteString("role", _role);
            w.WriteString("event", eventName);
            foreach (var (k, v) in fields)
            {
                if (ForbiddenKeyParts.Any(p => k.Contains(p, StringComparison.OrdinalIgnoreCase)))
                    throw new ArgumentException($"audit field '{k}' is not permitted", nameof(fields));
                w.WritePropertyName(k);
                JsonSerializer.Serialize(w, v is Enum e ? e.ToString() : v);
            }
            w.WriteEndObject();
        }
        ms.WriteByte((byte)'\n');
        lock (_gate)
        {
            try
            {
                var path = CurrentFile(ms.Length);
                using var fs = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.Read);
                fs.Write(ms.GetBuffer(), 0, (int)ms.Length);
            }
            catch (IOException) { /* logging must never crash a session; failures surface via health in the UI */ }
            catch (UnauthorizedAccessException) { }
        }
    }

    private string CurrentFile(long incoming)
    {
        var day = _time.GetUtcNow().UtcDateTime.ToString("yyyyMMdd");
        for (var n = 0; ; n++)
        {
            var path = Path.Combine(_dir, n == 0 ? $"audit-{_role}-{day}.jsonl" : $"audit-{_role}-{day}.{n}.jsonl");
            if (!File.Exists(path) || new FileInfo(path).Length + incoming <= _maxBytes) return path;
        }
    }

    private void Prune(int retentionDays)
    {
        try
        {
            var cutoff = _time.GetUtcNow().UtcDateTime.AddDays(-retentionDays);
            foreach (var f in Directory.EnumerateFiles(_dir, $"audit-{_role}-*.jsonl"))
                if (File.GetLastWriteTimeUtc(f) < cutoff) File.Delete(f);
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }
}
