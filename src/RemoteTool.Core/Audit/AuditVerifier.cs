using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace RemoteTool.Core.Audit;

public sealed record AuditVerification(bool Ok, int Lines, string? Problem, string? File, int LineNumber);

/// <summary>Verifies the SHA-256 hash chain written by <see cref="JsonlAuditLog"/>.</summary>
public static class AuditVerifier
{
    public static readonly string Genesis = new('0', 64);

    public static IReadOnlyList<string> FilesInOrder(string dir, string role)
        => Directory.Exists(dir)
            ? Directory.EnumerateFiles(dir, $"audit-{role}-*.jsonl").OrderBy(KeyOf, StringComparer.Ordinal).ToList()
            : new List<string>();

    private static string KeyOf(string path)
    {
        // audit-<role>-<yyyyMMdd>[.<n>].jsonl  ->  "<yyyyMMdd>.<n padded>"
        var name = Path.GetFileNameWithoutExtension(path);
        var tail = name[(name.LastIndexOf('-') + 1)..];
        var parts = tail.Split('.');
        var n = parts.Length > 1 && int.TryParse(parts[1], out var i) ? i : 0;
        return $"{parts[0]}.{n:D6}";
    }

    internal static string LastHashOf(string dir, string role)
    {
        foreach (var f in FilesInOrder(dir, role).AsEnumerable().Reverse())
        {
            string? last = null;
            try { last = File.ReadLines(f, Encoding.UTF8).LastOrDefault(l => l.Length > 0); } catch (IOException) { }
            if (last is not null) return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(last)));
        }
        return Genesis;
    }

    public static AuditVerification Verify(string dir, string role)
    {
        var expected = (string?)null; // null until the first chained line (older, unchained logs are tolerated at the start)
        var total = 0;
        foreach (var file in FilesInOrder(dir, role))
        {
            var n = 0;
            foreach (var line in File.ReadLines(file, Encoding.UTF8))
            {
                n++;
                if (line.Length == 0) continue;
                total++;
                string? prev;
                try { using var doc = JsonDocument.Parse(line); prev = doc.RootElement.TryGetProperty("prev", out var p) ? p.GetString() : null; }
                catch (JsonException) { return new AuditVerification(false, total, "line is not valid JSON", file, n); }
                if (expected is null && prev is null) continue;                 // legacy unchained prefix
                if (prev is null) return new AuditVerification(false, total, "line without chain hash inside a chained log", file, n);
                if (expected is not null && !string.Equals(prev, expected, StringComparison.Ordinal))
                    return new AuditVerification(false, total, "hash chain broken (line modified, removed or inserted before this line)", file, n);
                expected = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(line)));
            }
        }
        return new AuditVerification(true, total, null, null, 0);
    }
}
