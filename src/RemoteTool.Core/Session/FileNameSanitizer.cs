using System.Globalization;
using System.Text;

namespace RemoteTool.Core.Session;

/// <summary>
/// Turns an attacker-controlled file name into a single safe path component: no directories, no traversal, no alternate
/// data streams, no reserved device names, no bidi/format tricks, bounded length.
/// </summary>
public static class FileNameSanitizer
{
    private static readonly HashSet<string> Reserved = new(StringComparer.OrdinalIgnoreCase)
    {
        "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$",
        "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
        "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    };

    private const int MaxLength = 120;

    public static string Sanitize(string? name)
    {
        name ??= "";
        var cut = name.LastIndexOfAny(new[] { '/', '\\' });
        if (cut >= 0) name = name[(cut + 1)..];

        var sb = new StringBuilder(name.Length);
        foreach (var c in name.Normalize(NormalizationForm.FormC))
        {
            var cat = char.GetUnicodeCategory(c);
            if (cat is UnicodeCategory.Control or UnicodeCategory.Format or UnicodeCategory.OtherNotAssigned
                or UnicodeCategory.Surrogate or UnicodeCategory.PrivateUse or UnicodeCategory.LineSeparator or UnicodeCategory.ParagraphSeparator) continue;
            sb.Append("<>:\"|?*".Contains(c) ? '_' : c);
        }
        var s = sb.ToString().Trim().TrimEnd('.', ' ');
        s = s.TrimStart(' ');
        if (s.Length == 0) return "file";

        var dot = s.IndexOf('.');
        var stem = dot < 0 ? s : s[..dot];
        if (Reserved.Contains(stem.TrimEnd())) s = "_" + s;

        if (s.Length > MaxLength)
        {
            var ext = Path.GetExtension(s);
            if (ext.Length > 16) ext = ext[..16];
            s = s[..(MaxLength - ext.Length)] + ext;
        }
        return s;
    }

    /// <summary>Returns a non-existing path inside <paramref name="directory"/> and guarantees it stays inside it.</summary>
    public static string UniquePath(string directory, string safeName)
    {
        var root = Path.GetFullPath(directory);
        var stem = Path.GetFileNameWithoutExtension(safeName);
        var ext = Path.GetExtension(safeName);
        for (var i = 0; i < 10_000; i++)
        {
            var candidate = Path.GetFullPath(Path.Combine(root, i == 0 ? safeName : $"{stem} ({i}){ext}"));
            if (!candidate.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.Ordinal))
                throw new InvalidOperationException("path escaped the receive directory");
            if (!File.Exists(candidate)) return candidate;
        }
        throw new IOException("too many files with the same name");
    }
}
