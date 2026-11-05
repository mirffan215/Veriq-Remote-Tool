using System.Text.Json;
using System.Text.RegularExpressions;

namespace RemoteTool.Core.Config;

/// <summary>
/// Which "edition" of the product this exe is (Enterprise / Production / UAT / the plain default). All editions share the same source code; an edition only changes
/// identity: name, window title, the folder settings and logs live in (so two editions can run side by side on one PC), icon and the built-in relay defaults.
/// Chosen at build time (<c>-p:Edition=UAT</c>), embedded as JSON, read once at start-up.
/// </summary>
public sealed record EditionInfo(string Id, string DisplayName, string DataFolder, string Banner)
{
    public static readonly EditionInfo Standard = new("Standard", "RemoteTool", "RemoteTool", "");

    /// <summary>The running edition. Set once at start-up; defaults to <see cref="Standard"/>.</summary>
    public static EditionInfo Current { get; set; } = Standard;

    /// <summary>"Veriq Remote Tool [UAT]" - what the window title bar shows, so a test build is never mistaken for production.</summary>
    public string WindowTitle => Banner.Length > 0 ? $"{DisplayName} [{Banner}]" : DisplayName;

    private static readonly Regex SafeFolder = new("^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$", RegexOptions.Compiled);

    /// <summary>Parses the embedded JSON. Anything missing or unsafe (a folder name that could escape the data directory) falls back to the Standard value.</summary>
    public static EditionInfo Parse(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return Standard;
        try
        {
            using var doc = JsonDocument.Parse(json);
            string Get(string name, string fallback) =>
                doc.RootElement.TryGetProperty(name, out var p) && p.ValueKind == JsonValueKind.String && !string.IsNullOrWhiteSpace(p.GetString()) ? p.GetString()!.Trim() : fallback;
            var folder = Get("dataFolder", Standard.DataFolder);
            if (!SafeFolder.IsMatch(folder) || folder.Contains("..")) folder = Standard.DataFolder;
            var banner = doc.RootElement.TryGetProperty("banner", out var b) && b.ValueKind == JsonValueKind.String ? b.GetString()!.Trim() : "";
            return new EditionInfo(Get("id", Standard.Id), Get("displayName", Standard.DisplayName), folder, banner.Length > 40 ? banner[..40] : banner);
        }
        catch (Exception e) when (e is JsonException or InvalidOperationException) { return Standard; }
    }
}
