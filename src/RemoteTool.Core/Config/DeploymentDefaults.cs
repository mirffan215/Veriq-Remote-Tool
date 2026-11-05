using System.Text;
using System.Text.Json;

namespace RemoteTool.Core.Config;

/// <summary>
/// Company-wide connection defaults built into (or shipped next to) the exe, so ordinary users never see relay settings.
/// JSON: <c>{"relay":"host:443","fingerprint":"AA..","accessKey":"..."}</c>; every field may instead be given base64-encoded as <c>relayB64</c>,
/// <c>fingerprintB64</c>, <c>accessKeyB64</c> (the build embeds them that way so no value can break the JSON).
/// NOTE: an access key inside the exe can be extracted by anyone who has the exe: it only keeps outsiders off the relay, it is not a user credential.
/// </summary>
public sealed record DeploymentDefaults(string Relay, string Fingerprint, string AccessKey)
{
    public static readonly DeploymentDefaults Empty = new("", "", "");
    public bool IsEmpty => Relay.Length == 0 && Fingerprint.Length == 0 && AccessKey.Length == 0;

    public static DeploymentDefaults Parse(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return Empty;
        try
        {
            using var doc = JsonDocument.Parse(json);
            var r = doc.RootElement;
            string Get(string plain)
            {
                if (r.TryGetProperty(plain, out var p) && p.ValueKind == JsonValueKind.String && !string.IsNullOrWhiteSpace(p.GetString())) return p.GetString()!.Trim();
                if (r.TryGetProperty(plain + "B64", out var b) && b.ValueKind == JsonValueKind.String && b.GetString() is { Length: > 0 } enc)
                    try { return Encoding.UTF8.GetString(Convert.FromBase64String(enc)).Trim(); } catch (FormatException) { }
                return "";
            }
            return new DeploymentDefaults(Get("relay"), Get("fingerprint"), Get("accessKey"));
        }
        catch (Exception e) when (e is JsonException or InvalidOperationException) { return Empty; }   // a broken defaults file must never stop the app
    }

    /// <summary>First non-empty value per field wins (call with the highest priority first).</summary>
    public static DeploymentDefaults Merge(params DeploymentDefaults?[] byPriority)
    {
        string First(Func<DeploymentDefaults, string> f) => byPriority.Where(d => d is not null).Select(d => f(d!)).FirstOrDefault(v => v.Length > 0) ?? "";
        return new DeploymentDefaults(First(d => d.Relay), First(d => d.Fingerprint), First(d => d.AccessKey));
    }

    /// <summary>Fills ONLY settings the user/admin has not set. Returns true if anything changed. The access key is stored protected.</summary>
    public bool ApplyTo(AppSettings s, ISecretProtector protector)
    {
        var changed = false;
        if (s.RelayAddress.Length == 0 && Relay.Length > 0) { s.RelayAddress = Relay; changed = true; }
        if (s.RelayFingerprint.Length == 0 && Fingerprint.Length > 0) { s.RelayFingerprint = Fingerprint; changed = true; }
        if (s.RelayAccessKeyProtected.Length == 0 && AccessKey.Length > 0) { s.RelayAccessKeyProtected = protector.Protect(AccessKey); changed = true; }
        return changed;
    }
}
