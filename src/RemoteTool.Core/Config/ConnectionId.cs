using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace RemoteTool.Core.Config;

/// <summary>
/// AnyDesk-style numeric connection code: CSPRNG, never starts with 0, never derived from host attributes.
/// Generated with <see cref="DefaultLength"/> (12) digits ≈ 9×10¹¹ possibilities, which together with the relay's per-IP lookup limits makes
/// enumeration impractical; 10 and 11 digit codes are accepted too (shorter codes issued by older/other deployments).
/// </summary>
public static partial class ConnectionId
{
    public const int MinLength = 10, MaxLength = 12, DefaultLength = 12;

    public static string Generate(int length = DefaultLength)
    {
        if (length is < MinLength or > MaxLength) throw new ArgumentOutOfRangeException(nameof(length));
        Span<char> c = stackalloc char[length];
        c[0] = (char)('1' + RandomNumberGenerator.GetInt32(9));          // 1..9: never a leading zero
        for (var i = 1; i < length; i++) c[i] = (char)('0' + RandomNumberGenerator.GetInt32(10));
        return new string(c);
    }

    public static bool IsValid(string id) => id.Length is >= MinLength and <= MaxLength && id[0] != '0' && id.All(char.IsAsciiDigit);

    /// <summary>"123456789012" -> "123 456 789 012" (groups of three; a short last group for 10/11 digits).</summary>
    public static string Format(string id)
    {
        if (!IsValid(id)) return id;
        var parts = new List<string>();
        for (var i = 0; i < id.Length; i += 3) parts.Add(id.Substring(i, Math.Min(3, id.Length - i)));
        return string.Join(' ', parts);
    }

    /// <summary>Accepts a 10–12 digit code with optional spaces.</summary>
    public static bool TryParseId(string input, out string id)
    {
        var s = new string(input.Where(c => !char.IsWhiteSpace(c)).ToArray());
        id = s;
        return IsValid(s);
    }
}

public abstract record ConnectTarget
{
    public sealed record ById(string Id) : ConnectTarget;
    public sealed record Direct(string Host, int Port) : ConnectTarget;

    public const int DefaultDirectPort = 21118;

    /// <summary>Parses the Connect field: a 10–12 digit code (spaces optional) or <c>host[:port]</c> / <c>[v6]:port</c>.</summary>
    public static bool TryParse(string? input, out ConnectTarget? target)
    {
        target = null;
        if (string.IsNullOrWhiteSpace(input)) return false;
        if (ConnectionId.TryParseId(input, out var id)) { target = new ById(id); return true; }
        var s = input.Trim();
        string host;
        var port = DefaultDirectPort;
        if (s.StartsWith('['))
        {
            var end = s.IndexOf(']');
            if (end < 0) return false;
            host = s[1..end];
            var rest = s[(end + 1)..];
            if (rest.Length > 0 && (rest[0] != ':' || !TryPort(rest[1..], out port))) return false;
        }
        else
        {
            var idx = s.LastIndexOf(':');
            if (idx >= 0 && s.IndexOf(':') == idx)
            {
                host = s[..idx];
                if (!TryPort(s[(idx + 1)..], out port)) return false;
            }
            else host = s;
        }
        if (host.Length == 0 || host.Length > 253 || host.Any(c => char.IsWhiteSpace(c) || char.IsControl(c))) return false;
        target = new Direct(host, port);
        return true;
    }

    private static bool TryPort(string s, out int port) => int.TryParse(s, out port) && port is > 0 and <= 65535;
}
