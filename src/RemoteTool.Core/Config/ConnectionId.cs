using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace RemoteTool.Core.Config;

/// <summary>AnyDesk-style 9-digit ID: CSPRNG, never starts with 0, never derived from host attributes.</summary>
public static partial class ConnectionId
{
    public static string Generate() => (100_000_000 + RandomNumberGenerator.GetInt32(900_000_000)).ToString(System.Globalization.CultureInfo.InvariantCulture);

    public static bool IsValid(string id) => id.Length == 9 && id[0] != '0' && id.All(char.IsAsciiDigit);

    /// <summary>"123456789" -> "123 456 789".</summary>
    public static string Format(string id) => id.Length == 9 ? $"{id[..3]} {id[3..6]} {id[6..]}" : id;

    /// <summary>Accepts a 9-digit ID with optional spaces.</summary>
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

    /// <summary>Parses the Connect field: a 9-digit ID (spaces optional) or <c>host[:port]</c> / <c>[v6]:port</c>.</summary>
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
