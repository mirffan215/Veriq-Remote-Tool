using System.Security.Cryptography;

namespace RemoteTool.Core.Security;

public static class PasswordGenerator
{
    // 31 symbols, no I/L/O/0/1 look-alikes: 8 chars ~ 39.6 bits.
    public const string Alphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";
    public const int Length = 8;

    public static string Generate()
    {
        Span<char> c = stackalloc char[Length];
        for (var i = 0; i < c.Length; i++) c[i] = Alphabet[RandomNumberGenerator.GetInt32(Alphabet.Length)];
        return new string(c);
    }

    /// <summary>Canonical form used for key derivation: upper-case, spaces and dashes removed.</summary>
    public static string Normalize(string s) => new(s.Where(ch => !char.IsWhiteSpace(ch) && ch != '-').Select(char.ToUpperInvariant).ToArray());
}
