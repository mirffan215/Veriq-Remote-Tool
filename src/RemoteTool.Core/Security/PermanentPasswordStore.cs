using System.Security.Cryptography;
using System.Text.Json;
using RemoteTool.Core.Config;

namespace RemoteTool.Core.Security;

/// <summary>The unattended-access credential as the host sees it. Holds the derived HMAC key, never the password.</summary>
public interface IPermanentCredential
{
    bool Enabled { get; }
    /// <summary>Fixed per-install salt, sent to the viewer in AuthChallenge.</summary>
    byte[] Salt { get; }
    /// <summary>PBKDF2-HMAC-SHA256(password, Salt, 600k): exactly the key the handshake needs.</summary>
    byte[] Key { get; }
}

/// <summary>
/// Persists the permanent password as salt + derived key (protected with the OS secret store, machine scope for the service),
/// so the plaintext password is never stored. The key is password-equivalent for authentication, so the file must stay
/// ACL-restricted (SYSTEM + Administrators); that is enforced by the installer.
/// </summary>
public sealed class PermanentPasswordStore : IPermanentCredential
{
    private sealed class Model { public string Salt { get; set; } = ""; public string KeyProtected { get; set; } = ""; }

    public const int MinLength = 12;
    private readonly string _file;
    private readonly ISecretProtector _protector;
    private byte[]? _salt, _key;

    public PermanentPasswordStore(string file, ISecretProtector protector)
    {
        _file = file;
        _protector = protector;
        Reload();
    }

    public bool Enabled => _key is not null && _salt is not null;
    public byte[] Salt => _salt ?? throw new InvalidOperationException("no permanent password set");
    public byte[] Key => _key ?? throw new InvalidOperationException("no permanent password set");

    /// <summary>Returns null if acceptable, otherwise a human-readable reason. Online-guessable forever, so stricter than the one-time password.</summary>
    public static string? Validate(string password)
    {
        if (password.Length < MinLength) return $"Use at least {MinLength} characters.";
        var classes = (password.Any(char.IsLower) ? 1 : 0) + (password.Any(char.IsUpper) ? 1 : 0) + (password.Any(char.IsDigit) ? 1 : 0)
                      + (password.Any(c => !char.IsLetterOrDigit(c)) ? 1 : 0);
        if (classes < 3) return "Mix at least three of: lower-case, upper-case, digits, symbols.";
        if (password.Distinct().Count() < 6) return "Too repetitive.";
        return null;
    }

    public void Set(string password)
    {
        var problem = Validate(password);
        if (problem is not null) throw new ArgumentException(problem, nameof(password));
        var salt = RandomNumberGenerator.GetBytes(Protocol.ProtocolConstants.SaltLength);
        var key = PasswordHandshake.DeriveKey(password, salt);
        Directory.CreateDirectory(Path.GetDirectoryName(_file)!);
        var json = JsonSerializer.Serialize(new Model { Salt = Convert.ToBase64String(salt), KeyProtected = _protector.Protect(Convert.ToBase64String(key)) });
        var tmp = _file + ".tmp";
        File.WriteAllText(tmp, json);
        File.Move(tmp, _file, true);
        _salt = salt;
        _key = key;
    }

    public void Clear()
    {
        if (File.Exists(_file)) File.Delete(_file);
        _salt = _key = null;
    }

    public void Reload()
    {
        _salt = _key = null;
        if (!File.Exists(_file)) return;
        try
        {
            var m = JsonSerializer.Deserialize<Model>(File.ReadAllText(_file));
            if (m is null) return;
            var key = Convert.FromBase64String(_protector.Unprotect(m.KeyProtected));
            var salt = Convert.FromBase64String(m.Salt);
            if (key.Length == 32 && salt.Length == Protocol.ProtocolConstants.SaltLength) { _key = key; _salt = salt; }
        }
        catch (Exception e) when (e is JsonException or FormatException or CryptographicException) { _salt = _key = null; } // unreadable => disabled, never open
    }
}
