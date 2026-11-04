using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using RemoteTool.Core.Audit;
using RemoteTool.Core.Config;
using RemoteTool.Core.Protocol;
using RemoteTool.Core.Session;

namespace RemoteTool.Core.Recording;

public enum RecordType : byte { Meta = 1, TileFrame = 2, H264Frame = 3, Event = 4, End = 5 }

public sealed record RecordEntry(TimeSpan Time, RecordType Type, byte[] Payload);

public interface ISessionRecorder : IDisposable
{
    void WriteFrame(FrameUpdateMessage frame);
    void WriteVideo(VideoFrameMessage frame);
    void WriteEvent(string text);
    /// <summary>Finishes the file; returns (path, sha256 hex) for the audit trail.</summary>
    (string Path, string Sha256)? Complete(string reason);
}

public interface ISessionRecorderFactory
{
    ISessionRecorder? Create(SessionInfo session, string hostName);
}

/// <summary>
/// Optional, OFF-by-default session recording. Records only screen updates and coarse events: never keystrokes, clipboard or file
/// contents. Every record is AES-256-GCM encrypted (vetted .NET primitive) with a per-file random key that is wrapped by the OS secret
/// store; the header is authenticated and record counters are bound into the nonce/AAD, so tampering, reordering and gaps are detected.
/// </summary>
public sealed class EncryptedSessionRecorder : ISessionRecorder
{
    internal static readonly byte[] Magic = Encoding.ASCII.GetBytes("RTREC001");
    private readonly FileStream _fs;
    private readonly byte[] _key;
    private readonly byte[] _header;
    private readonly byte[] _noncePrefix;
    private readonly System.Diagnostics.Stopwatch _clock = System.Diagnostics.Stopwatch.StartNew();
    private readonly object _gate = new();
    private uint _counter;
    private bool _completed;

    public string Path { get; }

    public EncryptedSessionRecorder(string path, ISecretProtector protector, SessionInfo session, string hostName)
    {
        Path = path;
        _key = RandomNumberGenerator.GetBytes(32);
        _noncePrefix = RandomNumberGenerator.GetBytes(8);
        var wrapped = Encoding.UTF8.GetBytes(protector.Protect(Convert.ToBase64String(_key)));
        var h = new ProtoWriter().Fixed(Magic).U16(1).Fixed(_noncePrefix).Bytes(wrapped).ToArray();
        _header = h;
        _fs = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.Read);
        _fs.Write(h);
        var meta = JsonSerializer.SerializeToUtf8Bytes(new { session = session.Id, viewer = session.ViewerName, source = session.Source, host = hostName,
            startedUtc = session.StartedAt, permissions = session.Permissions.ToString() });
        Append(RecordType.Meta, meta);
    }

    public void WriteFrame(FrameUpdateMessage frame) => Append(RecordType.TileFrame, frame.Serialize());
    public void WriteVideo(VideoFrameMessage frame) => Append(RecordType.H264Frame, frame.Serialize());
    public void WriteEvent(string text) => Append(RecordType.Event, Encoding.UTF8.GetBytes(text));

    private void Append(RecordType type, byte[] payload)
    {
        lock (_gate)
        {
            if (_completed) return;
            var plain = new byte[9 + payload.Length];
            BinaryPrimitives.WriteUInt64BigEndian(plain, (ulong)_clock.ElapsedMilliseconds);
            plain[8] = (byte)type;
            payload.CopyTo(plain, 9);
            var nonce = new byte[12];
            _noncePrefix.CopyTo(nonce, 0);
            BinaryPrimitives.WriteUInt32BigEndian(nonce.AsSpan(8), _counter);
            var cipher = new byte[plain.Length];
            var tag = new byte[16];
            using (var gcm = new AesGcm(_key, 16)) gcm.Encrypt(nonce, plain, cipher, tag, AadFor(_header, _counter));
            var len = new byte[4];
            BinaryPrimitives.WriteUInt32BigEndian(len, (uint)(cipher.Length + 16));
            _fs.Write(len);
            _fs.Write(cipher);
            _fs.Write(tag);
            _counter++;
        }
    }

    internal static byte[] AadFor(byte[] header, uint counter)
    {
        var aad = new byte[header.Length + 4];
        header.CopyTo(aad, 0);
        BinaryPrimitives.WriteUInt32BigEndian(aad.AsSpan(header.Length), counter);
        return aad;
    }

    public (string Path, string Sha256)? Complete(string reason)
    {
        lock (_gate)
        {
            if (_completed) return null;
        }
        Append(RecordType.End, Encoding.UTF8.GetBytes(reason));
        lock (_gate)
        {
            _completed = true;
            _fs.Flush(true);
            _fs.Dispose();
        }
        using var rf = File.OpenRead(Path);
        return (Path, Convert.ToHexString(SHA256.HashData(rf)));
    }

    public void Dispose() { if (!_completed) Complete("aborted"); CryptographicOperations.ZeroMemory(_key); }
}

public sealed class SessionRecorderFactory : ISessionRecorderFactory
{
    private readonly string _dir;
    private readonly ISecretProtector _protector;

    public SessionRecorderFactory(string directory, ISecretProtector protector, int retentionDays = 30)
    {
        _dir = directory;
        _protector = protector;
        Directory.CreateDirectory(_dir);
        foreach (var f in Directory.EnumerateFiles(_dir, "*.rtrec"))
            if (File.GetLastWriteTimeUtc(f) < DateTime.UtcNow.AddDays(-retentionDays)) { try { File.Delete(f); } catch (IOException) { } }
    }

    public ISessionRecorder? Create(SessionInfo session, string hostName)
    {
        try
        {
            var name = $"{session.StartedAt.UtcDateTime:yyyyMMdd-HHmmss}-{session.Id:N}.rtrec";
            return new EncryptedSessionRecorder(System.IO.Path.Combine(_dir, name), _protector, session, hostName);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { return null; }
    }
}

public static class RecordingReader
{
    /// <summary>Decrypts and enumerates a recording. Throws <see cref="CryptographicException"/> on any tampering, reordering or gap.</summary>
    public static IEnumerable<RecordEntry> Read(string path, ISecretProtector protector)
    {
        using var fs = File.OpenRead(path);
        var magic = new byte[EncryptedSessionRecorder.Magic.Length];
        fs.ReadExactly(magic);
        if (!magic.AsSpan().SequenceEqual(EncryptedSessionRecorder.Magic)) throw new InvalidDataException("not a RemoteTool recording");
        var ver = new byte[2]; fs.ReadExactly(ver);
        var prefix = new byte[8]; fs.ReadExactly(prefix);
        var lenBuf = new byte[4]; fs.ReadExactly(lenBuf);
        var wrapped = new byte[BinaryPrimitives.ReadUInt32BigEndian(lenBuf)];
        if (wrapped.Length > 4096) throw new InvalidDataException("corrupt header");
        fs.ReadExactly(wrapped);
        var header = new ProtoWriter().Fixed(magic).U16(BinaryPrimitives.ReadUInt16BigEndian(ver)).Fixed(prefix).Bytes(wrapped).ToArray();
        var key = Convert.FromBase64String(protector.Unprotect(Encoding.UTF8.GetString(wrapped)));

        uint counter = 0;
        var sawEnd = false;
        while (fs.Position < fs.Length)
        {
            if (sawEnd) throw new CryptographicException("data after end record");
            fs.ReadExactly(lenBuf);
            var total = BinaryPrimitives.ReadUInt32BigEndian(lenBuf);
            if (total < 16 + 9 || total > 64u * 1024 * 1024) throw new InvalidDataException("corrupt record length");
            var blob = new byte[total];
            fs.ReadExactly(blob);
            var nonce = new byte[12];
            prefix.CopyTo(nonce, 0);
            BinaryPrimitives.WriteUInt32BigEndian(nonce.AsSpan(8), counter);
            var plain = new byte[total - 16];
            using (var gcm = new AesGcm(key, 16))
                gcm.Decrypt(nonce, blob.AsSpan(0, plain.Length), blob.AsSpan(plain.Length, 16), plain, EncryptedSessionRecorder.AadFor(header, counter));
            counter++;
            var type = (RecordType)plain[8];
            if (type == RecordType.End) sawEnd = true;
            yield return new RecordEntry(TimeSpan.FromMilliseconds(BinaryPrimitives.ReadUInt64BigEndian(plain)), type, plain[9..]);
        }
    }
}
