using System.Security.Cryptography;
using RemoteTool.Core.Audit;
using RemoteTool.Core.Protocol;

namespace RemoteTool.Core.Session;

public sealed record FileOfferInfo(string PeerName, string FileName, long Size);

public interface IFileTransferPrompt
{
    /// <summary>Asks the local user whether an incoming file may be saved. Must default to "no".</summary>
    Task<bool> ConfirmAsync(FileOfferInfo info, CancellationToken ct);
}

public sealed record FileTransferOptions(string ReceiveDirectory, long MaxBytes = 1L << 30, int ChunkSize = ProtocolConstants.DefaultFileChunk);

public enum FileSendOutcome { Completed, Rejected, HashMismatch, Failed, Cancelled }

/// <summary>
/// Chunked, integrity-checked file transfer used by both roles. Receiver: per-transfer user confirmation, sanitized name,
/// dedicated folder, <c>.part</c> file renamed only after the SHA-256 matches. Sender: hashes first, streams 64 KiB chunks.
/// One incoming and one outgoing transfer at a time.
/// </summary>
public sealed class FileTransferService : IDisposable
{
    private sealed class Incoming
    {
        public uint Id; public string PartPath = ""; public string FinalPath = ""; public long Size; public long Received;
        public byte[] ExpectedHash = Array.Empty<byte>(); public FileStream? Stream; public IncrementalHash? Hash; public bool Active;
    }

    private readonly FrameWriter _writer;
    private readonly IFileTransferPrompt _prompt;
    private readonly FileTransferOptions _opt;
    private readonly IAuditLog _audit;
    private readonly string _peer;
    private readonly object _gate = new();
    private readonly SemaphoreSlim _sendGate = new(1, 1);
    private readonly CancellationTokenSource _lifetime = new();
    private Incoming? _in;
    private uint _nextId;
    private uint _sendId;
    private TaskCompletionSource<FileAckMessage>? _offerAck, _doneAck;

    public FileTransferService(FrameWriter writer, IFileTransferPrompt prompt, FileTransferOptions options, IAuditLog audit, string peerName)
    {
        _writer = writer;
        _prompt = prompt;
        _opt = options;
        _audit = audit;
        _peer = peerName;
    }

    /// <summary>Raised when a file was received and verified (final path).</summary>
    public event Action<string>? FileReceived;
    internal Task PendingOffer { get; private set; } = Task.CompletedTask;

    // ---------------------------------------------------------------- receiving / dispatch

    public async Task HandleAsync(Frame f, CancellationToken ct)
    {
        switch ((MessageType)f.Type)
        {
            case MessageType.FileOffer: PendingOffer = ProcessOfferAsync(FileOfferMessage.Parse(f.Payload)); break; // never block the read loop on the user
            case MessageType.FileChunk: await ProcessChunkAsync(FileChunkMessage.Parse(f.Payload), ct).ConfigureAwait(false); break;
            case MessageType.FileAck: ProcessAck(FileAckMessage.Parse(f.Payload)); break;
        }
    }

    private async Task ProcessOfferAsync(FileOfferMessage o)
    {
        var ct = _lifetime.Token;
        try
        {
            var safe = FileNameSanitizer.Sanitize(o.Name);
            if (o.Size > (ulong)_opt.MaxBytes)
            {
                _audit.Write("file_rejected", ("name", safe), ("size", (long)Math.Min(o.Size, long.MaxValue)), ("reason", "too-large"));
                await Ack(o.TransferId, FileStatus.Error, 0, ct).ConfigureAwait(false);
                return;
            }
            lock (_gate)
            {
                if (_in is not null) { _ = Ack(o.TransferId, FileStatus.Reject, 0, ct); return; }
                _in = new Incoming { Id = o.TransferId }; // reserve the slot while the user decides
            }
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(TimeSpan.FromSeconds(60));
            bool ok;
            try { ok = await _prompt.ConfirmAsync(new FileOfferInfo(_peer, safe, (long)o.Size), timeout.Token).ConfigureAwait(false); }
            catch (OperationCanceledException) { ok = false; }
            if (!ok)
            {
                ClearIncoming(o.TransferId);
                _audit.Write("file_rejected", ("name", safe), ("size", (long)o.Size), ("reason", "user"));
                await Ack(o.TransferId, FileStatus.Reject, 0, ct).ConfigureAwait(false);
                return;
            }
            Directory.CreateDirectory(_opt.ReceiveDirectory);
            var final = FileNameSanitizer.UniquePath(_opt.ReceiveDirectory, safe);
            var part = final + ".part";
            var inc = new Incoming
            {
                Id = o.TransferId, PartPath = part, FinalPath = final, Size = (long)o.Size, ExpectedHash = o.Sha256,
                Stream = new FileStream(part, FileMode.Create, FileAccess.Write, FileShare.None),
                Hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256), Active = true,
            };
            lock (_gate) _in = inc;
            _audit.Write("file_accepted", ("name", safe), ("size", inc.Size), ("from", _peer));
            await Ack(o.TransferId, FileStatus.Accept, 0, ct).ConfigureAwait(false);
            if (inc.Size == 0) await FinishAsync(inc, ct).ConfigureAwait(false);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or OperationCanceledException or ObjectDisposedException)
        {
            ClearIncoming(o.TransferId);
            try { await Ack(o.TransferId, FileStatus.Error, 0, CancellationToken.None).ConfigureAwait(false); } catch { }
        }
    }

    private async Task ProcessChunkAsync(FileChunkMessage c, CancellationToken ct)
    {
        Incoming? inc;
        lock (_gate) inc = _in;
        if (inc is null || !inc.Active || inc.Id != c.TransferId)
        {
            await Ack(c.TransferId, FileStatus.Error, 0, ct).ConfigureAwait(false); // unsolicited chunk: tell the sender to stop
            return;
        }
        if ((ulong)inc.Received != c.Offset || inc.Received + c.Data.Length > inc.Size)
        {
            Abort(inc, "bad-offset");
            await Ack(c.TransferId, FileStatus.Error, (ulong)inc.Received, ct).ConfigureAwait(false);
            return;
        }
        try
        {
            await inc.Stream!.WriteAsync(c.Data, ct).ConfigureAwait(false);
            inc.Hash!.AppendData(c.Data);
            inc.Received += c.Data.Length;
        }
        catch (IOException)
        {
            Abort(inc, "disk-error");
            await Ack(c.TransferId, FileStatus.Error, 0, ct).ConfigureAwait(false);
            return;
        }
        if (inc.Received == inc.Size) await FinishAsync(inc, ct).ConfigureAwait(false);
    }

    private async Task FinishAsync(Incoming inc, CancellationToken ct)
    {
        inc.Active = false;
        await inc.Stream!.DisposeAsync().ConfigureAwait(false);
        var actual = inc.Hash!.GetHashAndReset();
        inc.Hash.Dispose();
        if (!CryptographicOperations.FixedTimeEquals(actual, inc.ExpectedHash))
        {
            TryDelete(inc.PartPath);
            ClearIncoming(inc.Id);
            _audit.Write("file_failed", ("name", Path.GetFileName(inc.FinalPath)), ("reason", "hash-mismatch"));
            await Ack(inc.Id, FileStatus.HashMismatch, (ulong)inc.Received, ct).ConfigureAwait(false);
            return;
        }
        File.Move(inc.PartPath, inc.FinalPath);
        MarkFromInternet(inc.FinalPath);
        ClearIncoming(inc.Id);
        _audit.Write("file_received", ("name", Path.GetFileName(inc.FinalPath)), ("size", inc.Size), ("sha256", Convert.ToHexString(actual)), ("from", _peer));
        FileReceived?.Invoke(inc.FinalPath);
        await Ack(inc.Id, FileStatus.Complete, (ulong)inc.Received, ct).ConfigureAwait(false);
    }

    /// <summary>Adds the Zone.Identifier stream (ZoneId=3) so Windows SmartScreen treats the file as downloaded.</summary>
    private static void MarkFromInternet(string path)
    {
        if (!OperatingSystem.IsWindows()) return;
        try { File.WriteAllText(path + ":Zone.Identifier", "[ZoneTransfer]\r\nZoneId=3\r\n"); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }

    private void ProcessAck(FileAckMessage a)
    {
        if (a.TransferId != Volatile.Read(ref _sendId)) { CancelIncomingIfMatches(a); return; }
        switch (a.Status)
        {
            case FileStatus.Accept: _offerAck?.TrySetResult(a); break;
            case FileStatus.Complete or FileStatus.HashMismatch: _doneAck?.TrySetResult(a); break;
            default: _offerAck?.TrySetResult(a); _doneAck?.TrySetResult(a); break; // reject / error / cancel end the transfer
        }
    }

    private void CancelIncomingIfMatches(FileAckMessage a)
    {
        if (a.Status is not (FileStatus.Cancel or FileStatus.Error)) return;
        Incoming? inc;
        lock (_gate) inc = _in;
        if (inc is not null && inc.Id == a.TransferId) Abort(inc, "cancelled-by-peer");
    }

    private void Abort(Incoming inc, string reason)
    {
        inc.Active = false;
        try { inc.Stream?.Dispose(); } catch { }
        inc.Hash?.Dispose();
        TryDelete(inc.PartPath);
        ClearIncoming(inc.Id);
        _audit.Write("file_failed", ("name", Path.GetFileName(inc.FinalPath)), ("reason", reason));
    }

    private void ClearIncoming(uint id) { lock (_gate) if (_in is not null && _in.Id == id) _in = null; }
    private static void TryDelete(string p) { try { if (p.Length > 0) File.Delete(p); } catch { } }
    private Task Ack(uint id, FileStatus s, ulong received, CancellationToken ct) => _writer.WriteAsync(MessageType.FileAck, new FileAckMessage(id, s, received).Serialize(), ct);

    // ---------------------------------------------------------------- sending

    public async Task<FileSendOutcome> SendAsync(string path, IProgress<long>? progress, CancellationToken ct)
    {
        await _sendGate.WaitAsync(ct).ConfigureAwait(false);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct, _lifetime.Token);
        var token = linked.Token;
        var id = Interlocked.Increment(ref _nextId);
        try
        {
            var info = new FileInfo(path);
            if (!info.Exists) return FileSendOutcome.Failed;
            if (info.Length > _opt.MaxBytes) return FileSendOutcome.Failed;
            byte[] hash;
            await using (var hs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, true))
                hash = await SHA256.HashDataAsync(hs, token).ConfigureAwait(false);

            _offerAck = new(TaskCreationOptions.RunContinuationsAsynchronously);
            _doneAck = new(TaskCreationOptions.RunContinuationsAsynchronously);
            Volatile.Write(ref _sendId, id);
            await _writer.WriteAsync(MessageType.FileOffer, new FileOfferMessage(id, info.Name, (ulong)info.Length, hash).Serialize(), token).ConfigureAwait(false);
            var accept = await _offerAck.Task.WaitAsync(TimeSpan.FromSeconds(75), token).ConfigureAwait(false);
            if (accept.Status == FileStatus.Reject) return FileSendOutcome.Rejected;
            if (accept.Status != FileStatus.Accept) return FileSendOutcome.Failed;

            var buf = new byte[_opt.ChunkSize];
            long sent = 0;
            await using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, true))
            {
                int n;
                while ((n = await fs.ReadAsync(buf, token).ConfigureAwait(false)) > 0)
                {
                    if (_doneAck.Task.IsCompleted) break; // receiver aborted
                    await _writer.WriteAsync(MessageType.FileChunk, new FileChunkMessage(id, (ulong)sent, buf.AsSpan(0, n).ToArray()).Serialize(), token).ConfigureAwait(false);
                    sent += n;
                    progress?.Report(sent);
                }
            }
            var done = await _doneAck.Task.WaitAsync(TimeSpan.FromSeconds(60), token).ConfigureAwait(false);
            var outcome = done.Status switch { FileStatus.Complete => FileSendOutcome.Completed, FileStatus.HashMismatch => FileSendOutcome.HashMismatch, _ => FileSendOutcome.Failed };
            _audit.Write(outcome == FileSendOutcome.Completed ? "file_sent" : "file_failed", ("name", info.Name), ("size", info.Length), ("sha256", Convert.ToHexString(hash)), ("to", _peer));
            return outcome;
        }
        catch (OperationCanceledException)
        {
            try { await _writer.WriteAsync(MessageType.FileAck, new FileAckMessage(id, FileStatus.Cancel, 0).Serialize(), CancellationToken.None).ConfigureAwait(false); } catch { }
            return FileSendOutcome.Cancelled;
        }
        catch (Exception e) when (e is TimeoutException or IOException or UnauthorizedAccessException) { return FileSendOutcome.Failed; }
        finally { _sendGate.Release(); }
    }

    /// <summary>Called when the session ends: cancels sends and removes any partial incoming file.</summary>
    public void Dispose()
    {
        _lifetime.Cancel();
        Incoming? inc;
        lock (_gate) inc = _in;
        if (inc is not null && inc.PartPath.Length > 0) Abort(inc, "session-ended");
    }
}
