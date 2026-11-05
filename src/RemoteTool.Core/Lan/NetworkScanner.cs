using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace RemoteTool.Core.Lan;

/// <summary>One computer found with the RemoteTool port open.</summary>
public sealed record ScanHit(IPAddress Address, int Port, string? HostName)
{
    public string Endpoint => Address.AddressFamily == AddressFamily.InterNetworkV6 ? $"[{Address}]:{Port}" : $"{Address}:{Port}";
}

public sealed record ScanProgress(int Checked, int Total, int Found);

/// <summary>Result of parsing what the user typed: either addresses to check or a reason why not.</summary>
public sealed record ScanTargets(IReadOnlyList<IPAddress> Addresses, string? Error)
{
    public bool Ok => Error is null;
}

/// <summary>
/// "Which computers on our network have the RemoteTool port open?" - a plain TCP connect check, started by the user, limited to PRIVATE address space
/// (an internet scanner would be abusive), capped in size, bounded in speed, and it never sends any data: finding a port open proves nothing about who
/// is behind it, the real handshake still authenticates the peer. Accepts single IPs, CIDR (10.10.5.0/24), ranges (10.10.5.10-10.10.5.50 or 10.10.5.10-50)
/// and computer names (resolved through DNS; every resolved address must also be private).
/// </summary>
public static class NetworkScanner
{
    public const int MaxTargets = 4096;      // a /20
    public const int DefaultConcurrency = 128;

    public static bool IsPrivate(IPAddress a)
    {
        if (a.AddressFamily != AddressFamily.InterNetwork) return false;
        var b = a.GetAddressBytes();
        return b[0] == 10 || b[0] == 127 || (b[0] == 172 && b[1] is >= 16 and <= 31) || (b[0] == 192 && b[1] == 168)
            || (b[0] == 169 && b[1] == 254) || (b[0] == 100 && b[1] is >= 64 and <= 127);
    }

    private static uint ToUInt(IPAddress a) { var b = a.GetAddressBytes(); return ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3]; }
    private static IPAddress FromUInt(uint v) => new(new[] { (byte)(v >> 24), (byte)(v >> 16), (byte)(v >> 8), (byte)v });

    public static Task<ScanTargets> ParseAsync(string? text, CancellationToken ct = default) => ParseAsync(text, ResolveDns, ct);

    private static async Task<IPAddress[]> ResolveDns(string name, CancellationToken ct)
    {
        using var c = CancellationTokenSource.CreateLinkedTokenSource(ct);
        c.CancelAfter(TimeSpan.FromSeconds(4));
        return await Dns.GetHostAddressesAsync(name, c.Token).ConfigureAwait(false);
    }

    public static async Task<ScanTargets> ParseAsync(string? text, Func<string, CancellationToken, Task<IPAddress[]>> resolve, CancellationToken ct = default)
    {
        var tokens = (text ?? "").Split(new[] { ',', ';', ' ', '\t', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (tokens.Length == 0) return new ScanTargets(Array.Empty<IPAddress>(), "Nothing to scan: enter a network such as 10.10.5.0/24, a range, an IP address or a computer name.");
        var set = new SortedSet<uint>();
        foreach (var token in tokens)
        {
            List<IPAddress> found;
            string? err;
            if (token.Contains('/')) err = ParseCidr(token, out found);
            else if (token.Contains('-') && TryParseRange(token, out found, out err)) { }
            else if (IPAddress.TryParse(token, out var single)) { found = new() { single }; err = null; }
            else if (token.Any(char.IsDigit) && token.All(c => char.IsDigit(c) || c is '.' or '-')) { found = new(); err = $"'{token}' is not a valid address or range."; }
            else
            {
                found = new();
                try { found.AddRange(await resolve(token, ct).ConfigureAwait(false)); err = null; }
                catch (Exception e) when (e is SocketException or OperationCanceledException or ArgumentException) { err = $"Cannot find a computer named '{token}'."; }
                if (err is null && found.Count == 0) err = $"Cannot find a computer named '{token}'.";
            }
            if (err is not null) return new ScanTargets(Array.Empty<IPAddress>(), err);
            foreach (var a in found.Where(a => a.AddressFamily == AddressFamily.InterNetwork))
            {
                if (!IsPrivate(a)) return new ScanTargets(Array.Empty<IPAddress>(), $"{a} is not a private network address. Only internal networks (10.x, 172.16-31.x, 192.168.x) can be scanned.");
                set.Add(ToUInt(a));
                if (set.Count > MaxTargets) return new ScanTargets(Array.Empty<IPAddress>(), $"That is more than {MaxTargets} addresses. Use a smaller range (for example a /24 network).");
            }
        }
        if (set.Count == 0) return new ScanTargets(Array.Empty<IPAddress>(), "No IPv4 addresses to scan.");
        return new ScanTargets(set.Select(FromUInt).ToList(), null);
    }

    private static string? ParseCidr(string token, out List<IPAddress> list)
    {
        list = new();
        var parts = token.Split('/');
        if (parts.Length != 2 || !IPAddress.TryParse(parts[0], out var ip) || ip.AddressFamily != AddressFamily.InterNetwork || !int.TryParse(parts[1], out var prefix) || prefix is < 0 or > 32)
            return $"'{token}' is not a valid network (example: 10.10.5.0/24).";
        if (!IsPrivate(ip)) return $"{ip} is not a private network address. Only internal networks (10.x, 172.16-31.x, 192.168.x) can be scanned.";
        if (prefix < 20) return $"/{prefix} is too large (more than {MaxTargets} addresses). Use /20 or smaller, for example 10.10.5.0/24.";
        var size = 1u << (32 - prefix);
        var network = ToUInt(ip) & ~(size - 1);
        uint first = network, last = network + size - 1;
        if (prefix <= 30) { first++; last--; }       // skip network and broadcast addresses
        for (var v = first; v <= last; v++) list.Add(FromUInt(v));
        return null;
    }

    private static bool TryParseRange(string token, out List<IPAddress> list, out string? error)
    {
        list = new(); error = null;
        var i = token.IndexOf('-');
        if (i <= 0 || !IPAddress.TryParse(token[..i], out var a) || a.AddressFamily != AddressFamily.InterNetwork) return false;
        var rest = token[(i + 1)..];
        IPAddress b;
        if (int.TryParse(rest, out var lastOctet) && lastOctet is >= 0 and <= 255)
        {
            var bytes = a.GetAddressBytes(); bytes[3] = (byte)lastOctet; b = new IPAddress(bytes);
        }
        else if (!IPAddress.TryParse(rest, out b!) || b.AddressFamily != AddressFamily.InterNetwork) { error = $"'{token}' is not a valid range."; return true; }
        uint from = ToUInt(a), to = ToUInt(b);
        if (to < from) { error = $"'{token}': the range ends before it starts."; return true; }
        if (!IsPrivate(a) || !IsPrivate(b)) { error = $"{(IsPrivate(a) ? b : a)} is not a private network address. Only internal networks (10.x, 172.16-31.x, 192.168.x) can be scanned."; return true; }
        if ((ulong)to - from + 1 > MaxTargets) { error = $"That range is more than {MaxTargets} addresses. Use a smaller range."; return true; }
        for (var v = from; v <= to; v++) list.Add(FromUInt(v));
        return true;
    }

    /// <summary>This computer's own IPv4 networks as CIDR strings ("10.10.10.0/24"); anything bigger than a /22 is narrowed to the /24 around this PC's address.</summary>
    public static IReadOnlyList<string> LocalNetworks()
    {
        var result = new List<string>();
        try
        {
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus != OperationalStatus.Up || nic.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel) continue;
                foreach (var ua in nic.GetIPProperties().UnicastAddresses)
                {
                    if (ua.Address.AddressFamily != AddressFamily.InterNetwork || !IsPrivate(ua.Address) || ua.Address.ToString().StartsWith("169.254")) continue;
                    var prefix = Math.Clamp(ua.PrefixLength, 0, 32);
                    if (prefix < 22) prefix = 24;
                    var mask = prefix == 0 ? 0u : uint.MaxValue << (32 - prefix);
                    var cidr = $"{FromUInt(ToUInt(ua.Address) & mask)}/{prefix}";
                    if (!result.Contains(cidr)) result.Add(cidr);
                }
            }
        }
        catch (NetworkInformationException) { }
        return result;
    }

    /// <summary>Checks every address for an open TCP port. <paramref name="onHit"/> is called (possibly from several threads) as each is found.</summary>
    public static async Task ScanAsync(IReadOnlyList<IPAddress> targets, int port, Action<ScanHit> onHit, IProgress<ScanProgress>? progress = null,
        int concurrency = DefaultConcurrency, TimeSpan? connectTimeout = null, bool resolveNames = true, CancellationToken ct = default)
    {
        var timeout = connectTimeout ?? TimeSpan.FromMilliseconds(700);
        int done = 0, found = 0;
        var total = targets.Count;
        await Parallel.ForEachAsync(targets, new ParallelOptions { MaxDegreeOfParallelism = Math.Clamp(concurrency, 1, 256), CancellationToken = ct }, async (ip, token) =>
        {
            try
            {
                if (await IsOpenAsync(ip, port, timeout, token).ConfigureAwait(false))
                {
                    var name = resolveNames ? await ReverseLookupAsync(ip, token).ConfigureAwait(false) : null;
                    Interlocked.Increment(ref found);
                    onHit(new ScanHit(ip, port, name));
                }
            }
            finally { progress?.Report(new ScanProgress(Interlocked.Increment(ref done), total, Volatile.Read(ref found))); }
        }).ConfigureAwait(false);
    }

    private static async Task<bool> IsOpenAsync(IPAddress ip, int port, TimeSpan timeout, CancellationToken ct)
    {
        using var tcp = new TcpClient(ip.AddressFamily);
        using var c = CancellationTokenSource.CreateLinkedTokenSource(ct);
        c.CancelAfter(timeout);
        try { await tcp.ConnectAsync(ip, port, c.Token).ConfigureAwait(false); return true; }
        catch (Exception e) when (e is SocketException or OperationCanceledException && !ct.IsCancellationRequested) { return false; }
    }

    private static async Task<string?> ReverseLookupAsync(IPAddress ip, CancellationToken ct)
    {
        using var c = CancellationTokenSource.CreateLinkedTokenSource(ct);
        c.CancelAfter(TimeSpan.FromSeconds(2));
        try
        {
            var e = await Dns.GetHostEntryAsync(ip.ToString(), c.Token).ConfigureAwait(false);
            return string.IsNullOrWhiteSpace(e.HostName) || e.HostName == ip.ToString() ? null : e.HostName;
        }
        catch (Exception e) when (e is SocketException or OperationCanceledException && !ct.IsCancellationRequested) { return null; }
    }
}
