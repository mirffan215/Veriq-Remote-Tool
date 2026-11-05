using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using RemoteTool.Core.Protocol;
using RemoteTool.Core.Security;
using RemoteTool.Core.Session;

namespace RemoteTool.Core.Relay;

/// <param name="Fingerprint">Optional hex SHA-256 of the relay certificate to pin (several, comma-separated, are accepted).
/// Empty = require a publicly trusted certificate.</param>
public sealed record RelayEndpoint(string Host, int Port, string AccessKey, string Fingerprint = "")
{
    public static bool TryParse(string address, string accessKey, string fingerprint, out RelayEndpoint? ep)
    {
        ep = null;
        var s = address.Trim();
        var idx = s.LastIndexOf(':');
        if (idx <= 0 || !int.TryParse(s[(idx + 1)..], out var port) || port is <= 0 or > 65535) return false;
        var host = s[..idx];
        if (host.Length == 0) return false;
        ep = new RelayEndpoint(host, port, accessKey, fingerprint);
        return true;
    }

    /// <summary>Parses "relay1:8443, relay2:8443" (comma or semicolon separated). Returns false if any entry is invalid or none given.</summary>
    public static bool TryParseList(string addresses, string accessKey, string fingerprint, out IReadOnlyList<RelayEndpoint> list)
    {
        var result = new List<RelayEndpoint>();
        list = result;
        foreach (var part in addresses.Split(new[] { ',', ';' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (!TryParse(part, accessKey, fingerprint, out var ep)) return false;
            result.Add(ep!);
        }
        return result.Count > 0;
    }
}

/// <summary>Outer TLS link to the relay (protects ID + access key on the wire; the peer-to-peer TLS runs inside it).</summary>
public static class RelayClient
{
    public static readonly TimeSpan ReplyTimeout = TimeSpan.FromSeconds(25);

    public static async Task<Stream> OpenAsync(RelayEndpoint ep, CancellationToken ct)
    {
        var tcp = new TcpClient { NoDelay = true };
        try
        {
            using var c = CancellationTokenSource.CreateLinkedTokenSource(ct);
            c.CancelAfter(TimeSpan.FromSeconds(15));
            await tcp.ConnectAsync(ep.Host, ep.Port, c.Token).ConfigureAwait(false);
            var ssl = new SslStream(tcp.GetStream(), false, (_, cert, _, errors) => Validate(ep, cert, errors));
            await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = ep.Host,
                EnabledSslProtocols = TlsPolicy.Protocols,
                CipherSuitesPolicy = TlsPolicy.OfferedSuites(),
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
            }, c.Token).ConfigureAwait(false);
            TlsPolicy.Require(ssl);
            return ssl;
        }
        catch { tcp.Dispose(); throw; }
    }

    private static bool Validate(RelayEndpoint ep, X509Certificate? cert, SslPolicyErrors errors)
    {
        if (cert is null) return false;
        if (string.IsNullOrWhiteSpace(ep.Fingerprint)) return errors == SslPolicyErrors.None;
        try
        {
            var actual = SHA256.HashData(cert.GetRawCertData());
            var ok = false;
            foreach (var one in ep.Fingerprint.Split(new[] { ',', ';' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                ok |= CryptographicOperations.FixedTimeEquals(Convert.FromHexString(one.Replace(":", "").Replace(" ", "")), actual);
            return ok;
        }
        catch (FormatException) { return false; }
    }

    /// <summary>Asks the relay to pair us with host <paramref name="id"/>. Returns the spliced raw stream.</summary>
    public static async Task<Stream> ConnectToHostAsync(RelayEndpoint ep, string id, CancellationToken ct)
    {
        Stream s;
        try { s = await OpenAsync(ep, ct).ConfigureAwait(false); }
        catch (Exception e) when (e is not OperationCanceledException || !ct.IsCancellationRequested)
        {
            throw new ConnectFailedException(ConnectFailure.Network, "Cannot reach the relay server.", e);
        }
        try
        {
            var w = new FrameWriter(s);
            var r = new FrameReader(s, MessageTypes.IsKnownRelay, RelayLimits.MaxControlPayload);
            using var c = CancellationTokenSource.CreateLinkedTokenSource(ct);
            c.CancelAfter(ReplyTimeout);
            await w.WriteAsync(RelayMessageType.Connect, new ConnectMessage(ep.AccessKey, id).Serialize(), c.Token).ConfigureAwait(false);
            var reply = await r.ReadAsync(c.Token).ConfigureAwait(false);
            if (reply.Type == (byte)RelayMessageType.Ready) return s;
            throw new ConnectFailedException(ConnectFailure.NotFound, "ID not found or offline.");
        }
        catch (Exception e)
        {
            await s.DisposeAsync().ConfigureAwait(false);
            if (e is ConnectFailedException) throw;
            if (e is OperationCanceledException && ct.IsCancellationRequested) throw;
            throw new ConnectFailedException(ConnectFailure.NotFound, "ID not found or offline.", e);
        }
    }

    /// <summary>Failover: tries each relay in order until one pairs us with the host.</summary>
    public static async Task<Stream> ConnectToHostAsync(IReadOnlyList<RelayEndpoint> relays, string id, CancellationToken ct)
    {
        ConnectFailedException? last = null;
        var anyNotFound = false;
        foreach (var r in relays)
        {
            try { return await ConnectToHostAsync(r, id, ct).ConfigureAwait(false); }
            catch (ConnectFailedException e) { last = e; anyNotFound |= e.Failure == ConnectFailure.NotFound; }
        }
        // A relay that answered "not found" beats "cannot reach": the host is simply offline.
        throw anyNotFound ? new ConnectFailedException(ConnectFailure.NotFound, "ID not found or offline.") : last ?? new ConnectFailedException(ConnectFailure.Network, "No relay configured.");
    }
}
