namespace RemoteTool.Relay;

/// <summary>Bound from the "Relay" configuration section (appsettings.json or RELAY__* environment variables).</summary>
public sealed class RelayOptions
{
    public int Port { get; set; } = 8443;
    /// <summary>Loopback-only HTTP port for /healthz. 0 disables it.</summary>
    public int HealthPort { get; set; } = 8081;
    /// <summary>Shared secret clients must present. Empty = open relay (a warning is logged).</summary>
    public string AccessKey { get; set; } = "";
    public string CertificatePath { get; set; } = "";
    public string CertificatePassword { get; set; } = "";
    /// <summary>Where the auto-generated self-signed certificate is persisted when no CertificatePath is set.</summary>
    public string DataDirectory { get; set; } = "data";
    public int MaxConcurrentSessions { get; set; } = 200;
    public int MaxRegisteredHosts { get; set; } = 10_000;
    public int MaxConnections { get; set; } = 2_000;
    public int IdleTimeoutSeconds { get; set; } = 90;
    public int PendingTimeoutSeconds { get; set; } = 15;
    public int PingIntervalSeconds { get; set; } = 10;
    public int ConnectsPerMinutePerIp { get; set; } = 10;
    public int FailedLookupsPerMinutePerIp { get; set; } = 5;
    public int RegistrationsPerMinutePerIp { get; set; } = 30;
    public int AcceptsPerMinutePerIp { get; set; } = 60;
}
