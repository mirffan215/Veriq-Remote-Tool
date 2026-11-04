using Microsoft.AspNetCore.Connections;
using System.Net;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using RemoteTool.Core.Security;

namespace RemoteTool.Relay;

public static class RelayHost
{
    public static WebApplication Build(string[] args, Action<RelayOptions>? tweak = null, ISpliceObserver? observer = null)
    {
        var builder = WebApplication.CreateSlimBuilder(args);
        builder.Configuration.AddJsonFile("appsettings.json", optional: true).AddEnvironmentVariables().AddCommandLine(args);
        var options = new RelayOptions();
        builder.Configuration.GetSection("Relay").Bind(options);
        tweak?.Invoke(options);
        builder.Services.AddSingleton(options);
        builder.Services.AddSingleton(sp => new RelayEngine(options, sp.GetRequiredService<ILoggerFactory>().CreateLogger("Relay"), observer: observer));
        builder.Services.AddSingleton<RelayConnectionHandler>();
        builder.Logging.AddSimpleConsole(o => { o.TimestampFormat = "yyyy-MM-ddTHH:mm:ssZ "; o.UseUtcTimestamp = true; });
        builder.Services.Configure<HostOptions>(o => o.ShutdownTimeout = TimeSpan.FromSeconds(20));

        var cert = LoadCertificate(options);
        builder.WebHost.ConfigureKestrel(k =>
        {
            k.AddServerHeader = false;
            k.Limits.MaxConcurrentConnections = options.MaxConnections;
            k.Listen(IPAddress.Any, options.Port, lo =>
            {
                lo.UseHttps(https =>
                {
                    https.ServerCertificate = cert;
                    https.SslProtocols = SslProtocols.Tls13;
                });
                lo.UseConnectionHandler<RelayConnectionHandler>();
            });
            if (options.HealthPort > 0) k.Listen(IPAddress.Loopback, options.HealthPort);
        });

        var app = builder.Build();
        app.MapGet("/healthz", (RelayEngine e) => Results.Ok(new { status = "ok", hosts = e.RegisteredHosts, sessions = e.ActiveSessions }));
        var log = app.Services.GetRequiredService<ILoggerFactory>().CreateLogger("Relay");
        log.LogInformation("Relay TLS certificate SHA-256 fingerprint (pin this in clients): {Fingerprint}", Convert.ToHexString(SHA256.HashData(cert.GetRawCertData())));
        if (string.IsNullOrEmpty(options.AccessKey))
            log.LogWarning("Relay:AccessKey is empty - ANY client can register IDs and relay traffic. Set an access key.");
        app.Lifetime.ApplicationStopping.Register(() => app.Services.GetRequiredService<RelayEngine>().DropAll());
        return app;
    }

    private static X509Certificate2 LoadCertificate(RelayOptions o)
    {
        if (!string.IsNullOrWhiteSpace(o.CertificatePath))
            return new X509Certificate2(o.CertificatePath, string.IsNullOrEmpty(o.CertificatePassword) ? null : o.CertificatePassword);

        var path = Path.Combine(o.DataDirectory, "relay-selfsigned.pfx");
        Directory.CreateDirectory(o.DataDirectory);
        if (File.Exists(path)) return new X509Certificate2(path, (string?)null, X509KeyStorageFlags.Exportable);
        using var eph = EphemeralCertificate.Create("RemoteTool Relay", TimeSpan.FromDays(3650));
        File.WriteAllBytes(path, eph.Certificate.Export(X509ContentType.Pfx));
        if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        return new X509Certificate2(path, (string?)null, X509KeyStorageFlags.Exportable);
    }
}
