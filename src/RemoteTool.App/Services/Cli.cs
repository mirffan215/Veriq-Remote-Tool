using System.Windows;
using RemoteTool.Capture;
using RemoteTool.Core.Audit;
using RemoteTool.Core.Config;
using RemoteTool.Service;
using RemoteTool.Service.Windows;
using RemoteTool.Video;

namespace RemoteTool.App;

/// <summary>Command-line utilities (no UI). Output goes to a file or a message box because the exe is a WinExe.</summary>
internal static class Cli
{
    public static int BenchCodec(string? file)
    {
        var path = file ?? Path.Combine(Path.GetTempPath(), "RemoteTool-codec-benchmark.md");
        using (var w = new StreamWriter(path))
        {
            w.WriteLine($"# RemoteTool codec benchmark {DateTime.Now:yyyy-MM-dd HH:mm}  ({Environment.OSVersion}, {Environment.ProcessorCount} cores, {CodecBenchmark.Resolution})\n");
            var res = CodecBenchmark.Run(() => H264Support.CreateEncoder(1280, 720, 30, 2500, out _));
            CodecBenchmark.Print(res, w);
            if (!res.Any(r => r.Codec.StartsWith("H.264"))) w.WriteLine("\nNo H.264 encoder could be created on this machine (Media Feature Pack missing?). Sessions will use the tile codec.");
        }
        MessageBox.Show("Benchmark written to:\n" + path, "RemoteTool");
        return 0;
    }

    /// <summary>
    /// Loopback TLS 1.3 mutual-authentication test with the exact code the app uses. Tells at once whether this Windows can do the handshake.
    /// Writes the OS details and the full exception chain to a file (the exe has no console).
    /// </summary>
    public static int TlsSelfTest(string? file)
    {
        var path = file ?? Path.Combine(Path.GetTempPath(), "RemoteTool-tls-selftest.txt");
        var sb = new System.Text.StringBuilder();
        sb.AppendLine($"RemoteTool TLS self-test {DateTime.Now:yyyy-MM-dd HH:mm}");
        sb.AppendLine($"OS: {Environment.OSVersion}   .NET: {Environment.Version}   RemoteTool {typeof(Cli).Assembly.GetName().Version}");
        try
        {
            var ok = RunTlsLoopback().GetAwaiter().GetResult();
            sb.AppendLine("RESULT: OK - " + ok);
        }
        catch (Exception e)
        {
            sb.AppendLine("RESULT: FAILED");
            for (Exception? x = e; x is not null; x = x.InnerException)
                sb.AppendLine($"  {x.GetType().FullName}: {x.Message}  (HResult 0x{x.HResult:X8})");
        }
        File.WriteAllText(path, sb.ToString());
        MessageBox.Show(sb.ToString() + "\nSaved to: " + path, "RemoteTool");
        return 0;
    }

    private static async Task<string> RunTlsLoopback()
    {
        using var srvCert = RemoteTool.Core.Security.EphemeralCertificate.Create("selftest-host");
        using var cliCert = RemoteTool.Core.Security.EphemeralCertificate.Create("selftest-viewer");
        var listener = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
        listener.Start();
        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            var port = ((System.Net.IPEndPoint)listener.LocalEndpoint).Port;
            var serverTask = Task.Run(async () =>
            {
                using var c = await listener.AcceptTcpClientAsync(cts.Token);
                await using var ch = await RemoteTool.Core.Security.TlsChannel.AcceptAsync(c.GetStream(), srvCert.Certificate, cts.Token);
                return "server side ok";
            });
            using var tcp = new System.Net.Sockets.TcpClient();
            await tcp.ConnectAsync(System.Net.IPAddress.Loopback, port, cts.Token);
            await using var client = await RemoteTool.Core.Security.TlsChannel.ConnectAsync(tcp.GetStream(), cliCert.Certificate, cts.Token);
            return "TLS 1.3 with mutual certificates works on this computer (" + await serverTask + ")";
        }
        finally { listener.Stop(); }
    }

    public static int ExportRecording(string[] args)
    {
        var i = Array.IndexOf(args, "--export-recording");
        if (i + 2 >= args.Length) { MessageBox.Show("Usage: RemoteTool.exe --export-recording <file.rtrec> <output folder>", "RemoteTool"); return 2; }
        try
        {
            // Recordings written by the service are protected with the machine key: run this elevated on the same PC. User-mode recordings use the user key.
            ISecretProtector prot = args.Contains("--machine") ? new MachineDpapiProtector() : new RemoteTool.App.Services.DpapiProtector();
            var s = RecordingExporter.Export(args[i + 1], prot, args[i + 2], TimeSpan.FromSeconds(5));
            MessageBox.Show($"Viewer: {s.Viewer}\nEnded: {s.Reason}\nImages: {s.ImagesWritten}\nH.264 bytes: {s.H264Bytes}\n\nFolder: {args[i + 2]}", "RemoteTool");
            return 0;
        }
        catch (Exception e) when (e is System.Security.Cryptography.CryptographicException or InvalidDataException or IOException)
        {
            MessageBox.Show("Cannot read this recording: " + e.Message + "\n(Wrong machine/user, or the file was modified.)", "RemoteTool");
            return 1;
        }
    }

    /// <summary>Headless install/configure for Intune/SCCM. Must run elevated (SYSTEM or an admin). Exit code 0 = success; the log is in %ProgramData%\RemoteTool\configure-service.log.</summary>
    public static int ConfigureService(string[] args)
    {
        var logFile = Path.Combine(ServicePaths.Default().Root, "configure-service.log");
        void Log(string m) { try { Directory.CreateDirectory(Path.GetDirectoryName(logFile)!); File.AppendAllText(logFile, $"{DateTime.UtcNow:O} {m}\n"); } catch (IOException) { } }
        var (input, error) = ServiceSetupArgs.Parse(args, Environment.GetEnvironmentVariable);
        if (input is null) { Log("invalid arguments: " + error); return 2; }
        try { var id = ServiceSetup.Apply(input, Log); Log("configured; service ID " + id); return 0; }
        catch (Exception e) when (e is InvalidOperationException or UnauthorizedAccessException or IOException or ArgumentException) { Log("failed: " + e.Message); return 1; }
    }

    /// <summary>
    /// Headless service control for the MSI (runs as SYSTEM from Windows Installer): <c>--service-control remove|stop|start</c>.
    /// Never shows UI. Exit 0 also when the service does not exist (nothing to do).
    /// </summary>
    public static int ServiceControl(string[] args)
    {
        var i = Array.IndexOf(args, "--service-control");
        var action = i + 1 < args.Length ? args[i + 1] : "";
        var logFile = Path.Combine(ServicePaths.Default().Root, "service-control.log");
        void Log(string m) { try { Directory.CreateDirectory(Path.GetDirectoryName(logFile)!); File.AppendAllText(logFile, $"{DateTime.UtcNow:O} {action}: {m}\n"); } catch (IOException) { } }
        try
        {
            switch (action)
            {
                case "remove": ServiceInstaller.RemoveService(Log); return 0;
                case "stop": if (ServiceInstaller.IsInstalled()) ServiceInstaller.Stop(Log); return 0;
                case "start": if (ServiceInstaller.IsInstalled()) ServiceInstaller.Start(Log); return 0;
                default: Log("unknown action"); return 2;
            }
        }
        catch (Exception e) when (e is InvalidOperationException or UnauthorizedAccessException or IOException) { Log("failed: " + e.Message); return 1; }
    }

    public static int VerifyAudit(string[] args)
    {
        var i = Array.IndexOf(args, "--verify-audit");
        var dir = i + 1 < args.Length ? args[i + 1] : ServicePaths.Default().LogDir;
        var role = i + 2 < args.Length ? args[i + 2] : "service";
        var r = AuditVerifier.Verify(dir, role);
        MessageBox.Show(r.Ok ? $"Audit log '{role}' OK: {r.Lines} lines, hash chain intact." : $"AUDIT LOG TAMPERED OR DAMAGED\n{r.Problem}\n{r.File}, line {r.LineNumber}", "RemoteTool");
        return r.Ok ? 0 : 1;
    }
}
