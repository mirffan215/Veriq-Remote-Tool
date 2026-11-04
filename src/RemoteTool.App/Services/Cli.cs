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
