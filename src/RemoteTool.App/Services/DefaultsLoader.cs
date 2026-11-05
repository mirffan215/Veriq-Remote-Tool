using System.Reflection;
using RemoteTool.Core.Config;

namespace RemoteTool.App.Services;

/// <summary>Finds the company defaults: environment/command line, a file next to the exe, then the values embedded at build time (highest priority first).</summary>
public static class DefaultsLoader
{
    public static DeploymentDefaults Load(string exeDirectory, string[] args)
    {
        string? Arg(string name) { var i = Array.IndexOf(args, name); return i >= 0 && i + 1 < args.Length ? args[i + 1] : null; }
        var fromEnvOrArgs = new DeploymentDefaults(
            (Arg("--relay") ?? Environment.GetEnvironmentVariable("REMOTETOOL_RELAY") ?? "").Trim(),
            (Arg("--relay-fp") ?? Environment.GetEnvironmentVariable("REMOTETOOL_RELAY_FP") ?? "").Trim(),
            (Arg("--relay-key") ?? Environment.GetEnvironmentVariable("REMOTETOOL_RELAY_KEY") ?? "").Trim());

        DeploymentDefaults fromFile = DeploymentDefaults.Empty;
        try
        {
            var f = Path.Combine(exeDirectory, "RemoteTool.defaults.json");
            if (File.Exists(f)) fromFile = DeploymentDefaults.Parse(File.ReadAllText(f));
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }

        DeploymentDefaults embedded = DeploymentDefaults.Empty;
        using (var s = typeof(DefaultsLoader).Assembly.GetManifestResourceStream("RemoteTool.defaults.json"))
            if (s is not null) { using var r = new StreamReader(s); embedded = DeploymentDefaults.Parse(r.ReadToEnd()); }

        return DeploymentDefaults.Merge(fromEnvOrArgs, fromFile, embedded);
    }
}
