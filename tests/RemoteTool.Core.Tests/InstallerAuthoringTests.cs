using System.Text.RegularExpressions;
using System.Xml.Linq;

namespace RemoteTool.Core.Tests;

/// <summary>
/// The MSI can only be built on Windows (WiX), so these tests guard its authoring on every platform: well-formed XML (a "--" inside a comment already
/// broke it once), the pinned upgrade identity, the Windows 11 gate, and the rule that the relay ACCESS KEY never becomes an MSI property.
/// The real build + install + uninstall is exercised by the Windows CI job.
/// </summary>
public class InstallerAuthoringTests
{
    private static string Root()
    {
        var d = new DirectoryInfo(AppContext.BaseDirectory);
        while (d is not null && !File.Exists(Path.Combine(d.FullName, "RemoteTool.sln"))) d = d.Parent;
        return d?.FullName ?? throw new InvalidOperationException("repo root not found");
    }

    private static readonly XNamespace W = "http://wixtoolset.org/schemas/v4/wxs";
    private static string Dir => Path.Combine(Root(), "deploy", "RemoteTool.Installer");
    private static XDocument Wxs() => XDocument.Load(Path.Combine(Dir, "Package.wxs"));

    [Fact]
    public void AuthoringFilesAreWellFormedXml_AndCommentsContainNoDoubleHyphen()
    {
        foreach (var f in new[] { "Package.wxs", "RemoteTool.Installer.wixproj" })
        {
            var text = File.ReadAllText(Path.Combine(Dir, f));
            XDocument.Parse(text);                                             // throws on '--' in a comment, unclosed tags, ...
            foreach (Match c in Regex.Matches(text, "<!--(.*?)-->", RegexOptions.Singleline))
                Assert.DoesNotContain("--", c.Groups[1].Value);
        }
        Assert.True(File.Exists(Path.Combine(Dir, "License.rtf")));
        Assert.StartsWith("{\\rtf1", File.ReadAllText(Path.Combine(Dir, "License.rtf")));
    }

    [Fact]
    public void UpgradeIdentityIsPinned_ChangingItWouldOrphanEveryInstalledCopy()
    {
        var pkg = Wxs().Root!.Element(W + "Package")!;
        Assert.Equal("6B1D1B52-8C3B-4F0A-9D61-3C7A5E0A1F24", (string)pkg.Attribute("UpgradeCode")!);
        Assert.Equal("perMachine", (string)pkg.Attribute("Scope")!);
        Assert.NotNull(pkg.Element(W + "MajorUpgrade"));
        Assert.Contains("$(ProductVersion)", (string)pkg.Attribute("Version")!);
    }

    [Fact]
    public void InstallsOnlyOnWindows11_ToTheAdminOnlyProgramFilesFolder()
    {
        var pkg = Wxs().Root!.Element(W + "Package")!;
        var launch = pkg.Element(W + "Launch")!;
        Assert.Contains("22000", (string)launch.Attribute("Condition")!);               // Windows 11 build number (TLS 1.3)
        Assert.Contains("ProgramFiles64Folder", pkg.Descendants(W + "StandardDirectory").Select(d => (string)d.Attribute("Id")!));
        Assert.DoesNotContain("AppData", File.ReadAllText(Path.Combine(Dir, "Package.wxs")));
        Assert.All(pkg.Descendants(W + "Component"), c => Assert.Equal("always64", (string?)c.Attribute("Bitness")));
    }

    [Fact]
    public void RelayAccessKeyIsNeverAnMsiProperty_OnlyAddressAndFingerprint()
    {
        var text = File.ReadAllText(Path.Combine(Dir, "Package.wxs"));
        var props = Wxs().Descendants(W + "Property").Select(p => (string)p.Attribute("Id")!).ToList();
        Assert.Contains("RELAY_ADDRESS", props); Assert.Contains("RELAY_FINGERPRINT", props);
        Assert.DoesNotContain(props, p => Regex.IsMatch(p, "KEY|SECRET|PASSWORD|TOKEN", RegexOptions.IgnoreCase));
        Assert.DoesNotContain("REMOTETOOL_RELAY_KEY", text);                         // no environment variable carrying the access key either
        Assert.All(Wxs().Descendants(W + "Property").Where(p => (string)p.Attribute("Id")! is "RELAY_ADDRESS" or "RELAY_FINGERPRINT"),
                   p => Assert.Equal("yes", (string?)p.Attribute("Secure")));          // only honoured when passed on the command line, not overridable by transforms of other users
    }

    [Fact]
    public void UninstallRemovesTheServiceThroughACommandTheAppActuallyImplements()
    {
        var ca = Wxs().Descendants(W + "CustomAction").Single(c => (string)c.Attribute("Id")! == "RemoveUnattendedService");
        Assert.Equal("deferred", (string)ca.Attribute("Execute")!);
        Assert.Equal("no", (string)ca.Attribute("Impersonate")!);                      // runs as SYSTEM: needed to remove a service
        Assert.Equal("ignore", (string)ca.Attribute("Return")!);                       // "no service installed" must not fail the uninstall
        Assert.Contains("--service-control remove", (string)ca.Attribute("ExeCommand")!);
        var seq = Wxs().Descendants(W + "Custom").Single(c => (string)c.Attribute("Action")! == "RemoveUnattendedService");
        Assert.Contains("NOT UPGRADINGPRODUCTCODE", (string)seq.Attribute("Condition")!);   // an upgrade must not delete the service

        var program = File.ReadAllText(Path.Combine(Root(), "src", "RemoteTool.App", "Program.cs"));
        var cli = File.ReadAllText(Path.Combine(Root(), "src", "RemoteTool.App", "Services", "Cli.cs"));
        Assert.Contains("--service-control", program);
        Assert.Contains("case \"remove\"", cli);
        Assert.DoesNotContain("MessageBox", cli[cli.IndexOf("public static int ServiceControl", StringComparison.Ordinal)..cli.IndexOf("public static int VerifyAudit", StringComparison.Ordinal)]);   // no UI as SYSTEM in session 0
    }

    [Fact]
    public void InstallerProjectBuildsTheSingleExeFirst_AndIsPartOfTheSolution()
    {
        var wixproj = File.ReadAllText(Path.Combine(Dir, "RemoteTool.Installer.wixproj"));
        Assert.Contains("RemoteTool.Package.csproj", wixproj);
        Assert.Contains("InstallerPlatform>x64<", wixproj);
        // The MSI lives in its OWN solution: Visual Studio refuses to load a WiX SDK project when it cannot restore the SDK, and that must not break the main solution.
        var wixSln = File.ReadAllText(Path.Combine(Root(), "deploy", "RemoteTool.Installer.sln"));
        Assert.Contains("RemoteTool.Installer.wixproj", wixSln);
        var sln = File.ReadAllText(Path.Combine(Root(), "RemoteTool.sln"));
        Assert.DoesNotContain("wixproj", sln);
        Assert.Contains("RemoteTool.Package.csproj", sln);
        Assert.Contains("RemoteTool.App.csproj", sln);
    }
}
