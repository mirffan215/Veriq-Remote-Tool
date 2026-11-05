using System.Text.RegularExpressions;
using System.Xml.Linq;
using RemoteTool.Core.Config;

namespace RemoteTool.Core.Tests;

[Collection("EditionState")]   // EditionInfo.Current is process-wide: these tests must not run beside others that read it
public class EditionTests
{
    private static string Root()
    {
        var d = new DirectoryInfo(AppContext.BaseDirectory);
        while (d is not null && !File.Exists(Path.Combine(d.FullName, "RemoteTool.sln"))) d = d.Parent;
        return d?.FullName ?? throw new InvalidOperationException("repository root not found");
    }

    private static readonly string[] Editions = { "Enterprise", "Production", "UAT" };
    private static string Dir(string e) => Path.Combine(Root(), "editions", e);
    private static Dictionary<string, string> Props(string e)
        => XDocument.Load(Path.Combine(Dir(e), "edition.props")).Descendants("PropertyGroup").Elements().GroupBy(x => x.Name.LocalName).ToDictionary(g => g.Key, g => g.First().Value);

    // ---------------------------------------------------------------- runtime

    [Fact]
    public void ParsesTheEmbeddedEditionAndBuildsTheWindowTitle()
    {
        var e = EditionInfo.Parse("""{"id":"UAT","displayName":"Veriq Remote Tool","dataFolder":"VeriqRemoteTool-UAT","banner":"UAT"}""");
        Assert.Equal("UAT", e.Id);
        Assert.Equal("VeriqRemoteTool-UAT", e.DataFolder);
        Assert.Equal("Veriq Remote Tool [UAT]", e.WindowTitle);
        Assert.Equal("Veriq Remote Tool", EditionInfo.Parse("""{"id":"P","displayName":"Veriq Remote Tool","dataFolder":"VeriqRemoteTool","banner":""}""").WindowTitle);
    }

    [Theory]
    [InlineData("")]
    [InlineData("not json")]
    [InlineData("{}")]
    [InlineData("[]")]
    public void MissingOrBrokenEditionFallsBackToTheStandardOne(string json)
    {
        var e = EditionInfo.Parse(json);
        Assert.Equal(EditionInfo.Standard.DataFolder, e.DataFolder);
        Assert.Equal(EditionInfo.Standard.DisplayName, e.DisplayName);
    }

    [Theory]
    [InlineData(@"..\..\Windows")]
    [InlineData("../etc")]
    [InlineData("a/b")]
    [InlineData(@"C:\evil")]
    [InlineData("..")]
    [InlineData("a..b/../c")]
    [InlineData(".hidden")]
    [InlineData("name with space")]
    public void AnUnsafeDataFolderCanNeverEscapeTheDataDirectory(string folder)
    {
        var json = System.Text.Json.JsonSerializer.Serialize(new { id = "X", displayName = "X", dataFolder = folder, banner = "" });
        Assert.Equal(EditionInfo.Standard.DataFolder, EditionInfo.Parse(json).DataFolder);
    }

    [Fact]
    public void EachEditionKeepsItsOwnSettingsAndLogFolders()
    {
        var before = EditionInfo.Current;
        var dir = Path.Combine(Path.GetTempPath(), "rt-ed-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            EditionInfo.Current = new EditionInfo("UAT", "Veriq Remote Tool", "VeriqRemoteTool-UAT", "UAT");
            var uat = StoragePaths.Detect(dir);
            EditionInfo.Current = new EditionInfo("Production", "Veriq Remote Tool", "VeriqRemoteTool", "");
            var prod = StoragePaths.Detect(dir);
            Assert.EndsWith("VeriqRemoteTool-UAT", uat.SettingsDirectory);
            Assert.EndsWith("VeriqRemoteTool", prod.SettingsDirectory);
            Assert.NotEqual(uat.SettingsDirectory, prod.SettingsDirectory);
            Assert.NotEqual(uat.LogDirectory, prod.LogDirectory);
            Assert.NotEqual(uat.SettingsFile, prod.SettingsFile);
        }
        finally { EditionInfo.Current = before; Directory.Delete(dir, true); }
    }

    // ---------------------------------------------------------------- the editions on disk

    [Fact]
    public void EveryEditionHasItsFiles_AndTheyAreWellFormed()
    {
        foreach (var e in Editions)
        {
            Assert.True(File.Exists(Path.Combine(Dir(e), "edition.props")), e);
            Assert.True(File.Exists(Path.Combine(Dir(e), "RemoteTool.ico")), e);
            Assert.True(new FileInfo(Path.Combine(Dir(e), "RemoteTool.ico")).Length > 1000, e + " icon looks empty");
            var csproj = XDocument.Load(Path.Combine(Dir(e), $"RemoteTool.{e}.csproj"));
            Assert.Equal(e, csproj.Descendants("Edition").Single().Value);
            Assert.Contains(csproj.Descendants("Import"), i => (string?)i.Attribute("Project") == @"..\Edition.Package.targets");
        }
        XDocument.Load(Path.Combine(Root(), "editions", "Edition.Package.targets"));
    }

    [Fact]
    public void EditionIdentitiesAreUniqueSoEditionsCanRunSideBySide()
    {
        var all = Editions.Select(Props).ToList();
        foreach (var p in all)
            foreach (var key in new[] { "EditionDisplayName", "EditionDataFolder", "EditionIcon", "EditionExeName", "EditionBanner" })
                Assert.True(p.ContainsKey(key), $"{key} missing");
        Assert.Equal(3, all.Select(p => p["EditionDataFolder"]).Distinct().Count());
        Assert.Equal(3, all.Select(p => p["EditionExeName"]).Distinct().Count());
        Assert.All(all, p => Assert.Matches("^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$", p["EditionDataFolder"]));
        Assert.All(all, p => Assert.EndsWith(".exe", p["EditionExeName"]));
    }

    [Fact]
    public void ProductionLooksLikeProduction_AndEverythingElseIsVisiblyMarked()
    {
        Assert.Equal("", Props("Production")["EditionBanner"]);
        Assert.Equal("UAT", Props("UAT")["EditionBanner"]);
        Assert.NotEqual("", Props("Enterprise")["EditionBanner"]);
    }

    [Fact]
    public void RelaySecretsNeverLiveInTheRepository_OnlyInEnvironmentVariables()
    {
        foreach (var e in Editions)
        {
            var text = File.ReadAllText(Path.Combine(Dir(e), "edition.props"));
            Assert.Matches(@"DefaultRelayAddress[^>]*>\$\(RT_[A-Z]+_RELAY\)<", text);
            Assert.Matches(@"DefaultRelayKey[^>]*>\$\(RT_[A-Z]+_RELAY_KEY\)<", text);
            Assert.DoesNotMatch(@"DefaultRelayKey[^>]*>[A-Za-z0-9+/=]{12,}<", text);
        }
    }

    [Fact]
    public void TheAppBuildUnderstandsEditions_AndOnlyThatEditionsCustomCodeIsCompiled()
    {
        var app = File.ReadAllText(Path.Combine(Root(), "src", "RemoteTool.App", "RemoteTool.App.csproj"));
        Assert.Contains(@"editions\$(Edition)\", app);
        Assert.Contains("$(EditionDir)edition.props", app);
        Assert.Contains(@"$(EditionDir)Customization\**\*.cs", app);
        Assert.Contains("RemoteTool.edition.json", app);
        Assert.Contains("OnStartup", File.ReadAllText(Path.Combine(Root(), "src", "RemoteTool.App", "EditionCustomization.cs")));
        Assert.Contains("EditionCustomization.Startup(this)", File.ReadAllText(Path.Combine(Root(), "src", "RemoteTool.App", "App.xaml.cs")));
        Assert.Contains("EditionInfo.Current = EditionLoader.Load()", File.ReadAllText(Path.Combine(Root(), "src", "RemoteTool.App", "Program.cs")));
        // the customisation example really implements the hook
        Assert.Matches(@"static partial void OnStartup\(App app\)", File.ReadAllText(Path.Combine(Dir("Enterprise"), "Customization", "EnterpriseCustomization.cs")));
    }

    [Fact]
    public void TheFullSolutionContainsEveryEdition_ButBuildSolutionNeverPackagesThem()
    {
        var sln = File.ReadAllText(Path.Combine(Root(), "RemoteTool.sln"));
        foreach (var e in Editions) Assert.Contains($"RemoteTool.{e}.csproj", sln);
        // editions share the app's obj folder, so they must not be built in parallel by "Build Solution"
        Assert.Empty(Regex.Matches(sln, @"\{5E1D0F0[123]-[0-9A-F-]+\}\.(Debug|Release)\|Any CPU\.Build\.0"));
    }

    [Fact]
    public void PackageTargetBuildsOneEditionAndRenamesTheExe()
    {
        var t = File.ReadAllText(Path.Combine(Root(), "editions", "Edition.Package.targets"));
        Assert.Contains("-p:Edition=$(Edition)", t);
        Assert.Contains("$(EditionExeName)", t);
        Assert.Contains("--self-contained true", t);
        Assert.Contains("artifacts\\$(Edition)", t);
    }
}
