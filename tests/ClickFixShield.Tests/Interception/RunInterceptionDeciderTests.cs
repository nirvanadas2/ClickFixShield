using ClickFixShield.Core.Interception;
using ClickFixShield.Core.Models;
using ClickFixShield.Core.Rules;
using Xunit;

namespace ClickFixShield.Tests.Interception;

public class RunInterceptionDeciderTests
{
    // A small, self-contained rule set (not the shipped rules.json) so these tests don't
    // break if the real rule set changes. HIGH crosses the HighRisk threshold (score > 50)
    // by itself; LOW does not (stays in the Suspicious band).
    private static readonly DetectionRule HighRiskRule = new("HIGH", "High Risk Marker", "HIGHRISKMARKER", 60, "Test", "test rule");
    private static readonly DetectionRule LowRiskRule = new("LOW", "Low Risk Marker", "LOWRISKMARKER", 30, "Test", "test rule");

    private static RunInterceptionDecider CreateDecider(IThreatCorrelationWindow? correlationWindow = null, TimeSpan? correlationTtl = null)
    {
        var engine = new HeuristicDetectionEngine(new[] { HighRiskRule, LowRiskRule });
        var window = correlationWindow ?? new ThreatCorrelationWindow();
        var options = new ProcessInterceptorOptions { CorrelationTtl = correlationTtl ?? TimeSpan.FromSeconds(20) };
        return new RunInterceptionDecider(engine, window, options);
    }

    [Fact]
    public void Decide_LolBinWithHighRiskCommandLine_ReturnsKill()
    {
        var decider = CreateDecider();
        var launch = new ProcessLaunchInfo(1234, "powershell.exe", "run HIGHRISKMARKER now", DateTimeOffset.UtcNow);

        var (decision, detection) = decider.Decide(launch);

        Assert.Equal(InterceptionDecision.Kill, decision);
        Assert.True(detection.Level >= ThreatLevel.HighRisk);
    }

    [Fact]
    public void Decide_NonLolBinWithHighRiskCommandLine_ReturnsAllow()
    {
        // Core safety invariant: never kill a process whose name isn't a known LOLBin,
        // regardless of how suspicious its command line looks.
        var decider = CreateDecider();
        var launch = new ProcessLaunchInfo(1234, "notepad.exe", "run HIGHRISKMARKER now", DateTimeOffset.UtcNow);

        var (decision, _) = decider.Decide(launch);

        Assert.Equal(InterceptionDecision.Allow, decision);
    }

    [Fact]
    public void Decide_LolBinWithBenignCommandLine_ReturnsAllow()
    {
        // Core safety invariant: never kill on process name alone - a benign LOLBin
        // launch must be allowed.
        var decider = CreateDecider();
        var launch = new ProcessLaunchInfo(1234, "powershell.exe", "Get-Process", DateTimeOffset.UtcNow);

        var (decision, _) = decider.Decide(launch);

        Assert.Equal(InterceptionDecision.Allow, decision);
    }

    [Fact]
    public void Decide_LolBinWithOnlyLowSeverityMatch_ReturnsAllow()
    {
        var decider = CreateDecider();
        var launch = new ProcessLaunchInfo(1234, "powershell.exe", "run LOWRISKMARKER now", DateTimeOffset.UtcNow);

        var (decision, detection) = decider.Decide(launch);

        Assert.Equal(InterceptionDecision.Allow, decision);
        Assert.True(detection.Level < ThreatLevel.HighRisk);
    }

    [Fact]
    public void Decide_RecentCorrelationMatch_EnrichesExplanationButDoesNotChangeKillDecision()
    {
        var window = new ThreatCorrelationWindow();
        window.Record("HIGHRISKMARKER payload from clipboard", DateTimeOffset.UtcNow);
        var decider = CreateDecider(window);

        var launch = new ProcessLaunchInfo(1234, "powershell.exe", "cmd wrapping HIGHRISKMARKER payload from clipboard here", DateTimeOffset.UtcNow);

        var (decision, detection) = decider.Decide(launch);

        Assert.Equal(InterceptionDecision.Kill, decision);
        Assert.Contains("Correlates with a recently observed clipboard write.", detection.Explanation);
    }

    [Fact]
    public void Decide_CorrelationMatchWithoutSeverity_NeverCausesKill()
    {
        // Core safety invariant: clipboard correlation alone is never sufficient - it can
        // only enrich an already-qualifying Kill, never substitute for the severity gate.
        var window = new ThreatCorrelationWindow();
        window.Record("just some correlated text", DateTimeOffset.UtcNow);
        var decider = CreateDecider(window);

        var launch = new ProcessLaunchInfo(1234, "powershell.exe", "just some correlated text with no rule match", DateTimeOffset.UtcNow);

        var (decision, _) = decider.Decide(launch);

        Assert.Equal(InterceptionDecision.Allow, decision);
    }

    [Fact]
    public void Decide_CorrelationMatchOlderThanTtl_DoesNotEnrichExplanation()
    {
        var window = new ThreatCorrelationWindow();
        window.Record("HIGHRISKMARKER payload from clipboard", DateTimeOffset.UtcNow.AddSeconds(-90));
        var decider = CreateDecider(window, correlationTtl: TimeSpan.FromSeconds(20));

        var launch = new ProcessLaunchInfo(1234, "powershell.exe", "HIGHRISKMARKER payload from clipboard", DateTimeOffset.UtcNow);

        var (decision, detection) = decider.Decide(launch);

        // Severity alone already qualifies for Kill - the aged-out correlation just
        // shouldn't be mentioned in the explanation.
        Assert.Equal(InterceptionDecision.Kill, decision);
        Assert.DoesNotContain("Correlates", detection.Explanation);
    }
}
