using ClickFixShield.Core.Contracts;
using ClickFixShield.Core.Models;

namespace ClickFixShield.Core.Interception;

public enum InterceptionDecision
{
    Allow,
    Kill
}

public sealed record ProcessLaunchInfo(int ProcessId, string ProcessName, string CommandLine, DateTimeOffset LaunchedAt);

/// <summary>
/// Pure decision logic for whether a just-launched process should be killed - zero
/// Win32/WMI dependencies by design, so it is directly unit-testable. A Kill decision
/// requires BOTH the process being a known LOLBin AND the command line scoring at least
/// <see cref="ThreatLevel.HighRisk"/> - never process name alone, never clipboard
/// correlation alone. Correlation only enriches the returned explanation; it never
/// lowers the HighRisk bar.
/// </summary>
public sealed class RunInterceptionDecider
{
    private readonly IDetectionEngine _engine;
    private readonly IThreatCorrelationWindow _correlationWindow;
    private readonly TimeSpan _correlationTtl;
    private readonly HashSet<string> _lolbinAllowlist;

    public RunInterceptionDecider(
        IDetectionEngine engine,
        IThreatCorrelationWindow correlationWindow,
        ProcessInterceptorOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(engine);
        ArgumentNullException.ThrowIfNull(correlationWindow);

        _engine = engine;
        _correlationWindow = correlationWindow;

        var opts = options ?? new ProcessInterceptorOptions();
        _correlationTtl = opts.CorrelationTtl;
        _lolbinAllowlist = new HashSet<string>(opts.LolBinAllowlist, StringComparer.OrdinalIgnoreCase);
    }

    public (InterceptionDecision Decision, DetectionResult Detection) Decide(ProcessLaunchInfo launch)
    {
        ArgumentNullException.ThrowIfNull(launch);

        var detection = _engine.Evaluate(launch.CommandLine, launch.LaunchedAt);
        var processName = System.IO.Path.GetFileName(launch.ProcessName);

        if (!_lolbinAllowlist.Contains(processName) || detection.Level < ThreatLevel.HighRisk)
        {
            return (InterceptionDecision.Allow, detection);
        }

        if (_correlationWindow.IsRecentMatch(launch.CommandLine, _correlationTtl))
        {
            detection = detection with
            {
                Explanation = $"{detection.Explanation} Correlates with a recently observed clipboard write."
            };
        }

        return (InterceptionDecision.Kill, detection);
    }
}
