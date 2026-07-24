using ClickFixShield.Core.Models;

namespace ClickFixShield.Core.Contracts;

/// <summary>Evaluates arbitrary text (clipboard content or a process command line) for ClickFix-style threats.</summary>
public interface IDetectionEngine
{
    DetectionResult Evaluate(string text, DateTimeOffset observedAt);
}
