namespace ClickFixShield.Core.Models;

/// <summary>
/// Result of evaluating a piece of text (clipboard content or a process command line)
/// against the detection engine's rule set.
/// </summary>
/// <param name="Score">
/// Aggregate weighted score in [0, 100]: the sum of every matching rule's weight
/// (plus a small entropy bonus), clamped — not just the single best-matching rule.
/// </param>
/// <param name="Level">The severity band derived from <paramref name="Score"/>.</param>
/// <param name="MatchedRuleIds">
/// Ids of every rule that matched (empty, not null, when nothing matched).
/// </param>
/// <param name="Explanation">Human-readable one-line summary of the result.</param>
public sealed record DetectionResult(
    int Score,
    ThreatLevel Level,
    IReadOnlyList<string> MatchedRuleIds,
    string? Explanation);
