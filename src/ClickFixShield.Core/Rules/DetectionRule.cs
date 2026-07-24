namespace ClickFixShield.Core.Rules;

/// <summary>
/// One heuristic detection rule: a regex <see cref="Pattern"/> with a fixed
/// <see cref="Weight"/> (0-100) contributing toward the aggregate score computed by
/// <see cref="HeuristicDetectionEngine"/>. Severity is NOT stored per-rule — it is
/// derived from the aggregate score of every rule that matches, not copied from a
/// single rule, since multiple weak/moderate signals on the same text should compound.
/// </summary>
public sealed record DetectionRule(
    string Id,
    string Name,
    string Pattern,
    int Weight,
    string Category,
    string Description);
