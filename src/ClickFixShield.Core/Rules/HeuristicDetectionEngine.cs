using System.Diagnostics;
using System.Text.Json;
using System.Text.RegularExpressions;
using ClickFixShield.Core.Contracts;
using ClickFixShield.Core.Models;

namespace ClickFixShield.Core.Rules;

/// <summary>
/// Weighted heuristic detection engine. Every rule whose <see cref="DetectionRule.Pattern"/>
/// matches the candidate text contributes its <see cref="DetectionRule.Weight"/> to a running
/// total - independent signals compound rather than only the single best match counting.
/// A small entropy bonus is added on top when at least one rule already matched, since
/// high-entropy tokens (base64/obfuscated blobs) sharpen an already-suspicious signal but
/// must never trigger a detection on their own (too noisy - UUIDs/hashes are high-entropy
/// and benign). The total is clamped to [0, 100] and bucketed into four bands:
/// 0-20 Safe, 21-50 Suspicious, 51-80 HighRisk, 81-100 Malicious.
/// </summary>
public sealed class HeuristicDetectionEngine : IDetectionEngine
{
    private const int SafeMax = 20;
    private const int SuspiciousMax = 50;
    private const int HighRiskMax = 80;

    private const double EntropyBonusThreshold = 4.0;
    private const int EntropyBonus = 12;

    private static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(200);

    private readonly IReadOnlyList<CompiledRule> _rules;

    public HeuristicDetectionEngine(IEnumerable<DetectionRule> rules)
    {
        ArgumentNullException.ThrowIfNull(rules);

        var compiled = new List<CompiledRule>();
        foreach (var rule in rules)
        {
            try
            {
                var regex = new Regex(rule.Pattern, RegexOptions.IgnoreCase | RegexOptions.Compiled, RegexTimeout);
                compiled.Add(new CompiledRule(rule, regex));
            }
            catch (ArgumentException ex)
            {
                Trace.WriteLine($"ClickFixShield: skipping rule '{rule.Id}' - invalid regex pattern: {ex.Message}");
            }
        }

        _rules = compiled;
    }

    public DetectionResult Evaluate(string text, DateTimeOffset observedAt)
    {
        if (string.IsNullOrEmpty(text))
        {
            return new DetectionResult(0, ThreatLevel.Safe, Array.Empty<string>(), "Empty input, score 0 -> Safe.");
        }

        var matched = new List<CompiledRule>();
        var total = 0;

        foreach (var rule in _rules)
        {
            bool isMatch;
            try
            {
                isMatch = rule.Regex.IsMatch(text);
            }
            catch (RegexMatchTimeoutException)
            {
                isMatch = false;
            }

            if (isMatch)
            {
                matched.Add(rule);
                total += rule.Rule.Weight;
            }
        }

        // Entropy bonus only ever sharpens an existing match - it can never be the sole
        // trigger for a detection, since high-entropy text (UUIDs, hashes, tokens) is
        // common and benign on its own.
        if (matched.Count > 0)
        {
            var entropy = ComputeEntropy(LongestToken(text));
            if (entropy > EntropyBonusThreshold)
            {
                total += EntropyBonus;
            }
        }

        var score = Math.Clamp(total, 0, 100);
        var level = Classify(score);

        var explanation = matched.Count == 0
            ? "No rules matched, score 0 -> Safe."
            : $"Matched {matched.Count} rule(s) ({string.Join(", ", matched.Select(m => m.Rule.Name))}), aggregate score {score} -> {level}.";

        return new DetectionResult(score, level, matched.Select(m => m.Rule.Id).ToArray(), explanation);
    }

    /// <summary>Loads a rule set from a JSON array of <see cref="DetectionRule"/> objects.
    /// A rule whose <c>Pattern</c> fails to compile as a regex is skipped (logged), not thrown,
    /// so one bad rule can't take down the whole rule set.</summary>
    public static IReadOnlyList<DetectionRule> LoadRulesFromJson(string json)
    {
        var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
        var rules = JsonSerializer.Deserialize<List<DetectionRule>>(json, options) ?? new List<DetectionRule>();

        var valid = new List<DetectionRule>();
        foreach (var rule in rules)
        {
            try
            {
                _ = new Regex(rule.Pattern);
                valid.Add(rule);
            }
            catch (ArgumentException ex)
            {
                Trace.WriteLine($"ClickFixShield: dropping rule '{rule.Id}' from loaded rule set - invalid regex pattern: {ex.Message}");
            }
        }

        return valid;
    }

    /// <summary>Loads a rule set from a JSON file on disk (e.g. Rules/rules.json shipped
    /// alongside the built app via CopyToOutputDirectory).</summary>
    public static IReadOnlyList<DetectionRule> LoadRulesFromFile(string path)
        => LoadRulesFromJson(File.ReadAllText(path));

    private static ThreatLevel Classify(int score) => score switch
    {
        <= SafeMax => ThreatLevel.Safe,
        <= SuspiciousMax => ThreatLevel.Suspicious,
        <= HighRiskMax => ThreatLevel.HighRisk,
        _ => ThreatLevel.Malicious
    };

    private static string LongestToken(string text)
    {
        var tokens = text.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
        return tokens.Length == 0 ? string.Empty : tokens.OrderByDescending(t => t.Length).First();
    }

    private static double ComputeEntropy(string token)
    {
        if (string.IsNullOrEmpty(token))
        {
            return 0;
        }

        var counts = new Dictionary<char, int>();
        foreach (var c in token)
        {
            counts[c] = counts.GetValueOrDefault(c) + 1;
        }

        var entropy = 0.0;
        var length = token.Length;
        foreach (var count in counts.Values)
        {
            var p = (double)count / length;
            entropy -= p * Math.Log2(p);
        }

        return entropy;
    }

    private sealed record CompiledRule(DetectionRule Rule, Regex Regex);
}
