using System.Collections.Concurrent;

namespace ClickFixShield.Core.Interception;

/// <summary>
/// Thread-safe in-memory <see cref="IThreatCorrelationWindow"/>. Entries older than
/// <see cref="MaxAge"/> are pruned opportunistically on every call so the backing
/// collection never grows unbounded over a long-running tray session.
/// </summary>
public sealed class ThreatCorrelationWindow : IThreatCorrelationWindow
{
    private static readonly TimeSpan MaxAge = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Recorded text shorter than this is ignored for substring correlation — very short
    /// strings (a few characters) would trivially "match" almost any candidate command
    /// line and produce meaningless correlation noise.
    /// </summary>
    private const int MinimumCorrelatableLength = 6;

    private readonly ConcurrentQueue<(string Text, DateTimeOffset At)> _entries = new();

    public void Record(string text, DateTimeOffset at)
    {
        if (!string.IsNullOrEmpty(text))
        {
            _entries.Enqueue((text, at));
        }

        Prune(at);
    }

    public bool IsRecentMatch(string candidateText, TimeSpan window)
    {
        if (string.IsNullOrEmpty(candidateText))
        {
            return false;
        }

        var now = DateTimeOffset.UtcNow;
        Prune(now);

        foreach (var (text, at) in _entries)
        {
            if (text.Length < MinimumCorrelatableLength)
            {
                continue;
            }

            if (now - at > window)
            {
                continue;
            }

            if (candidateText.Contains(text, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private void Prune(DateTimeOffset now)
    {
        while (_entries.TryPeek(out var oldest) && now - oldest.At > MaxAge)
        {
            _entries.TryDequeue(out _);
        }
    }
}
