namespace ClickFixShield.Core.Interception;

/// <summary>
/// Short-TTL, in-memory correlation of recently observed suspicious text (typically
/// clipboard content) against later candidate text (typically a process command line),
/// so a Win+R paste can be linked back to the clipboard write that hijacked it.
/// </summary>
public interface IThreatCorrelationWindow
{
    /// <summary>Records that <paramref name="text"/> was observed as suspicious at <paramref name="at"/>.</summary>
    void Record(string text, DateTimeOffset at);

    /// <summary>
    /// True if some text recorded within <paramref name="window"/> of now either equals
    /// <paramref name="candidateText"/> or is contained within it (command lines commonly
    /// wrap the pasted payload in extra shell syntax, so exact-only matching is too strict).
    /// </summary>
    bool IsRecentMatch(string candidateText, TimeSpan window);
}
