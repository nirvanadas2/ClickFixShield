namespace ClickFixShield.Core.Interception;

/// <summary>Configurable knobs for <see cref="ClipboardMonitor"/>.</summary>
public sealed class ClipboardMonitorOptions
{
    /// <summary>Number of attempts to read clipboard text before giving up on a single update notification.</summary>
    public int ReadRetryCount { get; init; } = 3;

    /// <summary>Delay between clipboard read retries (another process may be holding the clipboard open).</summary>
    public TimeSpan ReadRetryDelay { get; init; } = TimeSpan.FromMilliseconds(50);
}
