namespace ClickFixShield.Core.Models;

/// <summary>Where a <see cref="SecurityEvent"/> was observed.</summary>
public enum ThreatSource
{
    Clipboard,
    ProcessLaunch
}

/// <summary>What ClickFixShield did in response to a <see cref="SecurityEvent"/>.</summary>
public enum ThreatAction
{
    Flagged,
    Blocked,
    BlockAttemptFailed,
    Allowed
}

/// <summary>
/// A single detected/logged security event — either a suspicious clipboard write or
/// a suspicious process launch.
/// </summary>
public sealed record SecurityEvent(
    Guid Id,
    DateTimeOffset Timestamp,
    ThreatSource Source,
    string RawText,
    DetectionResult Detection,
    ThreatAction ActionTaken);
