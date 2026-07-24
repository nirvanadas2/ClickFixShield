namespace ClickFixShield.Core.Models;

/// <summary>
/// Four-band threat severity. Deliberately ordinal-comparable: <see cref="Safe"/> (0)
/// is least severe, <see cref="Malicious"/> (3) is most severe, so callers can write
/// <c>level &gt;= ThreatLevel.HighRisk</c> to test "at least this severe".
/// </summary>
public enum ThreatLevel
{
    Safe,
    Suspicious,
    HighRisk,
    Malicious
}
