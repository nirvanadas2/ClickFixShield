using ClickFixShield.Core.Models;

namespace ClickFixShield.Core.Contracts;

/// <summary>
/// Local persistence for <see cref="SecurityEvent"/>s. The concrete implementation is
/// SQLite-backed, chosen specifically so <see cref="GetByMinimumLevel"/> is a real
/// indexed query rather than a linear scan.
/// </summary>
public interface IEventStore
{
    void Save(SecurityEvent evt);
    IReadOnlyList<SecurityEvent> GetRecent(int count);
    SecurityEvent? GetById(Guid id);
    IReadOnlyList<SecurityEvent> GetByMinimumLevel(ThreatLevel minLevel, int count);
}
