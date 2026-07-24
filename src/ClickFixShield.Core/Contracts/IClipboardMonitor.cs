using ClickFixShield.Core.Models;

namespace ClickFixShield.Core.Contracts;

/// <summary>
/// Watches the Windows clipboard for suspicious ClickFix-style content (a page silently
/// writing an attack command before instructing the victim to paste it into Win+R).
/// </summary>
public interface IClipboardMonitor : IDisposable
{
    event EventHandler<SecurityEvent>? ThreatDetected;

    void Start();
    void Stop();
}
