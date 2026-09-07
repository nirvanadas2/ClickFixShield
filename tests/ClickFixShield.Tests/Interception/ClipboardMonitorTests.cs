using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using ClickFixShield.Core.Contracts;
using ClickFixShield.Core.Interception;
using ClickFixShield.Core.Models;
using ClickFixShield.Core.Rules;
using Xunit;

namespace ClickFixShield.Tests.Interception;

/// <summary>
/// Exercises the real Win32 clipboard + message loop (not a fake) because the bug this
/// guards against - a single clipboard write producing two near-identical
/// <see cref="SecurityEvent"/>s - lives entirely in how <see cref="ClipboardMonitor"/>
/// talks to the real clipboard API, not in any mockable seam.
/// </summary>
public class ClipboardMonitorTests
{
    private const uint CfUnicodeText = 13;
    private const uint GhndMoveable = 0x0042;

    private static readonly IReadOnlyList<DetectionRule> ShippedRules =
        HeuristicDetectionEngine.LoadRulesFromFile(Path.Combine(AppContext.BaseDirectory, "Rules", "rules.json"));

    [Fact]
    public void SingleClipboardWrite_ProducesExactlyOneSecurityEvent()
    {
        var engine = new HeuristicDetectionEngine(ShippedRules);
        var eventStore = new RecordingEventStore();
        var correlationWindow = new ThreatCorrelationWindow();

        using var monitor = new ClipboardMonitor(engine, eventStore, correlationWindow);

        var received = new ConcurrentQueue<SecurityEvent>();
        monitor.ThreatDetected += (_, evt) => received.Enqueue(evt);

        monitor.Start();
        try
        {
            // Unique per run so this test can't observe a stray event left over from
            // clipboard content another test (or the developer's own clipboard) wrote.
            var payload = $"powershell -enc {Guid.NewGuid():N} -windowstyle hidden";

            WriteClipboardText(payload);

            WaitUntil(() => received.Count > 0, TimeSpan.FromSeconds(5));

            // Give a spurious duplicate WM_CLIPBOARDUPDATE (the bug this test guards
            // against) time to arrive before asserting there was only ever one.
            Thread.Sleep(500);

            Assert.Single(received, e => e.RawText == payload);
            Assert.Single(eventStore.SavedEvents, e => e.RawText == payload);
        }
        finally
        {
            monitor.Stop();
        }
    }

    private static void WaitUntil(Func<bool> condition, TimeSpan timeout)
    {
        var deadline = DateTime.UtcNow + timeout;
        while (!condition() && DateTime.UtcNow < deadline)
        {
            Thread.Sleep(25);
        }
    }

    private static void WriteClipboardText(string text)
    {
        var opened = false;
        for (var attempt = 0; attempt < 20 && !opened; attempt++)
        {
            opened = OpenClipboard(0);
            if (!opened)
            {
                Thread.Sleep(25);
            }
        }

        if (!opened)
        {
            throw new InvalidOperationException("Could not open the clipboard for the test write.");
        }

        try
        {
            EmptyClipboard();

            var byteCount = (text.Length + 1) * sizeof(char);
            var hMem = GlobalAlloc(GhndMoveable, (nuint)byteCount);
            Assert.NotEqual(nint.Zero, hMem);

            var target = GlobalLock(hMem);
            Assert.NotEqual(nint.Zero, target);
            try
            {
                Marshal.Copy(text.ToCharArray(), 0, target, text.Length);
                Marshal.WriteInt16(target, text.Length * sizeof(char), 0);
            }
            finally
            {
                GlobalUnlock(hMem);
            }

            SetClipboardData(CfUnicodeText, hMem);
        }
        finally
        {
            CloseClipboard();
        }
    }

    private sealed class RecordingEventStore : IEventStore
    {
        private readonly ConcurrentQueue<SecurityEvent> _saved = new();

        public IReadOnlyCollection<SecurityEvent> SavedEvents => _saved;

        public void Save(SecurityEvent evt) => _saved.Enqueue(evt);
        public IReadOnlyList<SecurityEvent> GetRecent(int count) => _saved.ToArray();
        public SecurityEvent? GetById(Guid id) => _saved.FirstOrDefault(e => e.Id == id);
        public IReadOnlyList<SecurityEvent> GetByMinimumLevel(ThreatLevel minLevel, int count)
            => _saved.Where(e => e.Detection.Level >= minLevel).ToArray();
    }

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool OpenClipboard(nint hWndNewOwner);

    [DllImport("user32.dll")]
    private static extern bool CloseClipboard();

    [DllImport("user32.dll")]
    private static extern bool EmptyClipboard();

    [DllImport("user32.dll")]
    private static extern nint SetClipboardData(uint uFormat, nint hMem);

    [DllImport("kernel32.dll")]
    private static extern nint GlobalAlloc(uint uFlags, nuint dwBytes);

    [DllImport("kernel32.dll")]
    private static extern nint GlobalLock(nint hMem);

    [DllImport("kernel32.dll")]
    private static extern bool GlobalUnlock(nint hMem);
}
