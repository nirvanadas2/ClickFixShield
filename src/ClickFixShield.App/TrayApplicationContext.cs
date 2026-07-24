using ClickFixShield.Core.Contracts;
using ClickFixShield.Core.Interception;
using ClickFixShield.Core.Models;

namespace ClickFixShield.App;

/// <summary>Composition root's runtime shell: tray icon, context menu, and threat notifications.</summary>
public sealed class TrayApplicationContext : ApplicationContext
{
    private readonly IEventStore _eventStore;
    private readonly IClipboardMonitor _clipboardMonitor;
    private readonly ProcessInterceptor _processInterceptor;
    private readonly RunKeyHook _runKeyHook;
    private readonly NotifyIcon _notifyIcon;

    // A hidden, never-shown form purely to give this thread a Control whose handle we
    // can Invoke onto - ThreatDetected fires from the clipboard message loop / WMI
    // watcher thread, and WinForms controls must only be touched from the UI thread.
    private readonly Form _syncContext;

    private SecurityEvent? _lastEvent;

    public TrayApplicationContext(
        IEventStore eventStore,
        IClipboardMonitor clipboardMonitor,
        ProcessInterceptor processInterceptor,
        RunKeyHook runKeyHook)
    {
        _eventStore = eventStore;
        _clipboardMonitor = clipboardMonitor;
        _processInterceptor = processInterceptor;
        _runKeyHook = runKeyHook;

        _syncContext = new Form { ShowInTaskbar = false, WindowState = FormWindowState.Minimized, Opacity = 0 };
        _syncContext.CreateControl();

        var isProtected = _processInterceptor.IsActive;
        var statusText = isProtected ? "Protected" : "Limited (run as Administrator for full protection)";

        var menu = new ContextMenuStrip();
        menu.Items.Add("Recent Events", null, (_, _) => ShowEventHistory());
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add(new ToolStripMenuItem($"Status: {statusText}") { Enabled = false });
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("Exit", null, (_, _) => ExitApplication());

        _notifyIcon = new NotifyIcon
        {
            Icon = isProtected ? SystemIcons.Shield : SystemIcons.Warning,
            Text = isProtected ? "ClickFixShield - Protected" : "ClickFixShield - Limited protection",
            Visible = true,
            ContextMenuStrip = menu
        };
        _notifyIcon.DoubleClick += (_, _) => ShowLastEventOrHistory();
        _notifyIcon.BalloonTipClicked += (_, _) => ShowLastEventOrHistory();

        _clipboardMonitor.ThreatDetected += OnThreatDetected;
        _processInterceptor.ThreatDetected += OnThreatDetected;
    }

    private void OnThreatDetected(object? sender, SecurityEvent evt)
    {
        if (_syncContext.InvokeRequired)
        {
            _syncContext.Invoke(() => OnThreatDetected(sender, evt));
            return;
        }

        _lastEvent = evt;

        var title = evt.Source == ThreatSource.Clipboard
            ? "Suspicious clipboard content flagged"
            : evt.ActionTaken == ThreatAction.Blocked
                ? "Blocked suspicious process launch"
                : "Suspicious process launch detected";

        var icon = evt.Detection.Level >= ThreatLevel.HighRisk ? ToolTipIcon.Error : ToolTipIcon.Warning;

        _notifyIcon.ShowBalloonTip(5000, title, evt.Detection.Explanation ?? "See Recent Events for details.", icon);
    }

    private void ShowLastEventOrHistory()
    {
        if (_lastEvent is { } evt)
        {
            new ThreatDetailForm(evt).Show();
        }
        else
        {
            ShowEventHistory();
        }
    }

    private void ShowEventHistory() => new EventHistoryForm(_eventStore).Show();

    private void ExitApplication()
    {
        _notifyIcon.Visible = false;

        _clipboardMonitor.ThreatDetected -= OnThreatDetected;
        _processInterceptor.ThreatDetected -= OnThreatDetected;

        _clipboardMonitor.Dispose();
        _processInterceptor.Dispose();
        _runKeyHook.Dispose();
        _notifyIcon.Dispose();
        _syncContext.Dispose();

        Application.Exit();
    }
}
