using System.Diagnostics;
using System.Management;
using ClickFixShield.Core.Contracts;
using ClickFixShield.Core.Models;

namespace ClickFixShield.Core.Interception;

/// <summary>
/// Near-real-time detect-and-kill process interception via WMI
/// <c>Win32_ProcessStartTrace</c>. True pre-execution blocking would require a signed
/// kernel-mode driver (PsSetCreateProcessNotifyRoutineEx), which is out of scope for v1 -
/// this is a documented best-effort limitation, not a bug: the payload may already have
/// run harmful code in the milliseconds before the kill lands.
/// </summary>
public sealed class ProcessInterceptor : IDisposable
{
    private readonly RunInterceptionDecider _decider;
    private readonly IEventStore _eventStore;
    private ManagementEventWatcher? _watcher;

    public event EventHandler<SecurityEvent>? ThreatDetected;

    /// <summary>
    /// True once the WMI process-start subscription is active. False if subscribing
    /// failed - most commonly because the process is not running elevated, since
    /// <c>Win32_ProcessStartTrace</c> requires Administrator privileges - so the caller
    /// (tray UI) can surface a "protection limited" warning instead of silently doing nothing.
    /// </summary>
    public bool IsActive { get; private set; }

    public ProcessInterceptor(RunInterceptionDecider decider, IEventStore eventStore)
    {
        ArgumentNullException.ThrowIfNull(decider);
        ArgumentNullException.ThrowIfNull(eventStore);

        _decider = decider;
        _eventStore = eventStore;
    }

    public void Start()
    {
        if (_watcher is not null)
        {
            return;
        }

        try
        {
            var query = new WqlEventQuery("SELECT * FROM Win32_ProcessStartTrace");
            var watcher = new ManagementEventWatcher(query);
            watcher.EventArrived += OnProcessStarted;
            watcher.Start();
            _watcher = watcher;
            IsActive = true;
            LogDemo("Process interception ACTIVE - subscribed to Win32_ProcessStartTrace (running elevated).");
        }
        catch (Exception ex) when (ex is ManagementException or UnauthorizedAccessException)
        {
            // Not being elevated is an expected, common condition here - not fatal -
            // so degrade gracefully rather than throwing out of Start().
            IsActive = false;
            _watcher = null;
            LogDemo($"Process interception LIMITED - could not subscribe to Win32_ProcessStartTrace ({ex.GetType().Name}: {ex.Message}). Run as Administrator for full protection.");
        }
    }

    public void Stop()
    {
        if (_watcher is null)
        {
            return;
        }

        try
        {
            _watcher.Stop();
        }
        catch (ManagementException)
        {
            // Best-effort - the watcher may already be in a faulted state.
        }

        _watcher.EventArrived -= OnProcessStarted;
        _watcher.Dispose();
        _watcher = null;
        IsActive = false;
    }

    public void Dispose() => Stop();

    private void OnProcessStarted(object sender, EventArrivedEventArgs e)
    {
        try
        {
            var processId = Convert.ToInt32(e.NewEvent.Properties["ProcessID"].Value);
            var processName = Convert.ToString(e.NewEvent.Properties["ProcessName"].Value) ?? string.Empty;
            var commandLine = TryGetCommandLine(processId) ?? string.Empty;

            var launch = new ProcessLaunchInfo(processId, processName, commandLine, DateTimeOffset.UtcNow);
            var (decision, detection) = _decider.Decide(launch);

            if (decision != InterceptionDecision.Kill)
            {
                // Don't spam the event store (or the console) with every benign process
                // launch on the system - only surface events actually evaluated as
                // suspicious/killed, so a live demo's log stays readable.
                return;
            }

            LogDemo($"Process-start event received: {processName} (PID {processId}) scored {detection.Score} ({detection.Level}) - command line: {commandLine}");

            var correlated = detection.Explanation?.Contains("Correlates with a recently observed clipboard write.", StringComparison.Ordinal) == true;
            if (correlated)
            {
                LogDemo("  -> Matched a recently observed malicious clipboard write. Escalating to kill.");
            }

            LogDemo($"  -> Attempting to kill PID {processId} ({processName})...");

            var actionTaken = TryKill(processId) ? ThreatAction.Blocked : ThreatAction.BlockAttemptFailed;

            LogDemo(actionTaken == ThreatAction.Blocked
                ? $"  -> Kill succeeded: {processName} (PID {processId}) terminated."
                : $"  -> Kill FAILED for PID {processId} (it may have already exited).");

            var evt = new SecurityEvent(
                Guid.NewGuid(),
                DateTimeOffset.UtcNow,
                ThreatSource.ProcessLaunch,
                commandLine,
                detection,
                actionTaken);

            _eventStore.Save(evt);
            ThreatDetected?.Invoke(this, evt);
        }
        catch
        {
            // The WMI event-arrival thread must never die from an unhandled exception here.
        }
    }

    private static string? TryGetCommandLine(int processId)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                $"SELECT CommandLine FROM Win32_Process WHERE ProcessId = {processId}");
            using var results = searcher.Get();
            foreach (ManagementBaseObject result in results)
            {
                using (result)
                {
                    return result["CommandLine"] as string;
                }
            }
        }
        catch (ManagementException)
        {
            // The process may have already exited by the time we query it - fall back to
            // an empty command line rather than throwing.
        }

        return null;
    }

    /// <summary>
    /// Writes to both <see cref="Trace"/> (visible in DebugView/an attached debugger) and
    /// the console (visible when the app is launched via <c>dotnet run</c> from a
    /// terminal, as the README's live-demo instructions do) - so a demo watching the
    /// terminal can see process interception firing in real time.
    /// </summary>
    private static void LogDemo(string message)
    {
        var line = $"[ClickFixShield] {message}";
        Trace.WriteLine(line);
        Console.WriteLine(line);
    }

    private static bool TryKill(int processId)
    {
        try
        {
            using var process = System.Diagnostics.Process.GetProcessById(processId);
            process.Kill();
            return true;
        }
        catch
        {
            // Process may have already exited - a lost race, not an error.
            return false;
        }
    }
}
