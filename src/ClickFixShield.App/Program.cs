using ClickFixShield.Core.Contracts;
using ClickFixShield.Core.Interception;
using ClickFixShield.Core.Persistence;
using ClickFixShield.Core.Rules;

namespace ClickFixShield.App;

internal static class Program
{
    [STAThread]
    private static void Main()
    {
        ApplicationConfiguration.Initialize();

        var rulesPath = Path.Combine(AppContext.BaseDirectory, "Rules", "rules.json");
        var rules = HeuristicDetectionEngine.LoadRulesFromFile(rulesPath);
        IDetectionEngine engine = new HeuristicDetectionEngine(rules);

        IEventStore eventStore = new SqliteEventStore();
        IThreatCorrelationWindow correlationWindow = new ThreatCorrelationWindow();

        var decider = new RunInterceptionDecider(engine, correlationWindow);
        var processInterceptor = new ProcessInterceptor(decider, eventStore);
        IClipboardMonitor clipboardMonitor = new ClipboardMonitor(engine, eventStore, correlationWindow);
        var runKeyHook = new RunKeyHook();

        processInterceptor.Start();
        clipboardMonitor.Start();
        runKeyHook.Start();

        Application.Run(new TrayApplicationContext(eventStore, clipboardMonitor, processInterceptor, runKeyHook));
    }
}
