# ClickFixShield

A Windows tray application that defends against **ClickFix** social-engineering attacks.

## What ClickFix is

A malicious web page shows a fake CAPTCHA, verification prompt, or error message that
instructs the victim to press **Win+R**, paste a command (already silently written to
the clipboard by the page's JavaScript), and press Enter. Because the victim manually
executes the payload, the browser's own download/SmartScreen warnings never fire — the
"attack" is really just social engineering a user into running an attacker-chosen
command line themselves.

## What this tool does

- **Clipboard monitoring** (`ClickFixShield.Core.Interception.ClipboardMonitor`) — watches
  the Windows clipboard via `AddClipboardFormatListener` and evaluates every text write
  against the detection engine. De-duplicates on the clipboard's own sequence number
  (`GetClipboardSequenceNumber`) rather than the raw notification, since Windows can (and
  does) broadcast `WM_CLIPBOARDUPDATE` more than once for a single logical write — most
  commonly when the Clipboard History/Cloud Clipboard shell service re-opens the
  clipboard a few milliseconds later to attach its own synthesized formats.
- **Win+R / process-launch correlation with best-effort kill**
  (`ProcessInterceptor`, `RunKeyHook`, `RunInterceptionDecider`) — subscribes to Windows
  process-start notifications (WMI `Win32_ProcessStartTrace`) and kills a matching
  process, gated by a strict safety rule (see *Known limitations* below).
- **Weighted heuristic detection engine** (`HeuristicDetectionEngine`) — every matching
  rule's weight contributes to an aggregate 0–100 score (not just the single best
  match), bucketed into four severity bands: `Safe < Suspicious < HighRisk < Malicious`.
  Rules are loaded from an external JSON file (`src/ClickFixShield.Core/Rules/rules.json`)
  so new patterns can be added without recompiling.
- **Local event logging** (`SqliteEventStore`) — every flagged/blocked event is persisted
  to a SQLite database at `%LOCALAPPDATA%\ClickFixShield\events.db`, so severity-range
  queries (`GetByMinimumLevel`) are real indexed SQL queries rather than linear scans.
- **Tray UI** (`TrayApplicationContext`, `ThreatDetailForm`, `EventHistoryForm`) —
  protection status, balloon-tip alerts, and a browsable event history with full
  per-event detail (matched rules, score, raw text).

## Build & run

```
dotnet build ClickFixShield.sln
dotnet test tests/ClickFixShield.Tests/ClickFixShield.Tests.csproj
dotnet run --project src/ClickFixShield.App
```

**Run as Administrator for full protection.** `Win32_ProcessStartTrace` (the process-launch
interception mechanism) requires elevated privileges to subscribe. If `ProcessInterceptor`
fails to subscribe (not elevated), it sets `IsActive = false` instead of throwing, and the
tray icon/tooltip/context menu switch to a "Limited (run as Administrator for full
protection)" state — clipboard monitoring still works, but suspicious process launches
will no longer be detected or killed.

## Customizing detection rules

Rules live in `src/ClickFixShield.Core/Rules/rules.json` (copied to the build output
directory automatically) and are editable without recompiling. Each rule is:

```json
{
  "Id": "SCRIPT-MSHTA",
  "Name": "mshta Execution",
  "Pattern": "\\bmshta(\\.exe)?\\b",
  "Weight": 55,
  "Category": "ScriptExecution",
  "Description": "Invokes mshta.exe, a classic HTA/remote-script execution LOLBin."
}
```

`Pattern` is a .NET regex (case-insensitive, 200ms match timeout). A rule whose pattern
fails to compile is skipped at load time rather than crashing the app. Every rule that
matches contributes its `Weight` toward the aggregate score; scores `<=20` are Safe,
`21–50` Suspicious, `51–80` HighRisk, `>80` Malicious.

## Novelty & Positioning

To be upfront about what this project is and isn't: ClickFixShield is **applied
engineering, not a novel detection algorithm.** Every individual piece - clipboard format
listeners, WMI process-start tracing, weighted regex heuristics, SQLite for local
storage - is a well-established Windows API or technique. Nothing here is a research
contribution in malware detection or a new algorithmic idea.

What it does offer:

- **A specific, under-addressed threat model.** ClickFix (fake CAPTCHA / "verification"
  pages that trick a user into pasting an attacker-supplied command into Win+R) is a
  real, currently active social-engineering technique that most consumer AV and browser
  protections don't directly target, because the "attack" never touches disk via a
  browser download - it's the user's own manual paste-and-Enter that runs it.
- **Local, zero-infrastructure operation.** No signature database, no cloud lookup, no
  telemetry, no account/license server. Detection is entirely self-contained heuristics
  over the clipboard/process-launch text itself, running fully offline.
- **Two complementary vantage points combined.** Most public ClickFix write-ups discuss
  detecting the clipboard write; fewer combine that with a best-effort kill on the actual
  process launch, correlated back to the earlier clipboard content. That correlation
  (`RunInterceptionDecider`) is the closest thing to a distinguishing design choice here,
  and it's still just weighted heuristics plus a time-window join - not machine learning,
  not behavioral/AI-based detection.

In short: this is a well-tested, honestly-scoped implementation of known techniques
aimed at a specific, real attack pattern - not a claim to have invented a new way to
detect malware.

## Testing & Validation

- **27 tests total.** The original 25 are pure-logic, dependency-free unit tests covering
  the detection engine's rule matching/scoring/classification, the process-interception
  decision logic (`RunInterceptionDecider`), and the clipboard correlation window.
- **A clipboard-monitor regression test** (`ClipboardMonitorTests`) drives the real Win32
  clipboard and message loop end-to-end and asserts a single clipboard write produces
  exactly one `SecurityEvent`, guarding against the duplicate-notification bug described
  above.
- **A labeled precision/recall corpus** (`tests/ClickFixShield.Tests/Corpus/DetectionCorpusTests.cs`)
  runs the shipped `rules.json` against 20 hand-labeled attack-shaped strings (realistic
  ClickFix-style wrapper syntax around a harmless embedded action, covering every rule
  category) and 30 benign strings (URLs, git/npm/pip/dotnet/cloud CLI commands,
  legitimate PowerShell, plain text). It measures the engine against the same `HighRisk`
  threshold `RunInterceptionDecider` actually gates a kill decision on, and writes a full
  row-by-row markdown report to
  [`DETECTION_VALIDATION_REPORT.md`](DETECTION_VALIDATION_REPORT.md) on every test run.
  Current result: **100% precision, 95% recall** - zero benign strings are ever flagged
  HighRisk+, and 19/20 attack-shaped strings are correctly flagged; the one miss (a bare
  `wscript.exe` invocation with no other wrapper technique) is called out by name in the
  report as a known, honest gap rather than hidden.
- Run everything with `dotnet test tests/ClickFixShield.Tests/ClickFixShield.Tests.csproj`.

## Known limitations

This is a v1 defensive tool, and its guarantees are intentionally modest — stated
plainly rather than oversold:

- **No kernel-mode driver, so blocking is not guaranteed prevention.** True
  pre-execution blocking of arbitrary process creation requires a signed kernel driver
  (`PsSetCreateProcessNotifyRoutineEx`), which is out of scope for v1 (no code signing,
  no installer). Instead, `ProcessInterceptor` detects-and-kills near-real-time via a WMI
  process-start trace — there is an inherent race, and a malicious payload's first
  milliseconds of execution may already have run before the kill lands.
- **Requires Administrator privileges** for process interception to work at all (see
  *Build & run* above); clipboard monitoring works unprivileged.
- **Windows-only.**
- **Local-only** — no cloud telemetry or reporting of any kind.
- **Does not clear or modify the clipboard.** v1 flags and logs suspicious clipboard
  content but never touches it, to avoid interfering with legitimate copy/paste.
- **No auto-update, code signing, or installer.** Run from source or a local build
  output only.

## Explicitly out of scope for v1

- Cloud telemetry/reporting
- Auto-update mechanism
- Code signing / installer packaging
- Non-Windows platforms
- Kernel-mode driver / guaranteed pre-execution blocking
