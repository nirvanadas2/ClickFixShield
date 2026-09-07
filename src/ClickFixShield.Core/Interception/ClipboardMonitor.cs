using System.Runtime.InteropServices;
using System.Threading;
using ClickFixShield.Core.Contracts;
using ClickFixShield.Core.Models;

namespace ClickFixShield.Core.Interception;

/// <summary>
/// Watches the Windows clipboard for suspicious ClickFix-style content via
/// <c>AddClipboardFormatListener</c> on a dedicated hidden message-only window, so this
/// class has no dependency on the WinForms app (Core must not reference WinForms/WPF).
/// The window and its message pump live on their own background thread.
/// </summary>
public sealed class ClipboardMonitor : IClipboardMonitor
{
    private const uint CfUnicodeText = 13;
    private const uint WmClipboardUpdate = 0x031D;
    private static readonly nint HwndMessage = new(-3);

    private readonly IDetectionEngine _engine;
    private readonly IEventStore _eventStore;
    private readonly IThreatCorrelationWindow _correlationWindow;
    private readonly ClipboardMonitorOptions _options;

    private readonly ManualResetEventSlim _windowReady = new(false);
    private Thread? _messageThread;
    private nint _windowHandle;
    private uint _threadId;

    // Windows can (and does) deliver more than one WM_CLIPBOARDUPDATE for what a user
    // perceives as a single copy - most commonly because the Clipboard History / Cloud
    // Clipboard shell service (cbdhsvc) re-opens the clipboard a few ms later to add its
    // own synthesized formats, which broadcasts a second, content-identical notification.
    // The clipboard sequence number only advances on an actual content change, so it is
    // the correct signal to de-duplicate on - not the message arrival itself, and not a
    // post-hoc text comparison at the log layer.
    private uint? _lastProcessedSequence;

    // Keeps the callback delegate alive for the window's lifetime - otherwise the GC can
    // collect it while native code still holds a function pointer to it.
    private WndProcDelegate? _wndProc;

    public event EventHandler<SecurityEvent>? ThreatDetected;

    public ClipboardMonitor(
        IDetectionEngine engine,
        IEventStore eventStore,
        IThreatCorrelationWindow correlationWindow,
        ClipboardMonitorOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(engine);
        ArgumentNullException.ThrowIfNull(eventStore);
        ArgumentNullException.ThrowIfNull(correlationWindow);

        _engine = engine;
        _eventStore = eventStore;
        _correlationWindow = correlationWindow;
        _options = options ?? new ClipboardMonitorOptions();
    }

    public void Start()
    {
        if (_messageThread is not null)
        {
            return;
        }

        _messageThread = new Thread(RunMessageLoop)
        {
            IsBackground = true,
            Name = "ClickFixShield.ClipboardMonitor"
        };
        _messageThread.SetApartmentState(ApartmentState.STA);
        _messageThread.Start();
        _windowReady.Wait();
    }

    public void Stop()
    {
        if (_messageThread is null)
        {
            return;
        }

        PostThreadMessage(_threadId, WmQuit, 0, 0);
        _messageThread.Join(TimeSpan.FromSeconds(2));
        _messageThread = null;
        _windowReady.Reset();
    }

    public void Dispose()
    {
        Stop();
        _windowReady.Dispose();
    }

    private void RunMessageLoop()
    {
        _threadId = GetCurrentThreadId();
        _wndProc = WindowProc;

        var className = "ClickFixShield.ClipboardMonitor." + Guid.NewGuid().ToString("N");
        var moduleHandle = GetModuleHandleW(null);
        var wndClass = new WNDCLASS
        {
            lpfnWndProc = _wndProc,
            hInstance = moduleHandle,
            lpszClassName = className
        };

        RegisterClassW(ref wndClass);

        _windowHandle = CreateWindowExW(
            0, className, "ClickFixShieldClipboardMonitor", 0, 0, 0, 0, 0,
            HwndMessage, 0, moduleHandle, 0);

        if (_windowHandle != 0)
        {
            AddClipboardFormatListener(_windowHandle);
        }

        _windowReady.Set();

        while (GetMessageW(out var msg, 0, 0, 0) > 0)
        {
            TranslateMessage(ref msg);
            DispatchMessageW(ref msg);
        }

        if (_windowHandle != 0)
        {
            RemoveClipboardFormatListener(_windowHandle);
            DestroyWindow(_windowHandle);
            _windowHandle = 0;
        }

        UnregisterClassW(className, moduleHandle);
    }

    private nint WindowProc(nint hWnd, uint msg, nint wParam, nint lParam)
    {
        if (msg == WmClipboardUpdate)
        {
            try
            {
                OnClipboardUpdated();
            }
            catch
            {
                // A window procedure must never throw back into the message loop.
            }

            return 0;
        }

        return DefWindowProcW(hWnd, msg, wParam, lParam);
    }

    private void OnClipboardUpdated()
    {
        var sequence = GetClipboardSequenceNumber();
        if (_lastProcessedSequence.HasValue && sequence == _lastProcessedSequence.Value)
        {
            return;
        }

        _lastProcessedSequence = sequence;

        var text = TryReadClipboardText();
        if (string.IsNullOrEmpty(text))
        {
            return;
        }

        var observedAt = DateTimeOffset.UtcNow;
        var detection = _engine.Evaluate(text, observedAt);
        if (detection.Level <= ThreatLevel.Safe)
        {
            return;
        }

        _correlationWindow.Record(text, observedAt);

        // v1 deliberately does not clear/modify the clipboard - flag-and-log only, so
        // legitimate copy/paste is never interfered with. This is a product decision,
        // not an oversight.
        var evt = new SecurityEvent(Guid.NewGuid(), observedAt, ThreatSource.Clipboard, text, detection, ThreatAction.Flagged);
        _eventStore.Save(evt);
        ThreatDetected?.Invoke(this, evt);
    }

    private string? TryReadClipboardText()
    {
        for (var attempt = 0; attempt < _options.ReadRetryCount; attempt++)
        {
            if (attempt > 0)
            {
                Thread.Sleep(_options.ReadRetryDelay);
            }

            if (!IsClipboardFormatAvailable(CfUnicodeText))
            {
                return null;
            }

            // Another process (e.g. the source browser) may briefly hold the clipboard
            // open - OpenClipboard failing here is expected and worth a short retry.
            if (!OpenClipboard(_windowHandle))
            {
                continue;
            }

            try
            {
                var handle = GetClipboardData(CfUnicodeText);
                if (handle == 0)
                {
                    return null;
                }

                var pointer = GlobalLock(handle);
                if (pointer == 0)
                {
                    continue;
                }

                try
                {
                    return Marshal.PtrToStringUni(pointer);
                }
                finally
                {
                    GlobalUnlock(handle);
                }
            }
            finally
            {
                CloseClipboard();
            }
        }

        return null;
    }

    private delegate nint WndProcDelegate(nint hWnd, uint msg, nint wParam, nint lParam);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WNDCLASS
    {
        public uint style;
        public WndProcDelegate lpfnWndProc;
        public int cbClsExtra;
        public int cbWndExtra;
        public nint hInstance;
        public nint hIcon;
        public nint hCursor;
        public nint hbrBackground;
        public string? lpszMenuName;
        public string lpszClassName;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct POINT
    {
        public int x;
        public int y;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MSG
    {
        public nint hwnd;
        public uint message;
        public nint wParam;
        public nint lParam;
        public uint time;
        public POINT pt;
    }

    private const uint WmQuit = 0x0012;

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern ushort RegisterClassW(ref WNDCLASS lpWndClass);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern bool UnregisterClassW(string lpClassName, nint hInstance);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern nint CreateWindowExW(
        uint dwExStyle, string lpClassName, string lpWindowName, uint dwStyle,
        int x, int y, int nWidth, int nHeight,
        nint hWndParent, nint hMenu, nint hInstance, nint lpParam);

    [DllImport("user32.dll")]
    private static extern nint DefWindowProcW(nint hWnd, uint msg, nint wParam, nint lParam);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool DestroyWindow(nint hWnd);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern nint GetModuleHandleW(string? lpModuleName);

    [DllImport("kernel32.dll")]
    private static extern uint GetCurrentThreadId();

    [DllImport("user32.dll")]
    private static extern bool AddClipboardFormatListener(nint hwnd);

    [DllImport("user32.dll")]
    private static extern bool RemoveClipboardFormatListener(nint hwnd);

    [DllImport("user32.dll")]
    private static extern int GetMessageW(out MSG lpMsg, nint hWnd, uint wMsgFilterMin, uint wMsgFilterMax);

    [DllImport("user32.dll")]
    private static extern bool TranslateMessage(ref MSG lpMsg);

    [DllImport("user32.dll")]
    private static extern nint DispatchMessageW(ref MSG lpMsg);

    [DllImport("user32.dll")]
    private static extern bool PostThreadMessage(uint idThread, uint msg, nint wParam, nint lParam);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool OpenClipboard(nint hWndNewOwner);

    [DllImport("user32.dll")]
    private static extern bool CloseClipboard();

    [DllImport("user32.dll")]
    private static extern bool IsClipboardFormatAvailable(uint format);

    [DllImport("user32.dll")]
    private static extern uint GetClipboardSequenceNumber();

    [DllImport("user32.dll")]
    private static extern nint GetClipboardData(uint uFormat);

    [DllImport("kernel32.dll")]
    private static extern nint GlobalLock(nint hMem);

    [DllImport("kernel32.dll")]
    private static extern bool GlobalUnlock(nint hMem);
}
