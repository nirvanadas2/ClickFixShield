using System.Runtime.InteropServices;

namespace ClickFixShield.Core.Interception;

/// <summary>
/// Low-level keyboard hook that detects the Win+R chord as a correlation *signal* only.
/// Never blocks or swallows the keystroke - <see cref="CallNextHookEx"/> runs
/// unconditionally, so normal Win+R behavior for legitimate use is completely unaffected.
/// </summary>
public sealed class RunKeyHook : IDisposable
{
    private const int WhKeyboardLl = 13;
    private const int WmKeyDown = 0x0100;
    private const int WmSysKeyDown = 0x0104;
    private const int VkR = 0x52;
    private const int VkLWin = 0x5B;
    private const int VkRWin = 0x5C;

    private readonly LowLevelKeyboardProc _proc;
    private nint _hookHandle;

    public event EventHandler<DateTimeOffset>? RunDialogOpened;

    public RunKeyHook()
    {
        _proc = HookCallback;
    }

    public void Start()
    {
        if (_hookHandle != 0)
        {
            return;
        }

        using var currentProcess = System.Diagnostics.Process.GetCurrentProcess();
        using var currentModule = currentProcess.MainModule!;
        var moduleHandle = GetModuleHandle(currentModule.ModuleName);
        _hookHandle = SetWindowsHookEx(WhKeyboardLl, _proc, moduleHandle, 0);
    }

    public void Stop()
    {
        if (_hookHandle != 0)
        {
            UnhookWindowsHookEx(_hookHandle);
            _hookHandle = 0;
        }
    }

    public void Dispose() => Stop();

    private nint HookCallback(int nCode, nint wParam, nint lParam)
    {
        try
        {
            if (nCode >= 0 && (wParam == WmKeyDown || wParam == WmSysKeyDown))
            {
                var data = Marshal.PtrToStructure<KbdLlHookStruct>(lParam);
                if (data.VkCode == VkR &&
                    ((GetAsyncKeyState(VkLWin) & 0x8000) != 0 || (GetAsyncKeyState(VkRWin) & 0x8000) != 0))
                {
                    RunDialogOpened?.Invoke(this, DateTimeOffset.UtcNow);
                }
            }
        }
        catch
        {
            // A hook callback must never throw back into the global message loop.
        }

        return CallNextHookEx(_hookHandle, nCode, wParam, lParam);
    }

    private delegate nint LowLevelKeyboardProc(int nCode, nint wParam, nint lParam);

    [StructLayout(LayoutKind.Sequential)]
    private struct KbdLlHookStruct
    {
        public uint VkCode;
        public uint ScanCode;
        public uint Flags;
        public uint Time;
        public nint ExtraInfo;
    }

    [DllImport("user32.dll", SetLastError = true)]
    private static extern nint SetWindowsHookEx(int idHook, LowLevelKeyboardProc lpfn, nint hMod, uint dwThreadId);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool UnhookWindowsHookEx(nint hhk);

    [DllImport("user32.dll")]
    private static extern nint CallNextHookEx(nint hhk, int nCode, nint wParam, nint lParam);

    [DllImport("kernel32.dll")]
    private static extern nint GetModuleHandle(string? lpModuleName);

    [DllImport("user32.dll")]
    private static extern short GetAsyncKeyState(int vKey);
}
