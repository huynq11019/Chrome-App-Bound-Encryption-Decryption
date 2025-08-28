@echo off
setlocal

echo === DLL Injection Demo Build Script ===
echo WARNING: Educational purpose only!
echo.

REM Check if we're already in a VS Developer environment
where cl >nul 2>&1
if %errorlevel% equ 0 (
    echo [INFO] Already in Visual Studio Developer environment.
    goto :build
)

echo [INFO] Initializing Visual Studio Developer Command Prompt...

REM Try different VS installation paths
set "VSPATH="
if exist "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat" (
    set "VSPATH=C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat"
) else if exist "C:\Program Files\Microsoft Visual Studio\2022\Professional\Common7\Tools\VsDevCmd.bat" (
    set "VSPATH=C:\Program Files\Microsoft Visual Studio\2022\Professional\Common7\Tools\VsDevCmd.bat"
) else if exist "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\Common7\Tools\VsDevCmd.bat" (
    set "VSPATH=C:\Program Files\Microsoft Visual Studio\2022\Enterprise\Common7\Tools\VsDevCmd.bat"
) else if exist "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\Tools\VsDevCmd.bat" (
    set "VSPATH=C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\Tools\VsDevCmd.bat"
)

if "%VSPATH%"=="" (
    echo [ERROR] Visual Studio Developer Command Prompt not found!
    echo [ERROR] Please install Visual Studio with C++ development tools.
    echo [ERROR] Or manually run from "Developer Command Prompt for VS".
    pause
    exit /b 1
)

echo [INFO] Found VS tools at: %VSPATH%
echo [INFO] Setting up x64 development environment...

REM Initialize VS environment
call "%VSPATH%" -arch=x64
if %errorlevel% neq 0 (
    echo [ERROR] Failed to initialize Visual Studio environment.
    pause
    exit /b 1
)

:build
echo [INFO] Starting build process...

REM Create temp directory for logs
if not exist "C:\temp" mkdir "C:\temp"

echo [*] Building test DLL...
cl.exe /LD test_dll.cpp /Fe:test_dll.dll
if %ERRORLEVEL% NEQ 0 (
    echo [-] Failed to build DLL
    pause
    exit /b 1
)

echo [+] DLL built successfully

echo [*] Building injector...
cl.exe simple_dll_inject.cpp /Fe:injector.exe
if %ERRORLEVEL% NEQ 0 (
    echo [-] Failed to build injector
    pause
    exit /b 1
)

echo [+] Injector built successfully
echo.

echo === Usage Instructions ===
echo 1. Start notepad.exe
echo 2. Run: injector.exe
echo 3. Check C:\temp\injection_log.txt for results
echo.

echo === Files created ===
dir *.dll *.exe
echo.

echo Press any key to continue...
pause > nul
