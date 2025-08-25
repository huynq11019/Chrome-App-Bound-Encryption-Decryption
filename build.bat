@echo off
setlocal

echo ================================================
echo Chrome ABE Decryption - Developer Build Script
echo ================================================

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
) else if exist "C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\Common7\Tools\VsDevCmd.bat" (
    set "VSPATH=C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\Common7\Tools\VsDevCmd.bat"
) else if exist "C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\Common7\Tools\VsDevCmd.bat" (
    set "VSPATH=C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\Common7\Tools\VsDevCmd.bat"
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

REM Initialize VS environment and run build
call "%VSPATH%" -arch=x64
if %errorlevel% neq 0 (
    echo [ERROR] Failed to initialize Visual Studio environment.
    pause
    exit /b 1
)

:build
echo [INFO] Starting build process...
echo.

REM Run the actual build
call make.bat

if %errorlevel% equ 0 (
    echo.
    echo [SUCCESS] Build completed successfully!
    echo [INFO] Output: chrome_inject.exe
) else (
    echo.
    echo [ERROR] Build failed with error code %errorlevel%
)

echo.
pause
