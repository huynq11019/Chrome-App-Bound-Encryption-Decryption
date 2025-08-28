@echo off
echo === DLL Injection Demo - Simple Build ===
echo WARNING: Educational purpose only!
echo.

REM Setup VS environment
call "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat" -arch=x64

REM Create temp directory
if not exist "C:\temp" mkdir "C:\temp"

echo [*] Building test DLL...
cl.exe /LD test_dll.cpp /Fe:test_dll.dll /nologo
if %ERRORLEVEL% NEQ 0 (
    echo [-] Failed to build DLL
    pause
    exit /b 1
)

echo [+] DLL built successfully

echo [*] Building injector...
cl.exe simple_dll_inject.cpp /Fe:injector.exe /nologo
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
dir *.dll *.exe 2>nul
echo.

echo Press any key to continue...
pause > nul
