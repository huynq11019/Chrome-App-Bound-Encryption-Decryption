@echo off
echo === Advanced Stealth Injector Build ===
echo WARNING: Educational purpose only!

REM Setup VS environment
call "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat" -arch=x64

echo [*] Building evasion techniques demo...
cl.exe /O2 /MT /EHsc evasion_techniques.cpp /Fe:evasion_demo.exe /nologo
if %ERRORLEVEL% NEQ 0 (
    echo [-] Failed to build evasion demo
    pause
    exit /b 1
)

echo [*] Building stealth injector...
cl.exe /O2 /MT /EHsc stealth_injector.cpp /Fe:stealth_injector.exe /nologo
if %ERRORLEVEL% NEQ 0 (
    echo [-] Failed to build stealth injector
    pause
    exit /b 1
)

echo [*] Building analysis helper...
cl.exe /O2 /MT /EHsc analysis_helper.cpp /Fe:analysis_helper.exe /nologo
if %ERRORLEVEL% NEQ 0 (
    echo [-] Failed to build analysis helper
    pause
    exit /b 1
)

echo [+] All components built successfully!
echo.

echo === Files Created ===
dir *.exe

echo.
echo === Usage Instructions ===
echo 1. evasion_demo.exe     - Demonstrates evasion techniques
echo 2. stealth_injector.exe - Advanced injection with evasion
echo 3. analysis_helper.exe  - Tool for analyzing evasion techniques
echo.

echo === Security Testing Workflow ===
echo 1. Run analysis_helper.exe to set up monitoring
echo 2. Execute stealth_injector.exe to test evasion
echo 3. Analyze results and improve detection

pause
