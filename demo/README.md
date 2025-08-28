# DLL Injection Demo

⚠️ **WARNING: Educational Purpose Only!**

This demo shows basic DLL injection techniques. Only use for:
- Learning and research
- Authorized security testing
- Your own systems

## Files:

1. **simple_dll_inject.cpp** - Main injector program
2. **test_dll.cpp** - Test DLL to inject
3. **build_demo.bat** - Build script

## Requirements:

- Windows 10/11
- Visual Studio Build Tools or full VS
- Administrator privileges
- Developer Command Prompt

## Build Instructions:

1. Open **Developer Command Prompt for VS**
2. Navigate to this directory
3. Run: `build_demo.bat`

## Usage:

1. Start `notepad.exe`
2. Run `injector.exe`
3. Check `C:\temp\injection_log.txt` for results

## How it works:

1. **Process Discovery**: Find target process by name
2. **Memory Allocation**: Allocate memory in target process
3. **DLL Path Writing**: Write DLL path to target memory
4. **LoadLibrary**: Create remote thread calling LoadLibraryA
5. **Verification**: Check if DLL loaded successfully

## Security Notes:

- Modern Windows has protections against injection
- Some antivirus may flag this as suspicious
- UAC/DEP/ASLR may interfere
- Some processes are protected (PPL)

## Defensive Measures:

- Process protection (PPL)
- Code integrity checks
- EDR/AV behavioral detection
- Application sandboxing
- Principle of least privilege

## Legal Notice:

Use responsibly and only where authorized. Unauthorized access to computer systems is illegal in most jurisdictions.
