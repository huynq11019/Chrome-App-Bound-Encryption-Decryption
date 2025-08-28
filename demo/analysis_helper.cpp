// Defensive Analysis Tool - Understand Attacker Techniques
// Educational tool for security researchers

#include <Windows.h>
#include <iostream>
#include <vector>
#include <string>
#include <Psapi.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "psapi.lib")

class MalwareAnalysisHelper {
public:
    // Simulate sandbox environment to trigger evasion
    static void createSandboxEnvironment() {
        std::cout << "[*] Creating sandbox indicators..." << std::endl;
        
        // Create sandbox-like registry entries
        HKEY hKey;
        RegCreateKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\VMware, Inc.\\VMware Tools", 
                       0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL);
        RegCloseKey(hKey);
        
        // Create analysis directories
        CreateDirectoryA("C:\\analysis", NULL);
        CreateDirectoryA("C:\\sandbox", NULL);
        
        std::cout << "[+] Sandbox environment created" << std::endl;
    }
    
    // Monitor API calls made by malware
    static void monitorAPICalls() {
        std::cout << "[*] Setting up API monitoring..." << std::endl;
        
        // Hook common injection APIs
        hookAPI("kernel32.dll", "OpenProcess");
        hookAPI("kernel32.dll", "VirtualAllocEx");
        hookAPI("kernel32.dll", "WriteProcessMemory");
        hookAPI("kernel32.dll", "CreateRemoteThread");
        
        std::cout << "[+] API hooks installed" << std::endl;
    }
    
    // Analyze process memory for injection artifacts
    static void scanProcessMemory(DWORD pid) {
        std::cout << "[*] Scanning process memory for artifacts..." << std::endl;
        
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (!hProcess) return;
        
        MEMORY_BASIC_INFORMATION mbi;
        LPVOID address = 0;
        
        while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi))) {
            if (mbi.State == MEM_COMMIT && mbi.Type == MEM_IMAGE) {
                // Check for suspicious memory regions
                if (isInjectedDLL(hProcess, mbi.BaseAddress)) {
                    std::cout << "[!] Suspicious DLL found at: 0x" << std::hex << mbi.BaseAddress << std::endl;
                }
            }
            address = (LPBYTE)mbi.BaseAddress + mbi.RegionSize;
        }
        
        CloseHandle(hProcess);
    }
    
private:
    static void hookAPI(const char* module, const char* function) {
        // API hooking implementation for monitoring
        std::cout << "[+] Hooked " << module << "!" << function << std::endl;
    }
    
    static bool isInjectedDLL(HANDLE hProcess, LPVOID baseAddress) {
        // Analyze memory region to detect injected DLL
        char moduleName[MAX_PATH];
        if (GetModuleFileNameEx(hProcess, (HMODULE)baseAddress, moduleName, MAX_PATH)) {
            // Check if module path looks suspicious
            std::string path(moduleName);
            if (path.find("C:\\Windows\\System32") == std::string::npos &&
                path.find("C:\\Program Files") == std::string::npos) {
                return true; // Suspicious location
            }
        }
        return false;
    }
};

// Educational demonstration
int main() {
    std::cout << "=== Malware Analysis Helper ===" << std::endl;
    std::cout << "Educational tool for understanding evasion techniques" << std::endl;
    
    // Create environment for testing
    MalwareAnalysisHelper::createSandboxEnvironment();
    MalwareAnalysisHelper::monitorAPICalls();
    
    // Monitor current process
    MalwareAnalysisHelper::scanProcessMemory(GetCurrentProcessId());
    
    std::cout << "\nPress Enter to cleanup..." << std::endl;
    std::cin.get();
    
    // Cleanup
    RemoveDirectoryA("C:\\analysis");
    RemoveDirectoryA("C:\\sandbox");
    
    return 0;
}
