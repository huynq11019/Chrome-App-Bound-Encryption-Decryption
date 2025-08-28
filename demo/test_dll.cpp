// Test DLL - Educational Purpose Only
// This DLL will be injected into target process

#include <Windows.h>
#include <iostream>
#include <fstream>

// Export function for easy identification
extern "C" __declspec(dllexport) void TestFunction() {
    // Simple test function
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        {
            // DLL attached to process
            // Create a simple log file to prove injection worked
            std::ofstream logFile("C:\\temp\\injection_log.txt", std::ios::app);
            if (logFile.is_open()) {
                logFile << "DLL injected successfully into process!" << std::endl;
                logFile << "Process ID: " << GetCurrentProcessId() << std::endl;
                logFile << "Thread ID: " << GetCurrentThreadId() << std::endl;
                
                // Get process name
                char processName[MAX_PATH];
                GetModuleFileNameA(NULL, processName, MAX_PATH);
                logFile << "Process: " << processName << std::endl;
                logFile << "Timestamp: " << GetTickCount64() << std::endl;
                logFile << "---" << std::endl;
                logFile.close();
            }

            // Optional: Show message box (for demo only)
            // MessageBoxA(NULL, "DLL Injected Successfully!", "Injection Test", MB_OK);
        }
        break;

    case DLL_THREAD_ATTACH:
        // Thread attached
        break;

    case DLL_THREAD_DETACH:
        // Thread detaching
        break;

    case DLL_PROCESS_DETACH:
        // DLL detaching from process
        {
            std::ofstream logFile("C:\\temp\\injection_log.txt", std::ios::app);
            if (logFile.is_open()) {
                logFile << "DLL detached from process " << GetCurrentProcessId() << std::endl;
                logFile << "---" << std::endl;
                logFile.close();
            }
        }
        break;
    }
    return TRUE;
}
