# DLL Injection - Hướng Dẫn Thực Hành Từng Bước

🎯 **Hướng dẫn step-by-step để thực hiện DLL injection thành công**

---

## 🚀 **Chuẩn Bị Môi Trường**

### **1. Kiểm tra Windows Version:**
```powershell
# Kiểm tra version Windows
Get-ComputerInfo | Select WindowsProductName, WindowsVersion

# Kiểm tra architecture
[Environment]::Is64BitOperatingSystem
```

### **2. Cài đặt Visual Studio:**
```
Visual Studio 2019/2022 Community (Free)
├── Workloads:
│   ├── Desktop development with C++
│   └── Windows SDK (latest version)
├── Individual components:
│   ├── MSVC v143 compiler
│   ├── Windows SDK
│   └── CMake tools
```

### **3. Kiểm tra Developer Environment:**
```cmd
# Mở Developer Command Prompt for VS
# Hoặc run command:
"C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat"

# Test compiler
cl.exe /?
```

---

## 🔨 **Build Demo Project**

### **Bước 1: Clone/Download Project**
```powershell
# Navigate to project directory
cd "D:\hacker\Chrome-App-Bound-Encryption-Decryption\demo"

# List files
dir
```

### **Bước 2: Build DLL và Injector**
```cmd
# Mở Developer Command Prompt
# Chạy build script
.\build_simple.bat
```

**📋 Expected Output:**
```
=== DLL Injection Demo - Simple Build ===
[*] Building test DLL...
[+] DLL built successfully
[*] Building injector...
[+] Injector built successfully

Files created:
test_dll.dll     (285 KB)
injector.exe     (303 KB)
```

### **Bước 3: Verify Build**
```powershell
# Check file sizes và timestamps
Get-ChildItem *.dll,*.exe | Format-Table Name,Length,LastWriteTime

# Check if files are PE executables
Get-FileHash *.dll,*.exe -Algorithm MD5
```

---

## 🎯 **Thực Hiện Injection**

### **Bước 1: Chuẩn bị Target Process**
```powershell
# Start notepad
Start-Process notepad.exe

# Verify notepad is running
Get-Process notepad | Format-Table Id,ProcessName,Path

# Expected output:
# Id ProcessName Path
# -- ----------- ----
# 1234 notepad   C:\WINDOWS\system32\notepad.exe
```

### **Bước 2: Chạy Injector**
```powershell
# Run injector với admin privileges
Start-Process .\injector.exe -Verb RunAs

# Hoặc run trực tiếp nếu đã có admin rights
.\injector.exe
```

**📋 Console Output:**
```
=== Simple DLL Injection Demo ===
WARNING: Educational purpose only!

[*] Make sure notepad.exe is running and test.dll exists
[*] Press Enter to continue or Ctrl+C to exit...

[*] Searching for process: notepad.exe
[+] Found process ID: 1234
[+] Process opened successfully
[+] Memory allocated at: 0x7FF123456789
[+] DLL path written to target memory
[+] LoadLibraryA address: 0x7FFE12345678
[+] Remote thread created successfully
[+] DLL loaded at: 0x180000000
[+] Injection successful!
```

### **Bước 3: Verify Injection Success**
```powershell
# Check log file
Get-Content "C:\temp\injection_log.txt"

# Expected content:
# DLL injected successfully into process!
# Process ID: 1234
# Thread ID: 5678
# Process: C:\WINDOWS\system32\notepad.exe
# Timestamp: 431276796
```

---

## 🔍 **Troubleshooting Guide**

### **❌ Problem 1: "cl.exe not recognized"**
```
Cause: Visual Studio environment chưa được setup
Solution:
1. Mở "Developer Command Prompt for VS"
2. Hoặc run: VsDevCmd.bat -arch=x64
3. Re-run build script
```

### **❌ Problem 2: "Access denied (5)"**
```
Cause: Không đủ quyền administrator
Solution:
1. Right-click PowerShell → "Run as Administrator"
2. Hoặc disable UAC temporarily
3. Re-run injector
```

### **❌ Problem 3: "Process not found"**
```
Cause: Target process không chạy hoặc sai tên
Solution:
1. Verify target process: Get-Process notepad
2. Check process name spelling
3. Start target process trước khi inject
```

### **❌ Problem 4: "DLL loading failed"**
```
Cause: DLL path sai hoặc DLL corrupted
Solution:
1. Check DLL exists: Test-Path .\test_dll.dll
2. Verify DLL path trong injector code
3. Rebuild DLL
```

### **❌ Problem 5: "Remote thread creation failed"**
```
Cause: Process protection hoặc architecture mismatch
Solution:
1. Check target process architecture
2. Try different target (notepad.exe thường OK)
3. Disable antivirus temporarily
```

---

## 🛠️ **Customization Guide**

### **1. Thay đổi Target Process:**

**Sửa trong `simple_dll_inject.cpp`:**
```cpp
// Thay đổi từ:
std::wstring targetProcess = L"notepad.exe";

// Thành:
std::wstring targetProcess = L"calculator.exe";  // Windows Calculator
// hoặc
std::wstring targetProcess = L"mspaint.exe";     // MS Paint
```

### **2. Thêm Functionality vào DLL:**

**Sửa trong `test_dll.cpp`:**
```cpp
case DLL_PROCESS_ATTACH:
{
    // Thêm code của bạn ở đây
    MessageBoxA(NULL, "Hello from injected DLL!", "Success", MB_OK);
    
    // Hoặc
    AllocConsole();
    freopen_s((FILE**)stdout, "CONOUT$", "w", stdout);
    printf("DLL injected into PID: %d\n", GetCurrentProcessId());
    
    // Original logging code...
}
```

### **3. Multi-Process Injection:**

**Thêm function mới:**
```cpp
void InjectAllProcesses(const std::string& dllPath) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);
    
    if (Process32FirstW(hSnapshot, &pe)) {
        do {
            // Filter processes (avoid system processes)
            if (wcsstr(pe.szExeFile, L".exe") && pe.th32ProcessID > 1000) {
                InjectDLL(pe.szExeFile, dllPath);
            }
        } while (Process32NextW(hSnapshot, &pe));
    }
}
```

---

## 📊 **Monitoring và Analysis**

### **1. Process Monitor Setup:**
```powershell
# Download Process Monitor từ Microsoft Sysinternals
# Filter cho process events:
# - Process Name contains "notepad"
# - Operation is "Process and Thread Activity"
```

### **2. API Monitor Setup:**
```powershell
# Download API Monitor (free)
# Monitor APIs:
# - kernel32.dll!LoadLibraryA
# - kernel32.dll!CreateRemoteThread
# - ntdll.dll!NtCreateThreadEx
```

### **3. PowerShell Monitoring:**
```powershell
# Monitor DLL loads
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Kernel-Process/Analytic'} | 
    Where-Object {$_.Message -like "*LoadImage*"} |
    Select-Object TimeCreated,Id,Message

# Monitor process creation
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688} |
    Where-Object {$_.Message -like "*notepad*"}
```

---

## 🔬 **Advanced Experiments**

### **Experiment 1: DLL Persistence**
```cpp
// Thêm vào DllMain
case DLL_PROCESS_ATTACH:
{
    // Tạo thread để DLL persist
    CreateThread(NULL, 0, PersistentThread, NULL, 0, NULL);
}

DWORD WINAPI PersistentThread(LPVOID param) {
    while (true) {
        Sleep(5000);
        OutputDebugStringA("DLL still active...");
    }
    return 0;
}
```

### **Experiment 2: API Hooking**
```cpp
// Hook MessageBoxA
FARPROC originalMessageBox = GetProcAddress(GetModuleHandleA("user32.dll"), "MessageBoxA");

int WINAPI HookedMessageBox(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
    // Log the call
    OutputDebugStringA("MessageBox called!");
    
    // Call original function
    return ((int(WINAPI*)(HWND, LPCSTR, LPCSTR, UINT))originalMessageBox)
           (hWnd, "Hooked!", lpCaption, uType);
}
```

### **Experiment 3: Process Memory Scanning**
```cpp
void ScanProcessMemory(HANDLE hProcess) {
    MEMORY_BASIC_INFORMATION mbi;
    LPVOID address = 0;
    
    while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT && mbi.Protect == PAGE_EXECUTE_READWRITE) {
            printf("Suspicious memory at: 0x%p\n", mbi.BaseAddress);
        }
        address = (LPBYTE)mbi.BaseAddress + mbi.RegionSize;
    }
}
```

---

## 📈 **Performance Metrics**

### **Benchmarking Injection Speed:**
```cpp
#include <chrono>

auto start = std::chrono::high_resolution_clock::now();
bool success = injector.InjectDLL(targetProcess, dllPath);
auto end = std::chrono::high_resolution_clock::now();

auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
std::cout << "Injection took: " << duration.count() << "ms" << std::endl;
```

### **Memory Usage Analysis:**
```cpp
void PrintMemoryInfo(HANDLE hProcess) {
    PROCESS_MEMORY_COUNTERS pmc;
    if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc))) {
        printf("Working Set: %lu KB\n", pmc.WorkingSetSize / 1024);
        printf("Page File Usage: %lu KB\n", pmc.PagefileUsage / 1024);
    }
}
```

---

## 🎯 **Next Steps**

### **Beginner Level:**
1. ✅ Complete basic injection demo
2. ⭐ Modify target process
3. ⭐ Add simple DLL functionality
4. ⭐ Understand error codes

### **Intermediate Level:**
1. ⭐⭐ Implement manual DLL mapping
2. ⭐⭐ Add API hooking
3. ⭐⭐ Create process scanner
4. ⭐⭐ Handle different architectures (x86/x64)

### **Advanced Level:**
1. ⭐⭐⭐ Reflective DLL loading
2. ⭐⭐⭐ Direct syscalls
3. ⭐⭐⭐ Anti-debugging techniques
4. ⭐⭐⭐ Kernel-mode injection

---

## 📚 **Additional Resources**

### **Documentation:**
- [Microsoft Process and Thread Reference](https://docs.microsoft.com/en-us/windows/win32/procthread/)
- [PE Format Specification](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format)

### **Tools:**
- [Process Hacker](https://processhacker.sourceforge.io/)
- [API Monitor](http://www.rohitab.com/apimonitor)
- [CFF Explorer](https://ntcore.com/?page_id=388)

### **Practice Platforms:**
- VirtualBox/VMware (isolated environment)
- Windows Sandbox
- Docker Windows containers

---

*🔒 Remember: Always practice in authorized environments only!*
