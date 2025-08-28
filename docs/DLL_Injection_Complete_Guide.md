# DLL Injection - Hướng dẫn Toàn Diện cho Người Mới

📚 **Tài liệu này giải thích DLL Injection từ cơ bản đến nâng cao với ví dụ thực tế**

---

## 🎯 **DLL Injection là gì?**

**DLL Injection** là kỹ thuật "tiêm" một thư viện động (DLL) vào tiến trình đang chạy của ứng dụng khác.

### 🖼️ **Hình ảnh minh họa:**

```
┌─────────────────┐     Inject     ┌─────────────────┐
│   Injector      │ ───────────────▶│  Target Process │
│   Process       │     DLL.dll     │   (notepad.exe) │
│                 │                 │                 │
│ ┌─────────────┐ │                 │ ┌─────────────┐ │
│ │ injector.exe│ │                 │ │ notepad.exe │ │
│ └─────────────┘ │                 │ └─────────────┘ │
│                 │                 │ ┌─────────────┐ │
│                 │                 │ │ test_dll.dll│ │ ← Injected!
│                 │                 │ └─────────────┘ │
└─────────────────┘                 └─────────────────┘
```

---

## 🔍 **Tại sao cần DLL Injection?**

### ✅ **Ứng dụng hợp pháp:**
- **Debugging tools** (OllyDbg, x64dbg)
- **Performance monitoring** (Process Monitor)
- **Security testing** (Penetration testing)
- **Game modding** (Cheat engines)
- **API hooking** (Detours library)

### ⚠️ **Rủi ro:**
- **Malware injection**
- **Privilege escalation**
- **Data theft**
- **Process manipulation**

---

## 🧩 **Các Phương Pháp DLL Injection**

### 1. **Classic DLL Injection (SetWindowsHookEx)**
```
Application ──► Windows Hook ──► DLL loads in all processes
```

### 2. **CreateRemoteThread + LoadLibrary**
```
Injector ──► Allocate Memory ──► Write DLL Path ──► CreateRemoteThread(LoadLibrary)
```

### 3. **Manual DLL Mapping**
```
Injector ──► Read DLL ──► Map Sections ──► Fix Imports ──► Execute
```

### 4. **Reflective DLL Loading**
```
Injector ──► Encrypted DLL ──► Self-Loading Code ──► In-Memory Execution
```

---

## 🛠️ **Phân Tích Demo Code Từng Bước**

### **Bước 1: Tìm Target Process**

```cpp
DWORD FindProcessByName(const std::wstring& processName) {
    // Tạo snapshot của tất cả processes
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    
    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(PROCESSENTRY32W);
    
    if (Process32FirstW(hSnapshot, &pe)) {
        do {
            // So sánh tên process
            if (_wcsicmp(pe.szExeFile, processName.c_str()) == 0) {
                return pe.th32ProcessID;  // Trả về PID
            }
        } while (Process32NextW(hSnapshot, &pe));
    }
    
    return 0; // Không tìm thấy
}
```

**🎯 Giải thích:**
- `CreateToolhelp32Snapshot`: Chụp "ảnh" tất cả processes
- `Process32FirstW/NextW`: Duyệt qua từng process
- `_wcsicmp`: So sánh tên process (không phân biệt hoa thường)

### **Bước 2: Mở Target Process**

```cpp
// Mở process với quyền PROCESS_ALL_ACCESS
HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
```

**🎯 Giải thích:**
- `PROCESS_ALL_ACCESS`: Quyền truy cập toàn bộ
- `FALSE`: Không kế thừa handle
- `processId`: PID của target process

### **Bước 3: Cấp Phát Memory trong Target Process**

```cpp
// Cấp phát memory để chứa đường dẫn DLL
LPVOID pDllPath = VirtualAllocEx(
    hProcess,           // Target process handle
    NULL,              // Địa chỉ (NULL = tự động chọn)
    dllPathSize,       // Kích thước cần cấp
    MEM_COMMIT | MEM_RESERVE,  // Loại memory
    PAGE_READWRITE     // Quyền đọc/ghi
);
```

**🎯 Memory Layout:**
```
Target Process Memory Space:
┌─────────────────────────────────┐
│  Program Code                   │
├─────────────────────────────────┤
│  Stack                          │  
├─────────────────────────────────┤
│  Heap                           │
├─────────────────────────────────┤
│  [Allocated for DLL path] ←──── │  VirtualAllocEx cấp phát ở đây
└─────────────────────────────────┘
```

### **Bước 4: Ghi DLL Path vào Target Process**

```cpp
// Ghi đường dẫn DLL vào memory vừa cấp phát
WriteProcessMemory(
    hProcess,           // Target process
    pDllPath,          // Địa chỉ đích (trong target)
    dllPath.c_str(),   // Dữ liệu nguồn (trong injector)
    dllPathSize,       // Số bytes cần ghi
    &bytesWritten      // Số bytes đã ghi thực tế
);
```

**🎯 Memory Transfer:**
```
Injector Process          Target Process
┌─────────────────┐      ┌─────────────────┐
│ dllPath         │      │                 │
│ "C:\test.dll"   │ ────▶│ pDllPath        │
│                 │      │ "C:\test.dll"   │
└─────────────────┘      └─────────────────┘
    Source Memory           Destination Memory
```

### **Bước 5: Lấy Địa Chỉ LoadLibraryA**

```cpp
// Lấy handle của kernel32.dll
HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");

// Lấy địa chỉ hàm LoadLibraryA
LPTHREAD_START_ROUTINE pLoadLibrary = 
    (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryA");
```

**🎯 Giải thích:**
- `kernel32.dll` có trong mọi Windows process
- `LoadLibraryA` là hàm Windows API để load DLL
- Địa chỉ này giống nhau trong tất cả processes

### **Bước 6: Tạo Remote Thread**

```cpp
// Tạo thread trong target process để thực thi LoadLibraryA
HANDLE hRemoteThread = CreateRemoteThread(
    hProcess,        // Target process
    NULL,           // Security attributes
    0,              // Stack size (default)
    pLoadLibrary,   // Thread function (LoadLibraryA)
    pDllPath,       // Parameter (đường dẫn DLL)
    0,              // Creation flags
    NULL            // Thread ID
);
```

**🎯 Execution Flow:**
```
Target Process:
┌─────────────────────────────────┐
│ Main Thread                     │
│ ┌─────────────────────────────┐ │
│ │ notepad.exe execution       │ │
│ └─────────────────────────────┘ │
│                                 │
│ New Remote Thread ←─────────────┼── CreateRemoteThread
│ ┌─────────────────────────────┐ │
│ │ LoadLibraryA("C:\test.dll") │ │
│ └─────────────────────────────┘ │
└─────────────────────────────────┘
```

---

## 🔬 **Phân Tích Test DLL**

### **DllMain Function:**

```cpp
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:  // DLL được load vào process
        {
            // Tạo log file để chứng minh injection thành công
            std::ofstream logFile("C:\\temp\\injection_log.txt", std::ios::app);
            if (logFile.is_open()) {
                logFile << "DLL injected successfully into process!" << std::endl;
                logFile << "Process ID: " << GetCurrentProcessId() << std::endl;
                // ...
            }
        }
        break;
    // ... các cases khác
    }
    return TRUE;
}
```

**🎯 DLL Lifecycle:**
```
LoadLibrary("test.dll")
        ↓
    DllMain called with DLL_PROCESS_ATTACH
        ↓
    DLL code executes in target process
        ↓
    Log file created in C:\temp\
        ↓
    DLL remains loaded until process exits
```

---

## 📊 **So Sánh Các Kỹ Thuật Injection**

| Kỹ Thuật | Độ Khó | Stealth | Detection | Sử Dụng |
|----------|---------|---------|-----------|---------|
| **SetWindowsHookEx** | ⭐⭐ | ⭐ | Dễ phát hiện | Global hooks |
| **CreateRemoteThread** | ⭐⭐⭐ | ⭐⭐ | Trung bình | Targeted injection |
| **Manual Mapping** | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | Khó phát hiện | Advanced malware |
| **Reflective Loading** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | Rất khó phát hiện | APTs, Red teams |

---

## 🛡️ **Defensive Measures**

### **1. Process Protection:**
```cpp
// Protected Process Light (PPL)
CreateProcess(..., EXTENDED_STARTUPINFO_PRESENT, ...);
```

### **2. Code Integrity:**
```cpp
// Control Flow Guard (CFG)
#pragma comment(linker, "/guard:cf")
```

### **3. ASLR (Address Space Layout Randomization):**
```cpp
// Randomize memory layout
#pragma comment(linker, "/DYNAMICBASE")
```

### **4. DEP (Data Execution Prevention):**
```cpp
// Prevent code execution from data pages
SetProcessDEPPolicy(PROCESS_DEP_ENABLE);
```

---

## 🔍 **Phát Hiện DLL Injection**

### **1. Process Monitor:**
- Monitor process creation/modification
- Detect unusual DLL loads

### **2. Event Tracing for Windows (ETW):**
```cpp
// Monitor LoadImage events
EVENT_TRACE_PROPERTIES trace;
StartTrace(&sessionHandle, L"MyTrace", &trace);
```

### **3. API Hooking Detection:**
```cpp
// Check for inline hooks
BYTE originalBytes[5];
ReadProcessMemory(hProcess, pFunction, originalBytes, 5, NULL);
// Compare with known good bytes
```

---

## 🧪 **Lab Exercises**

### **Exercise 1: Basic Injection**
1. Build demo project
2. Inject into notepad.exe
3. Verify log file creation

### **Exercise 2: Process Discovery**
1. Modify injector để list tất cả processes
2. Cho phép user chọn target

### **Exercise 3: Advanced Injection**
1. Implement manual DLL mapping
2. Bypass basic AV detection

### **Exercise 4: Detection Evasion**
1. Use direct syscalls
2. Encrypt DLL payload

---

## 🚨 **Ethical Guidelines**

### ✅ **Acceptable Use:**
- Personal learning và research
- Authorized penetration testing
- Security tool development
- Academic research

### ❌ **Unacceptable Use:**
- Attacking systems without permission
- Malware development
- Data theft
- Privacy violations

---

## 📚 **Tài Liệu Tham Khảo**

### **Books:**
- "Windows Internals" by Mark Russinovich
- "The Rootkit Arsenal" by Bill Blunden
- "Practical Malware Analysis" by Michael Sikorski

### **Online Resources:**
- Microsoft Documentation (MSDN)
- MITRE ATT&CK Framework
- GitHub security research repositories

### **Tools:**
- Process Hacker
- API Monitor
- Detours Library
- WinAPIOverride

---

## 🎓 **Kiến Thức Cần Có**

### **Prerequisites:**
- ⭐⭐⭐ C/C++ Programming
- ⭐⭐⭐ Windows API
- ⭐⭐ Assembly Language
- ⭐⭐ PE File Format
- ⭐ Operating System Concepts

### **Advanced Topics:**
- Kernel-mode development
- Anti-debugging techniques
- Code obfuscation
- Exploit development

---

## ⚡ **Quick Reference**

### **Key Windows APIs:**
```cpp
OpenProcess()           // Mở process handle
VirtualAllocEx()        // Cấp phát memory
WriteProcessMemory()    // Ghi memory
CreateRemoteThread()    // Tạo thread
LoadLibraryA()         // Load DLL
GetProcAddress()       // Lấy function address
```

### **Common Error Codes:**
- `ERROR_ACCESS_DENIED (5)`: Không đủ quyền
- `ERROR_INVALID_HANDLE (6)`: Handle không hợp lệ  
- `ERROR_NOT_ENOUGH_MEMORY (8)`: Không đủ memory
- `ERROR_INVALID_PARAMETER (87)`: Parameter sai

---

*📝 Tài liệu này được tạo cho mục đích giáo dục. Sử dụng có trách nhiệm!*
