# DLL Injection - Visual Learning Guide

🎨 **Hướng dẫn học DLL Injection bằng hình ảnh và sơ đồ trực quan**

---

## 🖼️ **1. Tổng Quan Kiến Trúc**

### **Process Memory Layout:**
```
┌─────────────────────────────────────────────────────────────┐
│                    Windows Process Memory                    │
├─────────────────────────────────────────────────────────────┤
│  0x7FFFFFFF │ Kernel Space (System)                         │
├─────────────────────────────────────────────────────────────┤
│  0x7FFEFFFF │ User Space                                    │
│             │ ┌─────────────────────────────────────────┐   │
│             │ │ Stack (grows down)                      │   │
│             │ │ ┌─────────────────────────────────────┐ │   │
│             │ │ │ Local variables                     │ │   │
│             │ │ │ Function parameters                 │ │   │
│             │ │ └─────────────────────────────────────┘ │   │
│             │ └─────────────────────────────────────────┘   │
│             │                                               │
│             │ ┌─────────────────────────────────────────┐   │
│             │ │ Heap (grows up)                         │   │
│             │ │ ┌─────────────────────────────────────┐ │   │
│             │ │ │ Dynamic allocations                 │ │   │
│             │ │ │ malloc(), new                       │ │   │
│             │ │ └─────────────────────────────────────┘ │   │
│             │ └─────────────────────────────────────────┘   │
│             │                                               │
│             │ ┌─────────────────────────────────────────┐   │
│             │ │ DLL Space                               │   │
│             │ │ ┌─────────────────────────────────────┐ │   │
│             │ │ │ kernel32.dll                        │ │   │
│             │ │ │ user32.dll                          │ │   │
│             │ │ │ ntdll.dll                           │ │   │
│             │ │ │ test_dll.dll ←── INJECTED DLL       │ │   │
│             │ │ └─────────────────────────────────────┘ │   │
│             │ └─────────────────────────────────────────┘   │
│             │                                               │
│             │ ┌─────────────────────────────────────────┐   │
│             │ │ Code Section                            │   │
│             │ │ ┌─────────────────────────────────────┐ │   │
│             │ │ │ main()                              │ │   │
│             │ │ │ WinMain()                           │ │   │
│             │ │ │ Program executable code             │ │   │
│             │ │ └─────────────────────────────────────┘ │   │
│             │ └─────────────────────────────────────────┘   │
│  0x00400000 │                                               │
└─────────────────────────────────────────────────────────────┘
```

---

## 🔄 **2. DLL Injection Flow Diagram**

### **Classic CreateRemoteThread Method:**
```
┌─────────────────┐    Step 1: Find Target    ┌─────────────────┐
│   Injector      │ ──────────────────────────▶│  Target Process │
│   Process       │         (PID: 1234)        │   (notepad.exe) │
│                 │                             │                 │
│ ┌─────────────┐ │                             │ ┌─────────────┐ │
│ │injector.exe │ │                             │ │notepad.exe  │ │
│ └─────────────┘ │                             │ └─────────────┘ │
└─────────────────┘                             └─────────────────┘
        │                                                │
        │ Step 2: OpenProcess()                         │
        │ ──────────────────────────────────────────────▶│
        │                                                │
        │ Step 3: VirtualAllocEx()                       │
        │ ──────────────────────────────────────────────▶│
        │                                                │ ┌─────────────┐
        │                                                │ │ Allocated   │
        │                                                │ │ Memory      │
        │                                                │ │ 0x1FF70000  │
        │                                                │ └─────────────┘
        │ Step 4: WriteProcessMemory()                   │
        │ ──────────────────────────────────────────────▶│
        │ "C:\path\to\test_dll.dll"                      │ ┌─────────────┐
        │                                                │ │"C:\path\to\ │
        │                                                │ │test_dll.dll"│
        │                                                │ └─────────────┘
        │ Step 5: CreateRemoteThread()                   │
        │ ──────────────────────────────────────────────▶│
        │ Thread: LoadLibraryA                           │ ┌─────────────┐
        │ Param:  0x1FF70000                             │ │ New Thread  │
        │                                                │ │ LoadLibraryA│
        │                                                │ │ (DLL path)  │
        │                                                │ └─────────────┘
        │                                                │        │
        │                                                │        ▼
        │                                                │ ┌─────────────┐
        │                                                │ │test_dll.dll │
        │                                                │ │   LOADED    │
        │                                                │ └─────────────┘
```

---

## 🧩 **3. Code Structure Visualization**

### **Injector Program Flow:**
```
main()
│
├── Display Banner
│   └── "=== DLL Injection Demo ==="
│
├── Create SimpleDllInjector Object
│   └── injector = new SimpleDllInjector()
│
├── Set Target Parameters
│   ├── targetProcess = "notepad.exe"
│   └── dllPath = "C:\path\to\test_dll.dll"
│
├── Call InjectDLL()
│   │
│   ├── FindProcessByName()
│   │   ├── CreateToolhelp32Snapshot()
│   │   ├── Process32FirstW()
│   │   ├── Loop: Process32NextW()
│   │   │   └── Compare process names
│   │   └── Return PID
│   │
│   ├── OpenProcess()
│   │   └── Get process handle
│   │
│   ├── VirtualAllocEx()
│   │   └── Allocate memory for DLL path
│   │
│   ├── WriteProcessMemory()
│   │   └── Write DLL path to allocated memory
│   │
│   ├── GetProcAddress()
│   │   └── Get LoadLibraryA address
│   │
│   ├── CreateRemoteThread()
│   │   ├── Thread function: LoadLibraryA
│   │   └── Parameter: DLL path address
│   │
│   └── WaitForSingleObject()
│       └── Wait for injection completion
│
└── Display Results
    ├── Success: "Injection successful!"
    └── Failure: "Injection failed!"
```

### **DLL Structure Flow:**
```
test_dll.dll
│
├── DllMain()
│   │
│   ├── DLL_PROCESS_ATTACH
│   │   ├── Get Process Information
│   │   │   ├── GetCurrentProcessId()
│   │   │   ├── GetCurrentThreadId()
│   │   │   └── GetModuleFileNameA()
│   │   │
│   │   ├── Create Log File
│   │   │   ├── Open "C:\temp\injection_log.txt"
│   │   │   ├── Write process info
│   │   │   └── Close file
│   │   │
│   │   └── Optional: MessageBox()
│   │
│   ├── DLL_THREAD_ATTACH
│   │   └── (Handle thread creation)
│   │
│   ├── DLL_THREAD_DETACH  
│   │   └── (Handle thread destruction)
│   │
│   └── DLL_PROCESS_DETACH
│       └── (Cleanup when DLL unloads)
│
└── TestFunction() [Exported]
    └── (Optional test function)
```

---

## 🎭 **4. Memory State Transitions**

### **Before Injection:**
```
Notepad Process Memory:
┌─────────────────────────────────────┐
│ 0x7FFFFFFF │ Kernel Space            │
├─────────────────────────────────────┤
│ 0x7FFE0000 │ System DLLs             │
│            │ ┌─────────────────────┐ │
│            │ │ ntdll.dll           │ │
│            │ │ kernel32.dll        │ │
│            │ │ user32.dll          │ │
│            │ │ gdi32.dll           │ │
│            │ └─────────────────────┘ │
├─────────────────────────────────────┤
│ 0x10000000 │ Application Code        │
│            │ ┌─────────────────────┐ │
│            │ │ notepad.exe         │ │
│            │ │ - WinMain()         │ │
│            │ │ - Message loop      │ │
│            │ │ - File operations   │ │
│            │ └─────────────────────┘ │
└─────────────────────────────────────┘
```

### **During Injection:**
```
Notepad Process Memory:
┌─────────────────────────────────────┐
│ 0x7FFFFFFF │ Kernel Space            │
├─────────────────────────────────────┤
│ 0x7FFE0000 │ System DLLs             │
│            │ ┌─────────────────────┐ │
│            │ │ ntdll.dll           │ │
│            │ │ kernel32.dll        │ │
│            │ │ user32.dll          │ │
│            │ │ gdi32.dll           │ │
│            │ └─────────────────────┘ │
├─────────────────────────────────────┤
│ 0x1FF70000 │ Injected Memory ←──────│ VirtualAllocEx()
│            │ ┌─────────────────────┐ │
│            │ │"C:\path\to\         │ │ WriteProcessMemory()
│            │ │ test_dll.dll"       │ │
│            │ └─────────────────────┘ │
├─────────────────────────────────────┤
│ 0x10000000 │ Application Code        │
│            │ ┌─────────────────────┐ │
│            │ │ notepad.exe         │ │
│            │ │ - WinMain()         │ │
│            │ │ - Message loop      │ │
│            │ │ - File operations   │ │
│            │ │                     │ │
│            │ │ + Remote Thread ←───│ CreateRemoteThread()
│            │ │   LoadLibraryA()    │ │
│            │ └─────────────────────┘ │
└─────────────────────────────────────┘
```

### **After Successful Injection:**
```
Notepad Process Memory:
┌─────────────────────────────────────┐
│ 0x7FFFFFFF │ Kernel Space            │
├─────────────────────────────────────┤
│ 0x7FFE0000 │ System DLLs             │
│            │ ┌─────────────────────┐ │
│            │ │ ntdll.dll           │ │
│            │ │ kernel32.dll        │ │
│            │ │ user32.dll          │ │
│            │ │ gdi32.dll           │ │
│            │ └─────────────────────┘ │
├─────────────────────────────────────┤
│ 0x18000000 │ Injected DLL ←─────────│ LoadLibraryA() result
│            │ ┌─────────────────────┐ │
│            │ │ test_dll.dll        │ │
│            │ │ - DllMain()         │ │
│            │ │ - TestFunction()    │ │
│            │ │ - Log creation      │ │
│            │ └─────────────────────┘ │
├─────────────────────────────────────┤
│ 0x1FF70000 │ DLL Path (can free)     │
│            │ ┌─────────────────────┐ │
│            │ │"C:\path\to\         │ │
│            │ │ test_dll.dll"       │ │
│            │ └─────────────────────┘ │
├─────────────────────────────────────┤
│ 0x10000000 │ Application Code        │
│            │ ┌─────────────────────┐ │
│            │ │ notepad.exe         │ │
│            │ │ - WinMain()         │ │
│            │ │ - Message loop      │ │
│            │ │ - File operations   │ │
│            │ └─────────────────────┘ │
└─────────────────────────────────────┘
```

---

## 🔍 **5. API Call Sequence Diagram**

```
Injector Process                    Target Process                  Windows Kernel
      │                                   │                               │
      │ CreateToolhelp32Snapshot()        │                               │
      ├──────────────────────────────────────────────────────────────────▶│
      │                                   │                               │
      │ Process32FirstW()                 │                               │
      ├──────────────────────────────────────────────────────────────────▶│
      │                                   │                               │
      │ Process32NextW() (loop)           │                               │
      ├──────────────────────────────────────────────────────────────────▶│
      │                                   │                               │
      │ OpenProcess(PID)                  │                               │
      ├──────────────────────────────────────────────────────────────────▶│
      │                                   │ ◄─── Process Handle ──────────┤
      │                                   │                               │
      │ VirtualAllocEx()                  │                               │
      ├──────────────────────────────────▶│ ──────────────────────────────▶│
      │                                   │ ◄─── Memory Address ──────────┤
      │ ◄─────────────────────────────────┤                               │
      │                                   │                               │
      │ WriteProcessMemory()              │                               │
      ├──────────────────────────────────▶│ ──────────────────────────────▶│
      │ (DLL Path String)                 │                               │
      │                                   │                               │
      │ GetModuleHandleA("kernel32")      │                               │
      ├──────────────────────────────────────────────────────────────────▶│
      │                                   │                               │
      │ GetProcAddress("LoadLibraryA")    │                               │
      ├──────────────────────────────────────────────────────────────────▶│
      │                                   │                               │
      │ CreateRemoteThread()              │                               │
      ├──────────────────────────────────▶│ ──────────────────────────────▶│
      │ (LoadLibraryA, DLL Path)          │                               │
      │                                   │                               │
      │                                   │ ┌─── New Thread ─────┐       │
      │                                   │ │                    │       │
      │                                   │ │ LoadLibraryA()     │       │
      │                                   │ │ ├─ Open DLL file   │       │
      │                                   │ │ ├─ Map sections    │ ──────▶│
      │                                   │ │ ├─ Fix imports     │       │
      │                                   │ │ ├─ Call DllMain()  │       │
      │                                   │ │ └─ Return handle   │       │
      │                                   │ └────────────────────┘       │
      │                                   │                               │
      │ WaitForSingleObject()             │                               │
      ├──────────────────────────────────▶│                               │
      │ ◄─── Thread Exit Code ────────────┤                               │
      │                                   │                               │
```

---

## 📊 **6. Data Flow Visualization**

### **String Data Flow:**
```
Injector Process Memory           Target Process Memory
┌─────────────────────────┐      ┌─────────────────────────┐
│ std::string dllPath     │      │                         │
│ "C:\path\to\test.dll"   │      │                         │
│                         │      │                         │
│ [Address: 0x7FF01234]   │ ──── │ [Address: 0x1FF70000]   │
│                         │ Copy │ "C:\path\to\test.dll"   │
│                         │  ──▶ │                         │
│                         │      │ ◄─ LoadLibraryA reads  │
│                         │      │    this string          │
└─────────────────────────┘      └─────────────────────────┘
```

### **Handle Flow:**
```
OpenProcess() ──────────────────▶ Process Handle (HANDLE)
                                          │
                                          ▼
VirtualAllocEx() ──────────────▶ Memory Address (LPVOID)
                                          │
                                          ▼
WriteProcessMemory() ──────────▶ Success/Bytes Written
                                          │
                                          ▼
CreateRemoteThread() ──────────▶ Thread Handle (HANDLE)
                                          │
                                          ▼
WaitForSingleObject() ─────────▶ Thread Exit Code (DWORD)
```

---

## 🎯 **7. Error Flow Diagram**

### **Common Error Paths:**
```
OpenProcess()
    │
    ├─ SUCCESS ──────────────────────────▶ Continue
    │
    └─ FAILURE
        ├─ ERROR_ACCESS_DENIED (5)
        │   └─ Cause: Insufficient privileges
        │       └─ Solution: Run as Administrator
        │
        ├─ ERROR_INVALID_PARAMETER (87)
        │   └─ Cause: Invalid PID
        │       └─ Solution: Verify process exists
        │
        └─ ERROR_FILE_NOT_FOUND (2)
            └─ Cause: Process terminated
                └─ Solution: Restart target process

VirtualAllocEx()
    │
    ├─ SUCCESS ──────────────────────────▶ Continue
    │
    └─ FAILURE
        ├─ ERROR_NOT_ENOUGH_MEMORY (8)
        │   └─ Cause: Insufficient memory
        │       └─ Solution: Reduce allocation size
        │
        └─ ERROR_INVALID_HANDLE (6)
            └─ Cause: Bad process handle
                └─ Solution: Check OpenProcess() result

CreateRemoteThread()
    │
    ├─ SUCCESS ──────────────────────────▶ Continue
    │
    └─ FAILURE
        ├─ ERROR_ACCESS_DENIED (5)
        │   └─ Cause: Process protection
        │       └─ Solution: Choose different target
        │
        └─ ERROR_NOT_ENOUGH_MEMORY (8)
            └─ Cause: Stack allocation failed
                └─ Solution: Increase stack size
```

---

## 🛠️ **8. Build Process Visualization**

### **Compilation Flow:**
```
Source Files                    Compilation                 Output Files
┌─────────────────┐            ┌─────────────────┐         ┌─────────────────┐
│                 │            │                 │         │                 │
│ test_dll.cpp    │ ────────▶  │ cl.exe /LD      │ ─────▶  │ test_dll.dll    │
│ - DllMain()     │            │ (Link DLL)      │         │ - PE Format     │
│ - TestFunction()│            │                 │         │ - Export table  │
│                 │            │                 │         │ - Import table  │
└─────────────────┘            └─────────────────┘         └─────────────────┘
                                        │
┌─────────────────┐                     │                  ┌─────────────────┐
│                 │                     │                  │                 │
│simple_dll_inject│ ────────────────────┘ ──────────────▶  │ injector.exe    │
│.cpp             │                                        │ - PE Format     │
│ - main()        │                                        │ - Import table  │
│ - InjectDLL()   │                                        │ - Resources     │
│                 │                                        │                 │
└─────────────────┘                                        └─────────────────┘
```

### **Runtime Dependencies:**
```
injector.exe
    │
    ├─ Depends on:
    │   ├─ kernel32.dll (OpenProcess, VirtualAllocEx, etc.)
    │   ├─ advapi32.dll (Process enumeration)
    │   └─ user32.dll (Console output)
    │
    └─ Loads:
        └─ test_dll.dll (into target process)
            │
            └─ Depends on:
                ├─ kernel32.dll (GetCurrentProcessId, etc.)
                └─ user32.dll (MessageBox, if used)
```

---

## 🔄 **9. Process State Machine**

### **Target Process States:**
```
┌─────────────────┐
│   NOT_FOUND     │ ◄── FindProcessByName() fails
└─────────────────┘
         │
         │ Process found
         ▼
┌─────────────────┐
│     FOUND       │ ◄── Process exists in system
└─────────────────┘
         │
         │ OpenProcess() success
         ▼
┌─────────────────┐
│    OPENED       │ ◄── Have process handle
└─────────────────┘
         │
         │ Memory allocated
         ▼
┌─────────────────┐
│   ALLOCATED     │ ◄── VirtualAllocEx() success
└─────────────────┘
         │
         │ DLL path written
         ▼
┌─────────────────┐
│    WRITTEN      │ ◄── WriteProcessMemory() success
└─────────────────┘
         │
         │ Remote thread created
         ▼
┌─────────────────┐
│   INJECTING     │ ◄── CreateRemoteThread() success
└─────────────────┘
         │
         │ LoadLibraryA completes
         ▼
┌─────────────────┐
│   INJECTED      │ ◄── DLL successfully loaded
└─────────────────┘
```

---

## 📈 **10. Performance Visualization**

### **Injection Time Breakdown:**
```
Total Injection Time: ~50-200ms
┌────────────────────────────────────────────────────────────┐
│ Process Discovery    │████                              5ms │
├────────────────────────────────────────────────────────────┤
│ OpenProcess         │██                                2ms │
├────────────────────────────────────────────────────────────┤
│ Memory Allocation   │████                              5ms │
├────────────────────────────────────────────────────────────┤
│ Memory Write        │██                                3ms │
├────────────────────────────────────────────────────────────┤
│ Thread Creation     │████                              8ms │
├────────────────────────────────────────────────────────────┤
│ DLL Loading         │████████████████████████████     100ms│
├────────────────────────────────────────────────────────────┤
│ DllMain Execution   │████████                         15ms │
└────────────────────────────────────────────────────────────┘
```

### **Memory Usage:**
```
Process Memory Growth After Injection:
┌────────────────────────────────────────────────────────────┐
│ Before Injection │████████████                        12MB │
├────────────────────────────────────────────────────────────┤
│ After Injection  │██████████████████                  18MB │
├────────────────────────────────────────────────────────────┤
│ DLL Size         │████                               285KB │
├────────────────────────────────────────────────────────────┤
│ DLL Dependencies │████████                           512KB │
└────────────────────────────────────────────────────────────┘
```

---

## 🎨 **11. Interactive Learning Exercises**

### **Exercise 1: Visual Process Monitoring**
```powershell
# Monitor trong PowerShell
while ($true) {
    Clear-Host
    Write-Host "=== Process Monitor ===" -ForegroundColor Green
    Get-Process notepad | Format-Table Id,ProcessName,WorkingSet,Modules
    Start-Sleep 2
}
```

### **Exercise 2: Memory Visualization**
```cpp
void PrintMemoryMap(HANDLE hProcess) {
    MEMORY_BASIC_INFORMATION mbi;
    LPVOID address = 0;
    
    printf("Memory Map:\n");
    printf("Address           Size      State     Protect\n");
    printf("──────────────────────────────────────────────\n");
    
    while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi))) {
        printf("0x%016llX %8lluKB %s %s\n", 
               (ULONGLONG)mbi.BaseAddress,
               mbi.RegionSize / 1024,
               (mbi.State == MEM_COMMIT) ? "COMMIT" : "RESERVE",
               GetProtectionString(mbi.Protect));
        
        address = (LPBYTE)mbi.BaseAddress + mbi.RegionSize;
    }
}
```

---

*🎓 Học tập hiệu quả nhất khi kết hợp lý thuyết với thực hành hands-on!*
