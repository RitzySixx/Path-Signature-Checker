# Ritzy's Path Scanner v1.0.5

A Windows application that extracts file paths from text files and verifies their digital signatures with comprehensive security analysis.

## ✨ Features

- **Smart Path Extraction** - Automatically finds file paths in ANY text content using regex
- **Comprehensive Signature Verification** - Checks Authenticode & Catalog signatures  
- **Priority-Based Results** - Unsigned/malicious files shown first
- **Dark Mode Interface** - Modern UI with real-time search & filtering
- **Export to CSV** - Save results for further analysis
- **Drag & Drop Support** - Simply drop .txt files onto the app

## 🚀 Quick Start

1. **Run as Administrator** (required for signature verification)
2. **Drop .txt files** onto the app OR place them in the same directory
3. **Results appear automatically** - sorted by security priority

## 📊 How Path Detection Works

The app uses regex pattern `[A-Za-z]:\\[^\\s<>:"|?*\\r\\n]*\\.[A-Za-z0-9]+` to extract paths from ANY text content:

```
✅ Detects: C:\Windows\System32\notepad.exe
✅ Detects: D:\Program Files\MyApp\app.exe  
✅ Detects: E:\malware\suspicious.dll
✅ Works with: Log files, reports, lists, mixed content
```

## 🔍 Signature Status Categories

| Priority | Status | Description |
|----------|--------|-------------|
| 🔴 **HIGH** | NotSigned | No digital signature |
| 🔴 **HIGH** | Invalid/Fake Signature | Signature verification failed |
| 🟡 **MED** | Expired Certificate | Valid signature, expired cert |
| 🟢 **LOW** | Valid (Authenticode) | Properly signed file |

*30+ signature statuses supported*

## 💻 System Requirements

- Windows 7+ 
- **Administrator privileges required**
- Visual C++ Runtime (usually pre-installed)

## 🛠️ Compilation

```bash
# Visual Studio
cl.exe main.cpp /link wintrust.lib comctl32.lib shlwapi.lib shell32.lib

# MinGW  
g++ -o RitzysPathScanner.exe main.cpp -lwintrust -lcomctl32 -lshlwapi -lshell32 -mwindows
```

## 🎯 Use Cases

- **Malware Analysis** - Verify signatures of suspicious files
- **System Auditing** - Check signature status of system files  
- **Log Analysis** - Extract and verify paths from security logs
- **Compliance Checking** - Ensure all executables are properly signed

## 🔒 Why Administrator Rights?

Required for:
- Accessing system files for signature verification
- Catalog signature validation (Windows system files)
- Certificate chain validation APIs
- Accurate security status reporting

## 📁 Usage Examples

**Method 1 - Auto Discovery:**
```
1. Place .txt files in same directory as exe
2. Run as admin - auto-processes all .txt files
```

**Method 2 - Drag & Drop:**
```  
1. Run as admin
2. Drag any .txt file onto window
3. Processing starts automatically
```

## 🎨 Interface Features

- **Real-time Search** - Filter results as you type
- **Context Menu** - Right-click to copy names/paths/signatures  
- **Column Sorting** - Click headers to sort by any column
- **Progress Tracking** - Real-time progress with timing info
- **CSV Export** - Save filtered results

## 🐛 Troubleshooting

**"Admin Required" popup?** → Right-click exe → "Run as administrator"

**No paths found?** → Ensure text contains valid Windows paths (C:\path\file.exe)

**Slow performance?** → Large file counts (1000+) take time for thorough verification

---

**Made by RitzySix** | For cybersecurity professionals & system administrators
