# Ritzy's Path Scanner v1.0.5

A Windows application that extracts file paths from text files and verifies their digital signatures with comprehensive security analysis.

## ✨ Features

- **Smart Path Extraction** - Automatically finds file paths in ANY text content using regex pattern `[A-Za-z]:\\[^\\s<>:"|?*\\r\\n]*\\.[A-Za-z0-9]+`
- **Comprehensive Signature Verification** - Checks both Authenticode & Catalog signatures with 30+ status types
- **Priority-Based Results** - Unsigned/malicious files shown first with intelligent sorting
- **Dark Mode Interface** - Modern UI with real-time search & filtering
- **Export to CSV** - Save filtered results for further analysis
- **Drag & Drop Support** - Simply drop .txt files onto the app
- **Context Menu** - Right-click to copy file names, paths, or signatures
- **Multi-threaded Scanning** - Non-blocking UI with real-time progress tracking

## 🚀 Quick Start

1. **Run as Administrator** (required for signature verification)
2. **Drop .txt files** onto the app OR place them in the same directory
3. **Results appear automatically** - sorted by security priority

## 📊 Signature Status Categories (30+ Types)

### 🔴 **HIGH PRIORITY** (Shown First)
| Status | Description |
|--------|-------------|
| `NotSigned` | No digital signature found |
| `Invalid/Fake Signature` | Signature verification failed |
| `Tampered/Fake Signature` | File has been modified |
| `Fake/Invalid Certificate` | Certificate is invalid |
| `Corrupted/Fake Signature` | Signature data corrupted |

### 🟡 **MEDIUM PRIORITY**
| Status | Description |
|--------|-------------|
| `Expired Certificate` | Valid signature, expired certificate |
| `Revoked Certificate` | Certificate has been revoked |
| `Untrusted Root Certificate` | Root CA not trusted |
| `Certificate Chain Error` | Certificate chain validation failed |
| `Bad Signature Encoding` | Signature encoding issues |

### 🟢 **LOW PRIORITY** (Shown Last)
| Status | Description |
|--------|-------------|
| `Valid (Authenticode)` | Properly signed with Authenticode |
| `Valid (Catalog)` | Signed via Windows catalog system |

*Full list includes 30+ signature statuses with detailed error codes*

## 🔍 Advanced Signature Verification

The application performs comprehensive signature analysis using:

- **WinVerifyTrust API** - Authenticode signature verification
- **Catalog Signature Checking** - Windows system file validation
- **Certificate Chain Validation** - Full certificate path verification
- **Hash Verification** - File integrity checking
- **Timestamp Validation** - Signature timestamp verification

### Supported Error Codes
```cpp
TRUST_E_NOSIGNATURE, TRUST_E_SUBJECT_NOT_TRUSTED, TRUST_E_EXPLICIT_DISTRUST,
CERT_E_EXPIRED, CERT_E_REVOKED, CERT_E_UNTRUSTEDROOT, CERT_E_CHAINING,
CRYPT_E_BAD_MSG, CRYPT_E_HASH_VALUE, NTE_BAD_SIGNATURE
// + 20 more signature status codes
```

## 💻 System Requirements

- **Windows 7+** (Windows 10/11 recommended)
- **Administrator privileges required**
- Visual C++ Runtime (usually pre-installed)
- **Libraries**: wintrust.lib, comctl32.lib, shlwapi.lib, shell32.lib

## 🛠️ Compilation

### Visual Studio
```bash
cl.exe main.cpp /link wintrust.lib comctl32.lib shlwapi.lib shell32.lib
```

### MinGW
```bash
g++ -o RitzysPathScanner.exe main.cpp -lwintrust -lcomctl32 -lshlwapi -lshell32 -mwindows
```

### Required Headers
```cpp:main.cpp
#include <windows.h>
#include <wintrust.h>
#include <softpub.h>
#include <mscat.h>
#include <commctrl.h>
// + standard C++ libraries
```

## 🎯 Use Cases

- **Malware Analysis** - Verify signatures of suspicious files from logs
- **System Auditing** - Check signature status of system executables
- **Log Analysis** - Extract and verify paths from security/event logs
- **Compliance Checking** - Ensure all executables are properly signed
- **Incident Response** - Quickly verify file authenticity during investigations

## 🔒 Why Administrator Rights?

Required for:
- **System File Access** - Reading protected system files
- **Catalog Signature Validation** - Accessing Windows catalog database
- **Certificate Chain APIs** - Full certificate validation
- **Hash Calculation** - File integrity verification
- **Security Context** - Proper signature verification context

## 📁 Usage Examples

### Method 1 - Auto Discovery
```
1. Place .txt files in same directory as executable
2. Run as administrator
3. Auto-processes all .txt files in directory
```

### Method 2 - Drag & Drop
```
1. Run application as administrator
2. Drag any .txt file onto the window
3. Processing starts automatically
```

### Method 3 - Mixed Content Processing
```
✅ Works with any text containing paths:
- Security logs: "Process C:\Windows\System32\cmd.exe started"
- File lists: "C:\Program Files\App\malware.exe"
- Reports: "Found suspicious file at D:\Temp\virus.dll"
```

## 🎨 Interface Features

- **Real-time Search** - Filter results as you type across all columns
- **Context Menu** - Right-click to copy names/paths/signatures to clipboard
- **Column Sorting** - Click headers to sort by filename, path, or signature status
- **Progress Tracking** - Real-time progress with precise timing (HH:MM:SS.mmm)
- **CSV Export** - Export filtered results with proper escaping
- **Dark Mode UI** - Easy on the eyes with custom dark theme
- **Multi-selection** - Select multiple items for batch operations

## 🚀 Performance Features

- **Multi-threaded Scanning** - Non-blocking UI during file processing
- **Regex Path Extraction** - Efficiently finds paths in any text format
- **Memory Efficient** - Handles large file lists without memory issues
- **Progress Updates** - Real-time feedback during long scans
- **Auto-resize Columns** - Automatically adjusts column widths

## 🐛 Troubleshooting

**"Admin Required" popup?**
→ Right-click executable → "Run as administrator"

**No paths found in text files?**
→ Ensure text contains valid Windows paths (C:\path\file.exe format)

**Slow performance with large files?**
→ Large file counts (1000+) require time for thorough signature verification

**"Access Denied" status?**
→ File may be locked by another process or require higher privileges

**CSV export fails?**
→ Ensure write permissions in application directory

## 📋 Technical Details

### Path Detection Regex
```regex
[A-Za-z]:\\[^\\s<>:"|?*\\r\\n]*\\.[A-Za-z0-9]+
```
- Matches drive letter + colon + backslash
- Excludes invalid path characters
- Requires file extension
- Handles various text formats

### Signature Priority Algorithm
Files are sorted by security risk:
1. **Priority 1-10**: Unsigned/Invalid signatures (highest risk)
2. **Priority 11-25**: Certificate problems (medium risk)  
3. **Priority 26-40**: System/provider errors (low-medium risk)
4. **Priority 41-48**: Valid signatures (lowest risk)

---

**Made by RitzySix** | For cybersecurity professionals & system administrators

*Comprehensive digital signature verification tool for Windows file analysis*
