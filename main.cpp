#include <windows.h>
#include <commctrl.h>
#include <wintrust.h>
#include <softpub.h>
#include <shlwapi.h>
#include <shellapi.h>
#include <mscat.h>
#include <vector>
#include <string>
#include <fstream>
#include <thread>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <filesystem>
#include <regex>
#include <windowsx.h>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "shell32.lib")

// Additional error code definitions for signature verification
#define TRUST_E_NOSIGNATURE ((HRESULT)0x800B0100L)
#define TRUST_E_SUBJECT_NOT_TRUSTED ((HRESULT)0x800B0004L)
#define TRUST_E_EXPLICIT_DISTRUST ((HRESULT)0x800B0111L)
#define TRUST_E_SUBJECT_FORM_UNKNOWN ((HRESULT)0x800B0003L)
#define TRUST_E_PROVIDER_UNKNOWN ((HRESULT)0x800B0001L)
#define TRUST_E_BAD_DIGEST ((HRESULT)0x80096010L)
#define TRUST_E_CERT_SIGNATURE ((HRESULT)0x80096019L)
#define TRUST_E_SYSTEM_ERROR ((HRESULT)0x80096008L)
#define TRUST_E_NO_SIGNER_CERT ((HRESULT)0x80096009L)
#define TRUST_E_COUNTER_SIGNER ((HRESULT)0x8009600AL)
#define TRUST_E_TIME_STAMP ((HRESULT)0x8009600CL)
#define TRUST_E_FINANCIAL_CRITERIA ((HRESULT)0x8009601EL)
#define CERT_E_EXPIRED ((HRESULT)0x800B0101L)
#define CERT_E_REVOKED ((HRESULT)0x800B010CL)
#define CERT_E_UNTRUSTEDROOT ((HRESULT)0x800B0109L)
#define CERT_E_CHAINING ((HRESULT)0x800B010AL)
#define CERT_E_WRONG_USAGE ((HRESULT)0x800B0110L)
#define CERT_E_UNTRUSTEDTESTROOT ((HRESULT)0x800B010DL)
#define CERT_E_VALIDITYPERIODNESTING ((HRESULT)0x800B0102L)
#define CERT_E_CRITICAL ((HRESULT)0x800B0105L)
#define CERT_E_PURPOSE ((HRESULT)0x800B0106L)
#define CERT_E_ISSUERCHAINING ((HRESULT)0x800B0107L)
#define CERT_E_MALFORMED ((HRESULT)0x800B0108L)
#define CRYPT_E_BAD_MSG ((HRESULT)0x80091004L)
#define CRYPT_E_BAD_ENCODE ((HRESULT)0x80091005L)
#define CRYPT_E_BAD_LEN ((HRESULT)0x80091006L)
#define CRYPT_E_INVALID_MSG_TYPE ((HRESULT)0x8009100BL)
#define CRYPT_E_UNEXPECTED_MSG_TYPE ((HRESULT)0x8009100CL)
#define CRYPT_E_AUTH_ATTR_MISSING ((HRESULT)0x80091006L)
#define CRYPT_E_HASH_VALUE ((HRESULT)0x80091007L)
#define NTE_BAD_SIGNATURE ((HRESULT)0x80090006L)


// Control IDs
#define ID_LISTVIEW 1001
#define ID_PROGRESSBAR 1002
#define ID_STATUSBAR 1003
#define ID_SEARCHBOX 1004
#define ID_BUTTON_EXPORT 1005

// Custom messages
#define WM_SCAN_PROGRESS (WM_USER + 1)
#define WM_SCAN_COMPLETE (WM_USER + 2)
#define WM_ADD_ITEM (WM_USER + 3)

// Dark mode colors
#define DARK_BG_COLOR RGB(32, 32, 32)
#define DARK_TEXT_COLOR RGB(255, 255, 255)
#define DARK_GRID_COLOR RGB(64, 64, 64)
#define DARK_HEADER_COLOR RGB(48, 48, 48)
#define DARK_SELECTION_COLOR RGB(0, 120, 215)

struct FileResult {
    std::wstring fileName;
    std::wstring fullPath;
    std::wstring signatureStatus;
    std::wstring signatureDetails;
};

// Add this helper function to get sorting priority
int GetSignaturePriority(const std::wstring& status) {
    // Priority 1: Not signed (highest priority - shown first)
    if (status == L"NotSigned") return 1;

    // Priority 2-5: Fake/Invalid signatures
    if (status == L"Invalid/Fake Signature") return 2;
    if (status == L"Tampered/Fake Signature") return 3;
    if (status == L"Fake/Invalid Certificate") return 4;
    if (status == L"Corrupted/Fake Signature") return 5;

    // Priority 6-10: Bad signature formats/encoding
    if (status == L"Invalid Signature Format") return 6;
    if (status == L"Bad Signature Encoding") return 7;
    if (status == L"Bad Digital Signature") return 8;
    if (status == L"Invalid Message Type") return 9;
    if (status == L"Unexpected Message Type") return 10;

    // Priority 11-15: Certificate problems
    if (status == L"Expired Certificate") return 11;
    if (status == L"Revoked Certificate") return 12;
    if (status == L"Untrusted Root Certificate") return 13;
    if (status == L"Untrusted Test Root") return 14;
    if (status == L"Malformed Certificate") return 15;

    // Priority 16-20: Certificate chain/usage errors
    if (status == L"Certificate Chain Error") return 16;
    if (status == L"Certificate Wrong Usage") return 17;
    if (status == L"Certificate Validity Period Error") return 18;
    if (status == L"Certificate Purpose Error") return 19;
    if (status == L"Certificate Issuer Chain Error") return 20;

    // Priority 21-25: Certificate extensions/constraints
    if (status == L"Critical Certificate Extension") return 21;
    if (status == L"Financial Criteria Not Met") return 22;

    // Priority 26-30: Provider/system errors
    if (status == L"Unknown Signature Provider") return 26;
    if (status == L"System Error During Verification") return 27;
    if (status == L"No Signer Certificate") return 28;

    // Priority 31-35: Timestamp/counter signature errors
    if (status == L"Counter Signer Error") return 31;
    if (status == L"Timestamp Error") return 32;
    if (status == L"Hash Value Mismatch") return 33;

    // Priority 36-40: Trust/distrust
    if (status == L"Distrusted") return 36;

    // Priority 41-45: Generic signature errors
    if (status.find(L"Signature Error") != std::wstring::npos) return 41;

    // Priority 46: Deleted files
    if (status == L"Deleted") return 46;

    // Priority 47-48: Valid signatures (lowest priority - shown last)
    if (status == L"Valid (Catalog)") return 47;
    if (status == L"Valid (Authenticode)") return 48;

    // Priority 49: Any other status
    return 49;
}

class SignatureGrabber {
private:
    HWND hMainWnd, hListView, hProgressBar, hStatusBar, hSearchBox;
    HWND hExportButton;
    std::vector<std::wstring> filePaths;
    std::vector<FileResult> scanResults;
    std::vector<FileResult> filteredResults;
    bool isScanning = false;
    std::chrono::steady_clock::time_point scanStartTime;
    std::wstring draggedFile;
    HBRUSH hDarkBrush;

public:
    static LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
        SignatureGrabber* app = reinterpret_cast<SignatureGrabber*>(GetWindowLongPtr(hwnd, GWLP_USERDATA));

        switch (uMsg) {
        case WM_CONTEXTMENU:
            if (app && (HWND)wParam == app->hListView) {
                app->ShowContextMenu(GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam));
            }
            return 0;

        case WM_COMMAND:
            if (app) {
                switch (LOWORD(wParam)) {
                case ID_SEARCHBOX:
                    if (HIWORD(wParam) == EN_CHANGE) {
                        app->FilterResults();
                    }
                    break;
                case ID_BUTTON_EXPORT:
                    app->ExportResults();
                    break;
                case 2001: // Copy Names
                    app->CopySelectedItems(0);
                    break;
                case 2002: // Copy Paths
                    app->CopySelectedItems(1);
                    break;
                case 2003: // Copy Signatures
                    app->CopySelectedItems(2);
                    break;
                }
            }
            return 0;

        case WM_NOTIFY:
            if (app) return app->HandleNotify((LPNMHDR)lParam);
            return 0;

        case WM_SIZE:
            if (app) app->ResizeControls();
            return 0;

        case WM_CTLCOLORSTATIC:
        case WM_CTLCOLOREDIT:
            if (app) {
                HDC hdc = (HDC)wParam;
                SetTextColor(hdc, DARK_TEXT_COLOR);
                SetBkColor(hdc, DARK_BG_COLOR);
                return (LRESULT)app->hDarkBrush;
            }
            return 0;

        case WM_SCAN_PROGRESS:
            if (app) app->UpdateProgress((int)wParam, (int)lParam);
            return 0;

        case WM_ADD_ITEM:
            if (app) {
                FileResult* result = reinterpret_cast<FileResult*>(wParam);
                app->AddResultToList(*result);
                delete result;
            }
            return 0;

        case WM_SCAN_COMPLETE:
            if (app) app->OnScanComplete((DWORD)wParam);
            return 0;

        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
        }
        return DefWindowProc(hwnd, uMsg, wParam, lParam);
    }

    LRESULT HandleNotify(LPNMHDR pnmh) {
        if (pnmh->hwndFrom == hListView) {
            switch (pnmh->code) {
            case LVN_COLUMNCLICK:
            {
                LPNMLISTVIEW pnmlv = (LPNMLISTVIEW)pnmh;
                SortColumn(pnmlv->iSubItem);
            }
            break;
            case NM_CUSTOMDRAW:
                return HandleCustomDraw((LPNMLVCUSTOMDRAW)pnmh);
            }
        }
        return 0;
    }

    LRESULT HandleCustomDraw(LPNMLVCUSTOMDRAW pcd) {
        switch (pcd->nmcd.dwDrawStage) {
        case CDDS_PREPAINT:
            return CDRF_NOTIFYITEMDRAW;
        case CDDS_ITEMPREPAINT:
            pcd->clrText = DARK_TEXT_COLOR;
            pcd->clrTextBk = DARK_BG_COLOR;
            return CDRF_NEWFONT;
        }
        return CDRF_DODEFAULT;
    }

    void HandleDropFiles(HDROP hDrop) {
        UINT fileCount = DragQueryFileW(hDrop, 0xFFFFFFFF, NULL, 0);
        for (UINT i = 0; i < fileCount; i++) {
            WCHAR filePath[MAX_PATH];
            if (DragQueryFileW(hDrop, i, filePath, MAX_PATH)) {
                std::wstring file(filePath);
                if (file.substr(file.find_last_of(L".") + 1) == L"txt") {
                    draggedFile = file;
                    StartProcessing();
                    break;
                }
            }
        }
        DragFinish(hDrop);
    }

    void ShowContextMenu(int x, int y) {
        int selectedCount = ListView_GetSelectedCount(hListView);
        if (selectedCount == 0) return;

        HMENU hMenu = CreatePopupMenu();
        AppendMenuW(hMenu, MF_STRING, 2001, L"Copy File Names");
        AppendMenuW(hMenu, MF_STRING, 2002, L"Copy Full Paths");
        AppendMenuW(hMenu, MF_STRING, 2003, L"Copy Signatures");

        TrackPopupMenu(hMenu, TPM_RIGHTBUTTON, x, y, 0, hMainWnd, NULL);
        DestroyMenu(hMenu);
    }

    void CopySelectedItems(int column) {
        std::wstring clipboardText;
        int itemIndex = -1;

        while ((itemIndex = ListView_GetNextItem(hListView, itemIndex, LVNI_SELECTED)) != -1) {
            WCHAR buffer[MAX_PATH];
            LVITEMW item = {};
            item.mask = LVIF_TEXT;
            item.iItem = itemIndex;
            item.pszText = buffer;
            item.cchTextMax = MAX_PATH;

            switch (column) {
            case 0: // File names
                item.iSubItem = 0;
                ListView_GetItem(hListView, &item);
                clipboardText += std::wstring(buffer) + L"\r\n";
                break;
            case 1: // Full paths
                item.iSubItem = 1;
                ListView_GetItem(hListView, &item);
                clipboardText += std::wstring(buffer) + L"\r\n";
                break;
            case 2: // Signatures
                item.iSubItem = 2;
                ListView_GetItem(hListView, &item);
                clipboardText += std::wstring(buffer) + L"\r\n";
                break;
            }
        }

        if (!clipboardText.empty()) {
            // Remove last \r\n
            clipboardText = clipboardText.substr(0, clipboardText.length() - 2);

            if (OpenClipboard(hMainWnd)) {
                EmptyClipboard();

                HGLOBAL hClipboardData = GlobalAlloc(GMEM_DDESHARE, (clipboardText.length() + 1) * sizeof(wchar_t));
                if (hClipboardData) {
                    wchar_t* pchData = (wchar_t*)GlobalLock(hClipboardData);
                    wcscpy_s(pchData, clipboardText.length() + 1, clipboardText.c_str());
                    GlobalUnlock(hClipboardData);
                    SetClipboardData(CF_UNICODETEXT, hClipboardData);
                }
                CloseClipboard();
            }
        }
    }

    std::vector<std::wstring> ExtractPathsFromText(const std::wstring& text) {
        std::vector<std::wstring> paths;

        // Regex to match valid file paths: Drive letter + path + extension
        std::wregex pathRegex(L"[A-Za-z]:\\\\[^\\s<>:\"|?*\\r\\n]*\\.[A-Za-z0-9]+");
        std::wsregex_iterator start(text.begin(), text.end(), pathRegex);
        std::wsregex_iterator end;

        for (std::wsregex_iterator i = start; i != end; ++i) {
            std::wsmatch match = *i;
            std::wstring path = match.str();

            // Clean up the path (remove any trailing punctuation that's not part of extension)
            while (!path.empty() && (path.back() == L',' || path.back() == L';' ||
                path.back() == L'.' || path.back() == L')' || path.back() == L']')) {
                path.pop_back();
            }

            if (!path.empty()) {
                paths.push_back(path);
            }
        }

        return paths;
    }

    std::wstring GetDetailedSignatureStatus(const std::wstring& filePath) {
        std::wstring result = L"";

        // Check Authenticode signature
        WINTRUST_FILE_INFO fileInfo = {};
        fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
        fileInfo.pcwszFilePath = filePath.c_str();

        WINTRUST_DATA winTrustData = {};
        winTrustData.cbStruct = sizeof(WINTRUST_DATA);
        winTrustData.dwUIChoice = WTD_UI_NONE;
        winTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
        winTrustData.dwUnionChoice = WTD_CHOICE_FILE;
        winTrustData.pFile = &fileInfo;

        GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        LONG authResult = WinVerifyTrust(NULL, &policyGUID, &winTrustData);

        // Check catalog signature
        HCATADMIN hCatAdmin = NULL;
        HCATINFO hCatInfo = NULL;
        bool catalogSigned = false;

        HMODULE hWintrust = LoadLibraryW(L"wintrust.dll");
        if (hWintrust) {
            typedef BOOL(WINAPI* CryptCATAdminAcquireContextFunc)(HCATADMIN*, const GUID*, DWORD);
            typedef BOOL(WINAPI* CryptCATAdminReleaseContextFunc)(HCATADMIN, DWORD);
            typedef BOOL(WINAPI* CryptCATAdminCalcHashFromFileHandleFunc)(HANDLE, DWORD*, BYTE*, DWORD);
            typedef HCATINFO(WINAPI* CryptCATAdminEnumCatalogFromHashFunc)(HCATADMIN, BYTE*, DWORD, DWORD, HCATINFO*);
            typedef BOOL(WINAPI* CryptCATAdminReleaseCatalogContextFunc)(HCATADMIN, HCATINFO, DWORD);

            CryptCATAdminAcquireContextFunc pCryptCATAdminAcquireContext =
                (CryptCATAdminAcquireContextFunc)GetProcAddress(hWintrust, "CryptCATAdminAcquireContext");
            CryptCATAdminReleaseContextFunc pCryptCATAdminReleaseContext =
                (CryptCATAdminReleaseContextFunc)GetProcAddress(hWintrust, "CryptCATAdminReleaseContext");
            CryptCATAdminCalcHashFromFileHandleFunc pCryptCATAdminCalcHashFromFileHandle =
                (CryptCATAdminCalcHashFromFileHandleFunc)GetProcAddress(hWintrust, "CryptCATAdminCalcHashFromFileHandle");
            CryptCATAdminEnumCatalogFromHashFunc pCryptCATAdminEnumCatalogFromHash =
                (CryptCATAdminEnumCatalogFromHashFunc)GetProcAddress(hWintrust, "CryptCATAdminEnumCatalogFromHash");
            CryptCATAdminReleaseCatalogContextFunc pCryptCATAdminReleaseCatalogContext =
                (CryptCATAdminReleaseCatalogContextFunc)GetProcAddress(hWintrust, "CryptCATAdminReleaseCatalogContext");

            if (pCryptCATAdminAcquireContext && pCryptCATAdminReleaseContext &&
                pCryptCATAdminCalcHashFromFileHandle && pCryptCATAdminEnumCatalogFromHash &&
                pCryptCATAdminReleaseCatalogContext) {

                if (pCryptCATAdminAcquireContext(&hCatAdmin, NULL, 0)) {
                    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                        NULL, OPEN_EXISTING, 0, NULL);
                    if (hFile != INVALID_HANDLE_VALUE) {
                        DWORD hashSize = 0;
                        pCryptCATAdminCalcHashFromFileHandle(hFile, &hashSize, NULL, 0);
                        if (hashSize > 0) {
                            std::vector<BYTE> hash(hashSize);
                            if (pCryptCATAdminCalcHashFromFileHandle(hFile, &hashSize, hash.data(), 0)) {
                                hCatInfo = pCryptCATAdminEnumCatalogFromHash(hCatAdmin, hash.data(), hashSize, 0, NULL);
                                if (hCatInfo) {
                                    catalogSigned = true;
                                    pCryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
                                }
                            }
                        }
                        CloseHandle(hFile);
                    }
                    pCryptCATAdminReleaseContext(hCatAdmin, 0);
                }
            }
            FreeLibrary(hWintrust);
        }

        // Determine status based on all checks
        switch (authResult) {
        case ERROR_SUCCESS:
            result = L"Valid (Authenticode)";
            break;
        case TRUST_E_NOSIGNATURE:
            if (catalogSigned) {
                result = L"Valid (Catalog)";
            }
            else {
                result = L"NotSigned";
            }
            break;
        case TRUST_E_SUBJECT_NOT_TRUSTED:
            result = L"Invalid/Fake Signature";
            break;
        case TRUST_E_EXPLICIT_DISTRUST:
            result = L"Distrusted";
            break;
        case TRUST_E_SUBJECT_FORM_UNKNOWN:
            result = L"Invalid Signature Format";
            break;
        case TRUST_E_PROVIDER_UNKNOWN:
            result = L"Unknown Signature Provider";
            break;
        case TRUST_E_BAD_DIGEST:
            result = L"Tampered/Fake Signature";
            break;
        case TRUST_E_CERT_SIGNATURE:
            result = L"Fake/Invalid Certificate";
            break;
        case TRUST_E_SYSTEM_ERROR:
            result = L"System Error During Verification";
            break;
        case TRUST_E_NO_SIGNER_CERT:
            result = L"No Signer Certificate";
            break;
        case TRUST_E_COUNTER_SIGNER:
            result = L"Counter Signer Error";
            break;
        case TRUST_E_TIME_STAMP:
            result = L"Timestamp Error";
            break;
        case TRUST_E_FINANCIAL_CRITERIA:
            result = L"Financial Criteria Not Met";
            break;
        case CERT_E_EXPIRED:
            result = L"Expired Certificate";
            break;
        case CERT_E_REVOKED:
            result = L"Revoked Certificate";
            break;
        case CERT_E_UNTRUSTEDROOT:
            result = L"Untrusted Root Certificate";
            break;
        case CERT_E_CHAINING:
            result = L"Certificate Chain Error";
            break;
        case CERT_E_WRONG_USAGE:
            result = L"Certificate Wrong Usage";
            break;
        case CERT_E_UNTRUSTEDTESTROOT:
            result = L"Untrusted Test Root";
            break;
        case CERT_E_VALIDITYPERIODNESTING:
            result = L"Certificate Validity Period Error";
            break;
        case CERT_E_CRITICAL:
            result = L"Critical Certificate Extension";
            break;
        case CERT_E_PURPOSE:
            result = L"Certificate Purpose Error";
            break;
        case CERT_E_ISSUERCHAINING:
            result = L"Certificate Issuer Chain Error";
            break;
        case CERT_E_MALFORMED:
            result = L"Malformed Certificate";
            break;
        case CRYPT_E_BAD_MSG:
            result = L"Corrupted/Fake Signature";
            break;
        case CRYPT_E_BAD_ENCODE:
            result = L"Bad Signature Encoding";
            break;
        case CRYPT_E_INVALID_MSG_TYPE:
            result = L"Invalid Message Type";
            break;
        case CRYPT_E_UNEXPECTED_MSG_TYPE:
            result = L"Unexpected Message Type";
            break;
        case CRYPT_E_HASH_VALUE:
            result = L"Hash Value Mismatch";
            break;
        case NTE_BAD_SIGNATURE:
            result = L"Bad Digital Signature";
            break;
        default:
            if (catalogSigned && authResult == TRUST_E_NOSIGNATURE) {
                result = L"Valid (Catalog)";
            }
            else {
                result = L"Signature Error (Code: " + std::to_wstring(authResult) + L")";
            }
            break;
        }
        return result;
    }

    std::vector<std::wstring> FindTxtFiles() {
        std::vector<std::wstring> txtFiles;

        if (!draggedFile.empty()) {
            txtFiles.push_back(draggedFile);
            return txtFiles;
        }

        // Look for all .txt files in current directory
        WIN32_FIND_DATAW findData;
        HANDLE hFind = FindFirstFileW(L"*.txt", &findData);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                txtFiles.push_back(findData.cFileName);
            } while (FindNextFileW(hFind, &findData));
            FindClose(hFind);
        }

        return txtFiles;
    }

    bool LoadPathsFromFiles(const std::vector<std::wstring>& fileNames) {
        filePaths.clear();

        for (const auto& fileName : fileNames) {
            std::wifstream file(fileName);
            if (!file.is_open()) {
                continue; // Skip files that can't be opened
            }

            std::wstring content;
            std::wstring line;
            while (std::getline(file, line)) {
                if (!line.empty() && line.back() == L'\r') {
                    line.pop_back();
                }
                content += line + L"\n";
            }
            file.close();

            // Extract paths from the content
            std::vector<std::wstring> extractedPaths = ExtractPathsFromText(content);
            for (const auto& path : extractedPaths) {
                if (std::find(filePaths.begin(), filePaths.end(), path) == filePaths.end()) {
                    filePaths.push_back(path);
                }
            }
        }

        if (filePaths.empty()) {
            SendMessage(hStatusBar, SB_SETTEXT, 0, (LPARAM)L"No valid file paths found in .txt files");
            return false;
        }

        return true;
    }

    void StartProcessing() {
        std::vector<std::wstring> txtFiles = FindTxtFiles();
        if (txtFiles.empty()) {
            SendMessage(hStatusBar, SB_SETTEXT, 0, (LPARAM)L"No .txt files found");
            return;
        }

        if (!LoadPathsFromFiles(txtFiles)) return;

        StartScan();
    }

    void StartScan() {
        if (isScanning) return;

        isScanning = true;
        scanResults.clear();
        filteredResults.clear();
        EnableWindow(hExportButton, FALSE);

        SendMessage(hProgressBar, PBM_SETRANGE, 0, MAKELPARAM(0, filePaths.size()));
        SendMessage(hProgressBar, PBM_SETPOS, 0, 0);
        ShowWindow(hProgressBar, SW_SHOW);

        ListView_DeleteAllItems(hListView);
        SendMessage(hStatusBar, SB_SETTEXT, 0, (LPARAM)L"Scanning files...");

        scanStartTime = std::chrono::steady_clock::now();

        std::thread([this]() {
            for (size_t i = 0; i < filePaths.size(); ++i) {
                const auto& path = filePaths[i];
                PostMessage(hMainWnd, WM_SCAN_PROGRESS, i + 1, filePaths.size());

                std::wstring fileName = PathFindFileNameW(path.c_str());

                // Check if file exists first
                if (!PathFileExistsW(path.c_str())) {
                    FileResult* result = new FileResult{ fileName, path, L"Deleted", L"" };
                    PostMessage(hMainWnd, WM_ADD_ITEM, (WPARAM)result, 0);
                    continue;
                }

                std::wstring signature;
                try {
                    signature = GetDetailedSignatureStatus(path);
                }
                catch (...) {
                    signature = L"Access Denied";
                }

                FileResult* result = new FileResult{ fileName, path, signature, L"" };
                PostMessage(hMainWnd, WM_ADD_ITEM, (WPARAM)result, 0);
            }

            auto endTime = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - scanStartTime);
            PostMessage(hMainWnd, WM_SCAN_COMPLETE, (DWORD)elapsed.count(), 0);
            }).detach();
    }

    void UpdateProgress(int current, int total) {
        SendMessage(hProgressBar, PBM_SETPOS, current, 0);
        std::wstringstream status;
        status << L"Scanning... " << current << L" of " << total << L" files";
        SendMessage(hStatusBar, SB_SETTEXT, 0, (LPARAM)status.str().c_str());
    }

    void AddResultToList(const FileResult& result) {
        scanResults.push_back(result);
        filteredResults.push_back(result);

        LVITEMW item = {};
        item.mask = LVIF_TEXT;
        item.iItem = ListView_GetItemCount(hListView);
        item.iSubItem = 0;
        item.pszText = const_cast<LPWSTR>(result.fileName.c_str());
        int index = ListView_InsertItem(hListView, &item);

        ListView_SetItemText(hListView, index, 1, const_cast<LPWSTR>(result.fullPath.c_str()));
        ListView_SetItemText(hListView, index, 2, const_cast<LPWSTR>(result.signatureStatus.c_str()));
    }

    void OnScanComplete(DWORD elapsedMs) {
        isScanning = false;
        EnableWindow(hExportButton, TRUE);
        ShowWindow(hProgressBar, SW_HIDE);

        int hours = elapsedMs / 3600000;
        int minutes = (elapsedMs % 3600000) / 60000;
        int seconds = (elapsedMs % 60000) / 1000;
        int ms = elapsedMs % 1000;

        std::wstringstream status;
        status << L"Scan completed in "
            << std::setfill(L'0') << std::setw(2) << hours << L":"
            << std::setfill(L'0') << std::setw(2) << minutes << L":"
            << std::setfill(L'0') << std::setw(2) << seconds << L"."
            << std::setfill(L'0') << std::setw(3) << ms
            << L" - " << scanResults.size() << L" files processed";
        SendMessage(hStatusBar, SB_SETTEXT, 0, (LPARAM)status.str().c_str());

        // Auto-resize columns
        ListView_SetColumnWidth(hListView, 0, LVSCW_AUTOSIZE);
        ListView_SetColumnWidth(hListView, 1, LVSCW_AUTOSIZE);
        ListView_SetColumnWidth(hListView, 2, LVSCW_AUTOSIZE);
    }

    void FilterResults() {
        WCHAR searchText[256];
        GetWindowTextW(hSearchBox, searchText, 256);
        std::wstring filter(searchText);
        std::transform(filter.begin(), filter.end(), filter.begin(), ::towlower);

        ListView_DeleteAllItems(hListView);
        filteredResults.clear();

        for (const auto& result : scanResults) {
            std::wstring fileName = result.fileName;
            std::wstring fullPath = result.fullPath;
            std::wstring status = result.signatureStatus;

            std::transform(fileName.begin(), fileName.end(), fileName.begin(), ::towlower);
            std::transform(fullPath.begin(), fullPath.end(), fullPath.begin(), ::towlower);
            std::transform(status.begin(), status.end(), status.begin(), ::towlower);

            if (filter.empty() ||
                fileName.find(filter) != std::wstring::npos ||
                fullPath.find(filter) != std::wstring::npos ||
                status.find(filter) != std::wstring::npos) {

                filteredResults.push_back(result);

                LVITEMW item = {};
                item.mask = LVIF_TEXT;
                item.iItem = ListView_GetItemCount(hListView);
                item.iSubItem = 0;
                item.pszText = const_cast<LPWSTR>(result.fileName.c_str());
                int index = ListView_InsertItem(hListView, &item);

                ListView_SetItemText(hListView, index, 1, const_cast<LPWSTR>(result.fullPath.c_str()));
                ListView_SetItemText(hListView, index, 2, const_cast<LPWSTR>(result.signatureStatus.c_str()));
            }
        }
    }

    void SortColumn(int column) {
        static int lastColumn = -1;
        static bool ascending = true;

        if (column == lastColumn) {
            ascending = !ascending;
        }
        else {
            ascending = true;
            lastColumn = column;
        }

        bool isAscending = ascending;
        int sortColumn = column;

        std::sort(filteredResults.begin(), filteredResults.end(),
            [sortColumn, isAscending](const FileResult& a, const FileResult& b) {
                if (sortColumn == 2) { // Signature Status column
                    int priorityA = GetSignaturePriority(a.signatureStatus);
                    int priorityB = GetSignaturePriority(b.signatureStatus);

                    if (priorityA != priorityB) {
                        return isAscending ? priorityA < priorityB : priorityA > priorityB;
                    }

                    // If same priority, sort alphabetically by filename
                    return isAscending ? a.fileName < b.fileName : a.fileName > b.fileName;
                }
                else {
                    // For other columns, use regular string comparison
                    std::wstring aVal, bVal;
                    switch (sortColumn) {
                    case 0: aVal = a.fileName; bVal = b.fileName; break;
                    case 1: aVal = a.fullPath; bVal = b.fullPath; break;
                    default: return false;
                    }

                    std::transform(aVal.begin(), aVal.end(), aVal.begin(), ::towlower);
                    std::transform(bVal.begin(), bVal.end(), bVal.begin(), ::towlower);
                    return isAscending ? aVal < bVal : aVal > bVal;
                }
            });

        // Refresh ListView
        ListView_DeleteAllItems(hListView);
        for (const auto& result : filteredResults) {
            LVITEMW item = {};
            item.mask = LVIF_TEXT;
            item.iItem = ListView_GetItemCount(hListView);
            item.iSubItem = 0;
            item.pszText = const_cast<LPWSTR>(result.fileName.c_str());
            int index = ListView_InsertItem(hListView, &item);
            ListView_SetItemText(hListView, index, 1, const_cast<LPWSTR>(result.fullPath.c_str()));
            ListView_SetItemText(hListView, index, 2, const_cast<LPWSTR>(result.signatureStatus.c_str()));
        }
    }

    void ExportResults() {
        if (filteredResults.empty()) {
            MessageBoxW(hMainWnd, L"No results to export. Please run a scan first.",
                L"No Data", MB_OK | MB_ICONWARNING);
            return;
        }

        std::wofstream file(L"signature_results.csv");
        if (!file.is_open()) {
            MessageBoxW(hMainWnd, L"Failed to create export file!", L"Export Error", MB_OK | MB_ICONERROR);
            return;
        }

        file << L"File Name,Full Path,Signature Status\n";
        for (const auto& result : filteredResults) {
            file << L"\"" << result.fileName << L"\",\""
                << result.fullPath << L"\",\""
                << result.signatureStatus << L"\"\n";
        }

        file.close();
        MessageBoxW(hMainWnd, L"Results exported to signature_results.csv",
            L"Export Complete", MB_OK | MB_ICONINFORMATION);
    }

    void CreateControls() {
        // Search box
        CreateWindowW(L"STATIC", L"Search:",
            WS_VISIBLE | WS_CHILD,
            10, 15, 50, 20, hMainWnd, NULL, GetModuleHandle(NULL), NULL);

        hSearchBox = CreateWindowW(L"EDIT", L"",
            WS_VISIBLE | WS_CHILD | WS_BORDER | ES_AUTOHSCROLL,
            70, 12, 200, 25, hMainWnd, (HMENU)ID_SEARCHBOX, GetModuleHandle(NULL), NULL);

        // Export button
        hExportButton = CreateWindowW(L"BUTTON", L"Export CSV",
            WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
            280, 12, 100, 25, hMainWnd, (HMENU)ID_BUTTON_EXPORT, GetModuleHandle(NULL), NULL);

        // Progress bar
        hProgressBar = CreateWindowW(PROGRESS_CLASSW, NULL,
            WS_CHILD | PBS_SMOOTH,
            390, 15, 300, 20, hMainWnd, (HMENU)ID_PROGRESSBAR, GetModuleHandle(NULL), NULL);

        // Status bar
        hStatusBar = CreateWindowW(STATUSCLASSNAMEW, L"Ready - Drop .txt files or place them in the same directory",
            WS_VISIBLE | WS_CHILD | SBARS_SIZEGRIP,
            0, 0, 0, 0, hMainWnd, (HMENU)ID_STATUSBAR, GetModuleHandle(NULL), NULL);

        // ListView with dark mode
        hListView = CreateWindowW(WC_LISTVIEWW, L"",
            WS_VISIBLE | WS_CHILD | WS_BORDER | LVS_REPORT | LVS_SHOWSELALWAYS,
            10, 45, 760, 400, hMainWnd, (HMENU)ID_LISTVIEW, GetModuleHandle(NULL), NULL);

        // Set extended ListView styles
        ListView_SetExtendedListViewStyle(hListView,
            LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);

        // Set dark colors for ListView
        ListView_SetBkColor(hListView, DARK_BG_COLOR);
        ListView_SetTextBkColor(hListView, DARK_BG_COLOR);
        ListView_SetTextColor(hListView, DARK_TEXT_COLOR);

        // Add columns
        LVCOLUMNW col = {};
        col.mask = LVCF_TEXT | LVCF_WIDTH;
        col.cx = 200;
        col.pszText = (LPWSTR)L"File Name";
        ListView_InsertColumn(hListView, 0, &col);

        col.cx = 400;
        col.pszText = (LPWSTR)L"Full Path";
        ListView_InsertColumn(hListView, 1, &col);

        col.cx = 150;
        col.pszText = (LPWSTR)L"Signature Status";
        ListView_InsertColumn(hListView, 2, &col);

        // Set font for all controls
        HFONT hFont = CreateFontW(16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_OUTLINE_PRECIS, CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY, VARIABLE_PITCH, L"Segoe UI");

        SendMessage(hSearchBox, WM_SETFONT, (WPARAM)hFont, TRUE);
        SendMessage(hExportButton, WM_SETFONT, (WPARAM)hFont, TRUE);
        SendMessage(hListView, WM_SETFONT, (WPARAM)hFont, TRUE);
        SendMessage(hStatusBar, WM_SETFONT, (WPARAM)hFont, TRUE);
    }

    void ResizeControls() {
        RECT rect;
        GetClientRect(hMainWnd, &rect);

        RECT statusRect;
        GetWindowRect(hStatusBar, &statusRect);
        int statusHeight = statusRect.bottom - statusRect.top;

        SendMessage(hStatusBar, WM_SIZE, 0, 0);

        SetWindowPos(hListView, NULL, 10, 45,
            rect.right - 20, rect.bottom - 65 - statusHeight, SWP_NOZORDER);

        SetWindowPos(hProgressBar, NULL, 390, 15,
            rect.right - 410, 20, SWP_NOZORDER);
    }

    bool IsRunAsAdmin() {
        BOOL isAdmin = FALSE;
        PSID adminGroup = NULL;
        SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
        if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
            DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
            CheckTokenMembership(NULL, adminGroup, &isAdmin);
            FreeSid(adminGroup);
        }
        return isAdmin == TRUE;
    }

    int Run() {
        // Check admin privileges
        if (!IsRunAsAdmin()) {
            MessageBoxW(NULL,
                L"⚠️ ADMINISTRATOR PRIVILEGES REQUIRED ⚠️\n\n"
                L"This application needs Administrator rights to:\n"
                L"• Access system files and their signatures\n"
                L"• Verify catalog signatures properly\n"
                L"• Check embedded digital certificates\n\n"
                L"Please run this application as Administrator:\n"
                L"Right-click → 'Run as administrator'\n\n"
                L"Made by RitzySix - Signature Check Paths",
                L"Admin Required - Ritzy's Signature Grabber", MB_OK | MB_ICONWARNING);
            return 1;
        }

        // Register window class
        WNDCLASSW wc = {};
        wc.lpfnWndProc = WindowProc;
        wc.hInstance = GetModuleHandle(NULL);
        wc.lpszClassName = L"SignatureGrabber";
        wc.hbrBackground = CreateSolidBrush(DARK_BG_COLOR);
        wc.hCursor = LoadCursor(NULL, IDC_ARROW);
        wc.hIcon = LoadIcon(NULL, IDI_SHIELD);
        wc.lpszMenuName = NULL;
        wc.cbClsExtra = 0;
        wc.cbWndExtra = 0;

        if (!RegisterClassW(&wc)) {
            MessageBoxW(NULL, L"Failed to register window class!", L"Error", MB_OK | MB_ICONERROR);
            return 1;
        }

        // Create dark brush
        hDarkBrush = CreateSolidBrush(DARK_BG_COLOR);

        // Create main window
        hMainWnd = CreateWindowW(L"SignatureGrabber", L"Ritzy's Path Scanner v1.0.5",
            WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 900, 700,
            NULL, NULL, GetModuleHandle(NULL), NULL);

        if (!hMainWnd) {
            MessageBoxW(NULL, L"Failed to create main window!", L"Error", MB_OK | MB_ICONERROR);
            return 1;
        }

        SetWindowLongPtr(hMainWnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(this));

        // Initialize common controls
        INITCOMMONCONTROLSEX icex = {};
        icex.dwSize = sizeof(INITCOMMONCONTROLSEX);
        icex.dwICC = ICC_LISTVIEW_CLASSES | ICC_PROGRESS_CLASS | ICC_BAR_CLASSES;
        if (!InitCommonControlsEx(&icex)) {
            MessageBoxW(NULL, L"Failed to initialize common controls!", L"Error", MB_OK | MB_ICONERROR);
            return 1;
        }

        CreateControls();
        ShowWindow(hMainWnd, SW_SHOW);
        UpdateWindow(hMainWnd);

        // Auto-start processing
        StartProcessing();

        // Message loop
        MSG msg;
        while (GetMessage(&msg, NULL, 0, 0)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }

        return (int)msg.wParam;
    }
};

// Custom ListView subclass for dark mode
WNDPROC oldListViewProc;
LRESULT CALLBACK ListViewSubclassProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
    case WM_PAINT:
    {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);
        // Set dark colors
        SetBkColor(hdc, DARK_BG_COLOR);
        SetTextColor(hdc, DARK_TEXT_COLOR);
        EndPaint(hwnd, &ps);
        return CallWindowProc(oldListViewProc, hwnd, uMsg, wParam, lParam);
    }
    break;
    }
    return CallWindowProc(oldListViewProc, hwnd, uMsg, wParam, lParam);
}

// Application entry point
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    // Enable visual styles and dark mode
    INITCOMMONCONTROLSEX icc = {};
    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_WIN95_CLASSES;
    InitCommonControlsEx(&icc);

    // Set process DPI awareness
    SetProcessDPIAware();

    SignatureGrabber app;
    return app.Run();
}