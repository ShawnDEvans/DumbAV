#include <windows.h>
#include <stdio.h>

// This function will be called immediately by the loader above.
// In a proper Reflective DLL, the DllMain should NOT be the entry point,
// but rather a separate exported function named 'ReflectiveLoader'.
// For this example, we use DllMain's logic for simplicity.

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            // This code runs when the DLL is loaded (attached to the process).
            MessageBoxA(NULL, "Reflective DLL Executed Successfully!", "Payload Loaded", MB_OK);
            break;
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}
