#include <windows.h>
#include <iphlpapi.h>
#include "../include/anti_analysis.h"

// Windows winternals structure definitions
typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PVOID Ldr;
    PVOID ProcessParameters;
    PVOID Reserved4[3];
    PVOID AtlThunkSListPtr;
    PVOID Reserved5;
    ULONG Reserved6;
    PVOID Reserved7;
    ULONG Reserved8;
    ULONG AtlThunkSListPtr32;
    PVOID Reserved9[45];
    BYTE Reserved10[96];
    PVOID PostProcessInitRoutine;
    BYTE Reserved11[128];
    PVOID Reserved12[1];
    ULONG SessionId;
} PEB, *PPEB;

// Function to check for debugging/VM environment
BOOL check_analysis_environment(ANTI_ANALYSIS* aa) {
    // Check for debugger
    if (aa->pIsDebuggerPresent()) {
        return TRUE;
    }
    
    // Check for remote debugger
    BOOL debuggerPresent = FALSE;
    aa->pCheckRemoteDebuggerPresent(GetCurrentProcess(), &debuggerPresent);
    if (debuggerPresent) {
        return TRUE;
    }
    
    // Time-delta detection (for VM/sandboxes)
    DWORD start = aa->pGetTickCount();
    Sleep(500);  // Sleep for 500ms
    DWORD end = aa->pGetTickCount();
    if ((end - start) < 400) { // If less than 400ms passed, it's likely a VM/debugger
        return TRUE;
    }
    
    // Debug string test
    DWORD tick1 = aa->pGetTickCount();
    aa->pOutputDebugStringA("Anti-Analysis Check");
    DWORD tick2 = aa->pGetTickCount();
    if ((tick2 - tick1) > 100) { // If string processing took too long, debugger present
        return TRUE;
    }
    
    #ifdef _WIN64
    // PEB BeingDebugged flag check (64-bit)
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    if (pPeb->BeingDebugged) {
        return TRUE;
    }
    
    // NtGlobalFlag check (typically set by debuggers)
    DWORD ntGlobalFlag = *(DWORD*)((PBYTE)pPeb + 0xBC);
    if (ntGlobalFlag & 0x70) { // Check for FLG_HEAP_ENABLE_TAIL_CHECK, etc.
        return TRUE;
    }
    #else
    // 32-bit PEB access
    PPEB pPeb = (PPEB)__readfsdword(0x30);
    if (pPeb->BeingDebugged) {
        return TRUE;
    }
    
    // NtGlobalFlag check for 32-bit
    DWORD ntGlobalFlag = *(DWORD*)((PBYTE)pPeb + 0x68);
    if (ntGlobalFlag & 0x70) {
        return TRUE;
    }
    #endif
    
    // Check for common VM adapter MAC addresses (VMware)
    BYTE vmwareMAC[3] = {0x00, 0x05, 0x69}; // VMware MAC prefix
    BYTE virtualBoxMAC[3] = {0x08, 0x00, 0x27}; // VirtualBox MAC prefix
    
    IP_ADAPTER_INFO adapterInfo[16];
    DWORD dwBufLen = sizeof(adapterInfo);
    
    if (GetAdaptersInfo(adapterInfo, &dwBufLen) == ERROR_SUCCESS) {
        PIP_ADAPTER_INFO pAdapterInfo = adapterInfo;
        while (pAdapterInfo) {
            if (memcmp(pAdapterInfo->Address, vmwareMAC, 3) == 0 ||
                memcmp(pAdapterInfo->Address, virtualBoxMAC, 3) == 0) {
                return TRUE;
            }
            pAdapterInfo = pAdapterInfo->Next;
        }
    }
    
    return FALSE;
}

// Load anti-analysis functions
BOOL load_anti_analysis_functions(ANTI_ANALYSIS* aa) {
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32 == NULL) {
        return FALSE;
    }
    
    aa->pIsDebuggerPresent = (BOOL (*)(void))GetProcAddress(hKernel32, "IsDebuggerPresent");
    aa->pCheckRemoteDebuggerPresent = (BOOL (*)(HANDLE, PBOOL))
                                    GetProcAddress(hKernel32, "CheckRemoteDebuggerPresent");
    aa->pOutputDebugStringA = (void (*)(LPCSTR))GetProcAddress(hKernel32, "OutputDebugStringA");
    aa->pGetTickCount = (DWORD (*)(void))GetProcAddress(hKernel32, "GetTickCount");
    
    return (aa->pIsDebuggerPresent != NULL && 
            aa->pCheckRemoteDebuggerPresent != NULL && 
            aa->pOutputDebugStringA != NULL &&
            aa->pGetTickCount != NULL);
} 