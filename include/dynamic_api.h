#ifndef DYNAMIC_API_H
#define DYNAMIC_API_H

#include <windows.h>

// Structure for dynamically loading API functions
typedef struct {
    // Basic memory functions
    LPVOID (WINAPI *pVirtualAllocEx)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
    BOOL (WINAPI *pVirtualProtectEx)(HANDLE, LPVOID, SIZE_T, DWORD, PDWORD);
    BOOL (WINAPI *pVirtualFreeEx)(HANDLE, LPVOID, SIZE_T, DWORD);
    BOOL (WINAPI *pWriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
    
    // Thread/process functions
    HANDLE (WINAPI *pCreateRemoteThread)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, 
                                        LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
    DWORD (WINAPI *pWaitForSingleObject)(HANDLE, DWORD);
    HANDLE (WINAPI *pOpenProcess)(DWORD, BOOL, DWORD);
    BOOL (WINAPI *pCloseHandle)(HANDLE);
    
    // Advanced functions for alternative methods
    LPVOID pNtCreateThreadEx;
    LPVOID pRtlCreateUserThread;
    LPVOID pQueueUserAPC;
    
    // Helper functions
    FARPROC (WINAPI *pGetProcAddress)(HMODULE, LPCSTR);
    HMODULE (WINAPI *pLoadLibraryA)(LPCSTR);
    HMODULE (WINAPI *pGetModuleHandleA)(LPCSTR);
} API_POINTERS;

// Find target process to inject into
DWORD find_target_process(API_POINTERS* apis);

// Dynamically load API functions
BOOL load_dynamic_apis(API_POINTERS* apis);

#endif // DYNAMIC_API_H 