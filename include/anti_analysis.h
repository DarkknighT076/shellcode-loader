#ifndef ANTI_ANALYSIS_H
#define ANTI_ANALYSIS_H

#include <windows.h>

// Anti-analysis techniques
typedef struct {
    BOOL (*pIsDebuggerPresent)(void);
    BOOL (*pCheckRemoteDebuggerPresent)(HANDLE, PBOOL);
    void (*pOutputDebugStringA)(LPCSTR);
    DWORD (*pGetTickCount)(void);
} ANTI_ANALYSIS;

// Function to check for debugging/VM environment
BOOL check_analysis_environment(ANTI_ANALYSIS* aa);

// Load anti-analysis functions
BOOL load_anti_analysis_functions(ANTI_ANALYSIS* aa);

#endif // ANTI_ANALYSIS_H 