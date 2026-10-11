/*
 *  doscalls_main.c - OS/2 32-bit DOSCALLS.DLL Core API Module
 *  (c) Arucard 2026 - Wine-OS/2 Project
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdint.h>

/* Compliance structural return codes for the OS/2 32-bit ABI specifications */
#define NO_ERROR                    0
#define ERROR_INVALID_PARAMETER     87
#define ERROR_NOT_ENOUGH_MEMORY     8
// It shuould later be moved to an include header file.

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hinstDLL);
            break;
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}

/* 32-bit OS/2 API Implementations compiled natively inside the Win32 DLL container */
uint16_t WINAPI os2_DosWrite(LONG hFile, LPVOID pBuffer, LONG cbWrite, PLONG pBytesActual) {
    if (!pBytesActual) return ERROR_INVALID_PARAMETER;

    if (cbWrite == 0) {
        *pBytesActual = 0;
        return NO_ERROR;
    }

    if (!pBuffer) return ERROR_INVALID_PARAMETER;

    /* Redirect VIO handle operations to standard host stdout/stderr descriptors */
    if (hFile == 1 || hFile == 2) {
        DWORD written = 0;
        HANDLE host_std = GetStdHandle(hFile == 1 ? STD_OUTPUT_HANDLE : STD_ERROR_HANDLE);
        
        if (WriteFile(host_std, pBuffer, cbWrite, &written, NULL)) {
            *pBytesActual = (LONG)written;
            return NO_ERROR;
        }
    }

    return ERROR_INVALID_PARAMETER;
}

uint16_t WINAPI os2_DosExit(LONG action_flags, LONG result_code) {
    printf("[OS/2 32-bit API] DosExit triggered. Terminating process with code: %d\n", (int)result_code);
    ExitProcess((UINT)result_code);
    return NO_ERROR;
}
