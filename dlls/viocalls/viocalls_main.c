/*
 *  viocalls_main.c - OS/2 32-bit VIOCALLS.DLL Video Subsystem Module
 *  (c) Arucard 2026 - Wine-OS/2 Project
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdint.h>

#define NO_ERROR                    0
#define ERROR_VIO_INVALID_HANDLE    350

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

/* 32-bit OS/2 API VioWrtTTY: Writes a character string directly to the console stream */
uint16_t WINAPI os2_VioWrtTTY(PCHAR pStr, ULONG cbStr, ULONG hVio) {
    if (hVio != 0) return ERROR_VIO_INVALID_HANDLE;
    if (cbStr == 0 || !pStr) return NO_ERROR;

    HANDLE host_stdout = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD written = 0;

    if (WriteFile(host_stdout, pStr, cbStr, &written, NULL)) {
        return NO_ERROR;
    }

    return ERROR_VIO_INVALID_HANDLE;
}

/* 32-bit OS/2 API VioSetCurPos: Sets the text coordinates for the terminal cursor */
uint16_t WINAPI os2_VioSetCurPos(ULONG row, ULONG column, ULONG hVio) {
    if (hVio != 0) return ERROR_VIO_INVALID_HANDLE;

    HANDLE host_stdout = GetStdHandle(STD_OUTPUT_HANDLE);
    COORD coord;
    coord.X = (SHORT)column;
    coord.Y = (SHORT)row;

    if (SetConsoleCursorPosition(host_stdout, coord)) {
        return NO_ERROR;
    }

    return ERROR_VIO_INVALID_HANDLE;
}
