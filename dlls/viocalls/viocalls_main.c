/*
 *  viocalls_main.c - OS/2 16/32-bit VIOCALLS.DLL Video Subsystem Module
 *  (c) Arucard 2026 - Wine-OS/2 Project
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include "os2types.h"
#include "wineos2_286cpu.h" /* For 16-bit Pascal context resolution */

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) DisableThreadLibraryCalls(hinstDLL);
    return TRUE;
}

/* =========================================================================
 * 32-BIT FLAT BACKENDS (LX Subsystem)
 * ========================================================================= */

APIRET WINAPI os2_VioWrtTTY(PCHAR pStr, ULONG cbStr, HVIO hVio) {
    if (hVio != 0) return ERROR_VIO_INVALID_HANDLE;
    if (cbStr == 0 || !pStr) return NO_ERROR;

    HANDLE host_stdout = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD written = 0;

    if (WriteFile(host_stdout, pStr, cbStr, &written, NULL)) return NO_ERROR;
    return ERROR_VIO_INVALID_HANDLE;
}

APIRET WINAPI os2_VioSetCurPos(ULONG row, ULONG column, HVIO hVio) {
    if (hVio != 0) return ERROR_VIO_INVALID_HANDLE;

    HANDLE host_stdout = GetStdHandle(STD_OUTPUT_HANDLE);
    COORD coord;
    coord.X = (SHORT)column;
    coord.Y = (SHORT)row;

    if (SetConsoleCursorPosition(host_stdout, coord)) return NO_ERROR;
    return ERROR_VIO_INVALID_HANDLE;
}

/* =========================================================================
 * 16-BIT EMULATED BRIDGES (NE Subsystem)
 * ========================================================================= */

uint16_t os2_Vio16WrtTTY(CPU286_Context* ctx) {
    uint16_t sp_offset = ctx->sp + 4; /* Skip CS:IP */
    uint16_t hVio      = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 4);
    uint16_t cbStr     = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 2);
    uint16_t pStr_off  = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 0);
    uint16_t pStr_sel  = *(uint16_t*)mode16to32(ctx->ss, sp_offset - 2); /* Pascal calling selector layout */

    char* host_str = (char*)mode16to32(pStr_sel, pStr_off);
    APIRET rc = os2_VioWrtTTY(host_str, (ULONG)cbStr, (HVIO)hVio);

    ctx->sp += 8; /* Clean Pascal parameters */
    return (uint16_t)rc;
}

uint16_t os2_Vio16SetCurPos(CPU286_Context* ctx) {
    uint16_t sp_offset = ctx->sp + 4;
    uint16_t hVio      = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 4);
    uint16_t column    = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 2);
    uint16_t row       = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 0);

    APIRET rc = os2_VioSetCurPos((ULONG)row, (ULONG)column, (HVIO)hVio);
    ctx->sp += 6;
    return (uint16_t)rc;
}

