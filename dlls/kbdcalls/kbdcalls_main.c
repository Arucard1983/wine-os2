/*
 *  moucalls_main.c - OS/2 16/32-bit MOUCALLS.DLL Mouse Subsystem Module
 *  (c) Arucard 2026 - Wine-OS/2 Project
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "os2types.h"
#include "wineos2_286cpu.h"

APIRET WINAPI os2_MouGetNumButtons(PUSHORT pNumberOfButtons, ULONG hMou) {
    if (hMou != 0) return 1; /* ERROR_MOU_INVALID_HANDLE */
    if (!pNumberOfButtons) return NO_ERROR;

    int buttons = GetSystemMetrics(SM_CMOUSEBUTTONS);
    *pNumberOfButtons = (buttons == 0) ? 2 : (USHORT)buttons;
    
    return NO_ERROR;
}

uint16_t os2_Mou16GetNumButtons(CPU286_Context* ctx) {
    uint16_t sp_offset = ctx->sp + 4;
    uint16_t hMou      = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 4);
    uint16_t pBut_off  = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 2);
    uint16_t pBut_sel  = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 0);

    USHORT* host_buttons = (USHORT*)mode16to32(pBut_sel, pBut_off);
    APIRET rc = os2_MouGetNumButtons(host_buttons, (ULONG)hMou);

    ctx->sp += 6;
    return (uint16_t)rc;
}

