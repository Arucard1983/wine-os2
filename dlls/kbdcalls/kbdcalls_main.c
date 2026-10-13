/*
 *  kbdcalls_main.c - OS/2 16/32-bit Keyboard Subsystem Simulation
 *  (c) Arucard 2026 - Wine-OS/2 Project
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

#include "os2types.h"
#include "wineos2_286cpu.h"

/* Import dynamic registration routine from the master wineos2.exe core engine */
uint16_t CDECL wineos2_register_callgate(const char* mod_name, uint16_t ordinal, void* thunk_ptr);

/* =========================================================================
 * 32-BIT NATIVE CORES (LX Subsystem - Routes directly to Win32 Console API)
 * ========================================================================= */

APIRET CDECL os2_KbdCharIn(PKBDKEYINFO pkbci, USHORT fWait, HKBD hkbd) {
    HANDLE hInput = GetStdHandle(STD_INPUT_HANDLE);
    INPUT_RECORD ir;
    DWORD read;

    if (!pkbci) return 87; /* ERROR_INVALID_PARAMETER */
    memset(pkbci, 0, sizeof(KBDKEYINFO));

    /* Non-blocking request check matching historical OS/2 API constraints */
    if (fWait == 0) {
        DWORD events = 0;
        GetNumberOfConsoleInputEvents(hInput, &events);
        if (events == 0) return NO_ERROR; 
    }

    /* Process console input events safely */
    while (ReadConsoleInputA(hInput, &ir, 1, &read) && read > 0) {
        if (ir.EventType == KEY_EVENT && ir.Event.KeyEvent.bKeyDown) {
            pkbci->chChar = ir.Event.KeyEvent.uChar.AsciiChar;
            pkbci->chScan = ir.Event.KeyEvent.wVirtualScanCode;
            pkbci->time   = GetTickCount();
            return NO_ERROR;
        }
    }
    return NO_ERROR;
}

/* =========================================================================
 * 16-BIT EMULATED CORES (NE Subsystem - Corrected Stack Offsets & Pascal Cleanup)
 * ========================================================================= */

uint16_t os2_Kbd16CharIn(CPU286_Context* ctx) {
    uint16_t sp_offset = ctx->sp + 4; /* Skip 4 bytes of Far CS:IP return address */
    
    /* Pascal order: Unpacking parameters from highest stack coordinate to lowest */
    uint16_t pInfo_sel = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 6);
    uint16_t pInfo_off = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 4);
    uint16_t fWait     = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 2);
    uint16_t hkbd      = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 0);

    KBDKEYINFO* host_info = (KBDKEYINFO*)mode16to32(pInfo_sel, pInfo_off);
    if (!host_info) {
        ctx->sp += 8; /* Clean up 4 parameters of 2 bytes each */
        return 87;
    }

    APIRET rc = os2_KbdCharIn(host_info, fWait, (HKBD)hkbd);
    
    ctx->sp += 8; /* Pascal convention callee stack cleanup */
    return (uint16_t)rc;
}

/* =========================================================================
 * SUBSYSTEM INITIALIZATION - AUTONOMOUS BOOTSTRAP PIPELINE
 * ========================================================================= */

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinstDLL);

        /* 
         * Registers its own historical 16-bit execution Call Gate 
         * inside the centralized master wineos2 LDT structure.
         * Ordinal 4 maps to KbdCharIn under standard IBM specification rules.
         */
        wineos2_register_callgate("KBDCALLS", 4, os2_Kbd16CharIn);

        printf("[Kbdcalls] Autonomous 16-bit Callgate registration completed via wineos2 engine.\n");
        fflush(stdout);
    }
    return TRUE;
}
