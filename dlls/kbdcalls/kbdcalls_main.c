/*
 *  kbdcalls_main.c - OS/2 16/32-bit Keyboard Subsystem Simulation
 *  (c) Arucard 2026 - Wine-OS/2 Project
 */

#define WIN32_LEAN_AND_MEAN
#define WINEOS2_DLL_MODULE
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

#include "os2types.h"
#include "wineos2_286cpu.h"

OS2_LDT_ENTRY* virtual_ldt = NULL;

/* Define the function pointer type for the callgate registration routine */
typedef uint16_t (CDECL *PFN_wineos2_register_callgate)(const char* mod_name, uint16_t ordinal, uint16_t param_bytes, void* thunk_ptr);
typedef void* (CDECL *PFN_wineos2_get_ldt_ptr)(void);

/* =========================================================================
 * 32-BIT NATIVE CORES (LX Subsystem - Routes directly to Win32 Console API)
 * ========================================================================= */

APIRET CDECL os2_KbdCharIn(PKBDKEYINFO pkbci, USHORT fWait, HKBD hkbd) {
    HANDLE hInput = GetStdHandle(STD_INPUT_HANDLE);
    INPUT_RECORD ir;
    DWORD read;

    if (!pkbci) return 87; 
    memset(pkbci, 0, sizeof(KBDKEYINFO));

    if (fWait == 0) {
        DWORD events = 0;
        GetNumberOfConsoleInputEvents(hInput, &events);
        if (events == 0) return NO_ERROR; 
    }

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
    uint16_t sp_offset = ctx->sp + 4; 
    uint16_t pInfo_sel = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 6);
    uint16_t pInfo_off = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 4);
    uint16_t fWait     = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 2);
    uint16_t hkbd      = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 0);

    KBDKEYINFO* host_info = (KBDKEYINFO*)mode16to32(pInfo_sel, pInfo_off);
    if (!host_info) return 87;

    APIRET rc = os2_KbdCharIn(host_info, fWait, (HKBD)hkbd);
    return (uint16_t)rc; 
}

/* =========================================================================
 * SUBSYSTEM INITIALIZATION - AUTONOMOUS BOOTSTRAP PIPELINE
 * ========================================================================= */

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        HMODULE hCore;
        PFN_wineos2_register_callgate pfnRegister;
        PFN_wineos2_get_ldt_ptr pfnGetLdt;

        DisableThreadLibraryCalls(hinstDLL);

        hCore = GetModuleHandleA(NULL);
        if (!hCore) return FALSE;

        pfnGetLdt = (PFN_wineos2_get_ldt_ptr)GetProcAddress(hCore, "wineos2_get_ldt_ptr");
        if (pfnGetLdt) virtual_ldt = (OS2_LDT_ENTRY*)pfnGetLdt();

        pfnRegister = (PFN_wineos2_register_callgate)GetProcAddress(hCore, "wineos2_register_callgate");
        if (!pfnRegister) return FALSE;

        /* Ordinal 4, Footprint: 2 selectors/pointers (4+4) = 8 bytes */
        pfnRegister("KBDCALLS", 4, 8, os2_Kbd16CharIn);
    }
    return TRUE;
}

