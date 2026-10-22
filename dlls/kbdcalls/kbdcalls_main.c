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

APIRET CDECL os2_KbdCharIn(PKBDKEYINFO pkbci, ULONG fWait, HKBD hkbd) {
    HANDLE hInput = GetStdHandle(STD_INPUT_HANDLE);
    INPUT_RECORD ir;
    DWORD read;

    if (hkbd != 0) return 439; /* ERROR_KBD_INVALID_HANDLE */
    if (!pkbci) return 87;     /* ERROR_INVALID_PARAMETER */
    
    memset(pkbci, 0, sizeof(KBDKEYINFO));

    if (fWait == 0) { /* IO_NOWAIT */
        DWORD events = 0;
        GetNumberOfConsoleInputEvents(hInput, &events);
        if (events == 0) return NO_ERROR; 
    }

    while (ReadConsoleInputA(hInput, &ir, 1, &read) && read > 0) {
        if (ir.EventType == KEY_EVENT && ir.Event.KeyEvent.bKeyDown) {
            pkbci->chChar = ir.Event.KeyEvent.uChar.AsciiChar;
            pkbci->chScan = ir.Event.KeyEvent.wVirtualScanCode;
            pkbci->time   = GetTickCount();
            /* mapping Shift/Ctrl/Alt status when needed */
            if (ir.Event.KeyEvent.dwControlKeyState & SHIFT_PRESSED) pkbci->fsState |= 0x0002;
            return NO_ERROR;
        }
    }
    return NO_ERROR;
}

APIRET CDECL os2_KbdStringIn(PCH pchBuffer, PSTRINGINBUF pStringInBuf, ULONG fWait, HKBD hkbd) {
    DWORD read = 0;
    if (hkbd != 0) return 439;
    if (!pchBuffer || !pStringInBuf || pStringInBuf->cb == 0) return 87;

    if (fWait == 0) {
        DWORD events = 0;
        GetNumberOfConsoleInputEvents(GetStdHandle(STD_INPUT_HANDLE), &events);
        if (events == 0) {
            pStringInBuf->cchIn = 0;
            return NO_ERROR;
        }
    }

    /* Using Win32 Console as the best option */
    if (ReadConsoleA(GetStdHandle(STD_INPUT_HANDLE), pchBuffer, pStringInBuf->cb, &read, NULL)) {
        pStringInBuf->cchIn = (USHORT)read;
        return NO_ERROR;
    }
    return 444; /* ERROR_KBD_CANNOT_READ */
}

APIRET CDECL os2_KbdSetStatus(PKBDSTATUS pkbdst, HKBD hkbd) {
    if (hkbd != 0) return 439;
    if (!pkbdst) return 87;
    /* Default init is always true */
    return NO_ERROR;
}

APIRET CDECL os2_KbdGetStatus(PKBDSTATUS pkbdst, HKBD hkbd) {
    if (hkbd != 0) return 439;
    if (!pkbdst) return 87;

    memset(pkbdst, 0, sizeof(KBDSTATUS));
    pkbdst->cb = sizeof(KBDSTATUS);
    pkbdst->fsMask = 0x0001; /* Echo on */
    return NO_ERROR;
}

APIRET CDECL os2_KbdFlushBuffer(HKBD hkbd) {
    if (hkbd != 0) return 439;
    if (FlushConsoleInputBuffer(GetStdHandle(STD_INPUT_HANDLE))) {
        return NO_ERROR;
    }
    return 444;
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

    APIRET rc = os2_KbdCharIn(host_info, (ULONG)fWait, (HKBD)hkbd);
    return (uint16_t)rc; 
}

uint16_t os2_Kbd16StringIn(CPU286_Context* ctx) {
    uint16_t sp_offset = ctx->sp + 4;
    uint16_t pStr_sel  = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 10);
    uint16_t pStr_off  = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 8);
    uint16_t pBuf_sel  = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 6);
    uint16_t pBuf_off  = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 4);
    uint16_t fWait     = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 2);
    uint16_t hkbd      = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 0);

    char* host_str = (char*)mode16to32(pStr_sel, pStr_off);
    STRINGINBUF* host_buf = (STRINGINBUF*)mode16to32(pBuf_sel, pBuf_off);
    if (!host_str || !host_buf) return 87;

    APIRET rc = os2_KbdStringIn(host_str, host_buf, (ULONG)fWait, (HKBD)hkbd);
    return (uint16_t)rc;
}

uint16_t os2_Kbd16SetStatus(CPU286_Context* ctx) {
    uint16_t sp_offset = ctx->sp + 4;
    uint16_t pStat_sel = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 4);
    uint16_t pStat_off = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 2);
    uint16_t hkbd      = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 0);

    KBDSTATUS* host_stat = (KBDSTATUS*)mode16to32(pStat_sel, pStat_off);
    if (!host_stat) return 87;

    APIRET rc = os2_KbdSetStatus(host_stat, (HKBD)hkbd);
    return (uint16_t)rc;
}

uint16_t os2_Kbd16GetStatus(CPU286_Context* ctx) {
    uint16_t sp_offset = ctx->sp + 4;
    uint16_t pStat_sel = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 4);
    uint16_t pStat_off = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 2);
    uint16_t hkbd      = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 0);

    KBDSTATUS* host_stat = (KBDSTATUS*)mode16to32(pStat_sel, pStat_off);
    if (!host_stat) return 87;

    APIRET rc = os2_KbdGetStatus(host_stat, (HKBD)hkbd);
    return (uint16_t)rc;
}

uint16_t os2_Kbd16FlushBuffer(CPU286_Context* ctx) {
    uint16_t sp_offset = ctx->sp + 4;
    uint16_t hkbd      = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 0);

    APIRET rc = os2_KbdFlushBuffer((HKBD)hkbd);
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

         pfnRegister("KBDCALLS", 4,  8,  os2_Kbd16CharIn);      /* Ptr(4) + USHORT(2) + USHORT(2) */
        pfnRegister("KBDCALLS", 9,  12, os2_Kbd16StringIn);    /* Ptr(4) + Ptr(4) + USHORT(2) + USHORT(2) */
        pfnRegister("KBDCALLS", 19, 6,  os2_Kbd16SetStatus);   /* Ptr(4) + USHORT(2) */
        pfnRegister("KBDCALLS", 29, 6,  os2_Kbd16GetStatus);   /* Ptr(4) + USHORT(2) */
        pfnRegister("KBDCALLS", 42, 2,  os2_Kbd16FlushBuffer); /* USHORT(2) */

    }
    return TRUE;
}

