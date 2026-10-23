/*
 *  nls_main.c - OS/2 16/32-bit National Language Support Simulation
 *  (c) Arucard 2026 - Wine-OS/2 Project
 */

#define WIN32_LEAN_AND_MEAN
#define WINEOS2_DLL_MODULE 
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "os2types.h"
#include "wineos2_286cpu.h"

OS2_LDT_ENTRY* virtual_ldt = NULL;

typedef uint16_t (CDECL *PFN_wineos2_register_callgate)(const char* mod_name, uint16_t ordinal, uint16_t param_bytes, void* thunk_ptr);
typedef void* (CDECL *PFN_wineos2_get_ldt_ptr)(void);

/* =========================================================================
 * 32-BIT NATIVE CORES (LX Subsystem - Native NLS Logic)
 * ========================================================================= */

APIRET CDECL os2_DosQueryCollate(ULONG cbBuf, PVOID pCountryCode, PBYTE pBuf, PULONG pActualLen) {
    if (!pBuf || cbBuf < 2) return 87; /* ERROR_INVALID_PARAMETER */

    /* OS/2 a table with 2 bytes for size, thehna 256 bytes table */
    ULONG total_needed = 258;
    if (pActualLen) *pActualLen = total_needed;

    /* Fill the table with head sized (256 bytes = 0x0100) */
    if (cbBuf >= 2) {
        *(uint16_t*)pBuf = 256;
    }

    /* Fill the sequence with ASCII 1:1 */
    for (ULONG i = 0; i < 256 && (i + 2) < cbBuf; i++) {
        pBuf[i + 2] = (BYTE)i;
    }

    return NO_ERROR;
}

APIRET CDECL os2_DosQueryDBCSEnv(ULONG cbBuf, PVOID pCountryCode, PBYTE pBuf) {
    if (!pBuf || cbBuf < 2) return 87;

    /* Two null bytes means the end of DBCS (Single-Byte environment) */
    memset(pBuf, 0, cbBuf >= 12 ? 12 : cbBuf);
    return NO_ERROR;
}

/* =========================================================================
 * 16-BIT EMULATED CORES (NE Subsystem)
 * ========================================================================= */

uint16_t os2_Dos16GetCollate(CPU286_Context* ctx) {
    uint16_t sp_offset = ctx->sp + 4;

    uint16_t cbBuf      = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 12);
    uint16_t ctry_sel   = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 10);
    uint16_t ctry_off   = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 8);
    uint16_t buf_sel    = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 6);
    uint16_t buf_off    = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 4);
    uint16_t len_sel    = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 2);
    uint16_t len_off    = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 0);

    void* host_ctry     = mode16to32(ctry_sel, ctry_off);
    BYTE* host_buf      = (BYTE*)mode16to32(buf_sel, buf_off);
    uint16_t* host_len  = (uint16_t*)mode16to32(len_sel, len_off);

    if (!host_buf || !host_len) return 87;

    ULONG actual32 = 0;
    APIRET rc = os2_DosQueryCollate((ULONG)cbBuf, host_ctry, host_buf, &actual32);
    
    if (rc == NO_ERROR) {
        *host_len = (uint16_t)actual32;
    }
    return (uint16_t)rc;
}

uint16_t os2_Dos16GetDBCSEv(CPU286_Context* ctx) {
    uint16_t sp_offset = ctx->sp + 4;

    uint16_t cbBuf     = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 8);
    uint16_t ctry_sel  = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 6);
    uint16_t ctry_off  = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 4);
    uint16_t buf_sel   = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 2);
    uint16_t buf_off   = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 0);

    void* host_ctry = mode16to32(ctry_sel, ctry_off);
    BYTE* host_buf  = (BYTE*)mode16to32(buf_sel, buf_off);

    if (!host_buf) return 87;

    APIRET rc = os2_DosQueryDBCSEnv((ULONG)cbBuf, host_ctry, host_buf);
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

        /* NLS Ordinals tables */
        pfnRegister("NLS", 2, 14, os2_Dos16GetCollate); /* USHORT(2) + 3*FarPtr(12) = 14 */
        pfnRegister("NLS", 4, 10, os2_Dos16GetDBCSEv);  /* USHORT(2) + 2*FarPtr(8)  = 10 */

        printf("[NLS] Dynamic Callgates allocated sucessfully!\n");
        fflush(stdout);
    }
    return TRUE;
}
