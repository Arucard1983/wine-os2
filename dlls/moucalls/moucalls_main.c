/*
 *  moucalls_main.c - OS/2 16/32-bit Mouse Subsystem Simulation
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
 * 32-BIT NATIVE CORES (LX Subsystem - Raw Bootstrap Mock Layer)
 * ========================================================================= */

APIRET CDECL os2_MouGetPtrPos(PVOID pCursorPos, HMOU hmou) {
    if (!pCursorPos) return 87;
    memset(pCursorPos, 0, 4); 
    return NO_ERROR;
}

/* =========================================================================
 * 16-BIT EMULATED CORES (NE Subsystem - Corrected Stack Offsets & Pascal Cleanup)
 * ========================================================================= */

uint16_t os2_Mou16GetPtrPos(CPU286_Context* ctx) {
    uint16_t sp_offset = ctx->sp + 4; 
    uint16_t pPos_sel;
    uint16_t pPos_off;
    uint16_t hmou;
    void* host_pos;
    APIRET rc;
    
    pPos_sel  = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 4);
    pPos_off  = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 2);
    hmou      = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 0);

    host_pos = mode16to32(pPos_sel, pPos_off);
    if (!host_pos) return 87;

    rc = os2_MouGetPtrPos(host_pos, (HMOU)hmou);
    
    /* FIX: 'ctx->sp += 6' REMOVIDO. Agora é controlado pelo param_bytes da chamada 0x9A do Core! */
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

        /* Ordinal 4. Parâmetros: 1 Far Pointer (4 bytes) + 1 Handle (2 bytes) = 6 bytes */
        pfnRegister("MOUCALLS", 4, 6, os2_Mou16GetPtrPos);

        printf("[Moucalls] Autonomous 16-bit Callgate registration completed via runtime linking.\n");
        fflush(stdout);
    }
    return TRUE;
}
