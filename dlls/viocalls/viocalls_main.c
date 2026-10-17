/*
 *  viocalls_main.c - OS/2 16/32-bit Video Subsystem Simulation
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

APIRET CDECL os2_VioWrtTTY(PCH pchString, ULONG cbString, HVIO hvio) {
    DWORD bytesWritten;
    if (!pchString || cbString == 0) return NO_ERROR;

    if (WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), pchString, cbString, &bytesWritten, NULL)) {
        return NO_ERROR;
    }
    return ERROR_VIO_INVALID_HANDLE;
}

/* =========================================================================
 * 16-BIT EMULATED CORES (NE Subsystem - Corrected Stack Offsets & Pascal Cleanup)
 * ========================================================================= */

uint16_t os2_Vio16WrtTTY(CPU286_Context* ctx) {
    uint16_t sp_offset = ctx->sp + 4; 
    uint16_t cbString;
    uint16_t pStr_sel;
    uint16_t pStr_off;
    uint16_t hvia_val;
    char* host_string;
    APIRET rc;
    
    cbString  = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 6);
    pStr_sel  = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 4);
    pStr_off  = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 2);
    hvia_val  = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 0);

    host_string = (char*)mode16to32(pStr_sel, pStr_off);
    if (!host_string) return 87;

    rc = os2_VioWrtTTY(host_string, (ULONG)cbString, (HVIO)hvia_val);
    
    /* FIX: 'ctx->sp += 8' REMOVIDO. Agora delegado centralizadamente ao executável através do param_bytes! */
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

        /* Ordinal 5. Parâmetros: cbString (2) + Far Pointer String (4) + Handle (2) = 8 bytes */
        pfnRegister("VIOCALLS", 5, 8, os2_Vio16WrtTTY);

        printf("[Viocalls] Autonomous 16-bit Callgate registration completed via runtime linking.\n");
        fflush(stdout);
    }
    return TRUE;
}
