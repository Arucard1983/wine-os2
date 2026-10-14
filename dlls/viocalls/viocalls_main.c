/*
 *  viocalls_main.c - OS/2 16/32-bit Video Subsystem Simulation
 *  (c) Arucard 2026 - Wine-OS/2 Project
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

#include "os2types.h"
#include "wineos2_286cpu.h"

/* Define the function pointer type for the callgate registration routine */
typedef uint16_t (CDECL *PFN_wineos2_register_callgate)(const char* mod_name, uint16_t ordinal, void* thunk_ptr);

/* =========================================================================
 * 32-BIT NATIVE CORES (LX Subsystem - Routes directly to Win32 Console API)
 * ========================================================================= */

APIRET CDECL os2_VioWrtTTY(PCH pchString, ULONG cbString, HVIO hvio) {
    DWORD bytesWritten;
    
    if (!pchString || cbString == 0) return NO_ERROR;

    /* Write directly into the active Win32 standard output device stream */
    if (WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), pchString, cbString, &bytesWritten, NULL)) {
        return NO_ERROR;
    }
    return ERROR_VIO_INVALID_HANDLE;
}

/* =========================================================================
 * 16-BIT EMULATED CORES (NE Subsystem - Corrected Stack Offsets & Pascal Cleanup)
 * ========================================================================= */

uint16_t os2_Vio16WrtTTY(CPU286_Context* ctx) {
    uint16_t sp_offset = ctx->sp + 4; /* Skip 4 bytes of Far CS:IP return address */
    uint16_t cbString;
    uint16_t pStr_sel;
    uint16_t pStr_off;
    uint16_t hvia_val;
    char* host_string;
    APIRET rc;
    
    /* Pascal order: Unpacking parameters from highest stack coordinate to lowest */
    cbString  = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 6);
    pStr_sel  = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 4);
    pStr_off  = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 2);
    hvia_val  = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 0);

    host_string = (char*)mode16to32(pStr_sel, pStr_off);
    if (!host_string) {
        ctx->sp += 8; /* Clean up 4 parameters of 2 bytes each */
        return 87; /* ERROR_INVALID_PARAMETER */
    }

    rc = os2_VioWrtTTY(host_string, (ULONG)cbString, (HVIO)hvia_val);
    
    ctx->sp += 8; /* Pascal convention callee stack cleanup */
    return (uint16_t)rc;
}

/* =========================================================================
 * SUBSYSTEM INITIALIZATION - AUTONOMOUS BOOTSTRAP PIPELINE
 * ========================================================================= */

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        HMODULE hCore;
        PFN_wineos2_register_callgate pfnRegister;

        DisableThreadLibraryCalls(hinstDLL);

        /* Dynamically look up the master engine core executable image */
        hCore = GetModuleHandleA(NULL);
        if (!hCore) return FALSE;

        pfnRegister = (PFN_wineos2_register_callgate)GetProcAddress(hCore, "wineos2_register_callgate");
        if (!pfnRegister) {
            printf("[VIOCALLS] Error: Could not resolve wineos2_register_callgate dynamically.\n");
            fflush(stdout);
            return FALSE;
        }

        /* 
         * Registers its own historical 16-bit execution Call Gate 
         * inside the centralized master wineos2 LDT structure.
         * Ordinal 5 maps to VioWrtTTY under standard IBM specification rules.
         */
        pfnRegister("VIOCALLS", 5, os2_Vio16WrtTTY);

        printf("[Viocalls] Autonomous 16-bit Callgate registration completed via runtime linking.\n");
        fflush(stdout);
    }
    return TRUE;
}

