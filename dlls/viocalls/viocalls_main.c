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

APIRET CDECL os2_VioGetMode(PVIOMODEINFO pvioModeInfo, HVIO hvio) {
    if (hvio != 0) return 1; /* ERROR_VIO_INVALID_HANDLE */
    if (!pvioModeInfo) return 160; /* ERROR_VIO_INVALID_PARMS */

    /* Set compatibility flags by program demand */
    if (pvioModeInfo->cb >= 2)  pvioModeInfo->fbType = 1; /* VGMT_TEXT (Text Code) */
    if (pvioModeInfo->cb >= 3)  pvioModeInfo->color  = 4; /* 16 colors (2^4) */
    if (pvioModeInfo->cb >= 5)  pvioModeInfo->col    = 80;
    if (pvioModeInfo->cb >= 7)  pvioModeInfo->row    = 25;
    
    /* Optional features demanded by cb using LX standards */
    if (pvioModeInfo->cb >= 9)  pvioModeInfo->hres   = 720;
    if (pvioModeInfo->cb >= 11) pvioModeInfo->vres   = 400;

    return NO_ERROR;
}

APIRET CDECL os2_VioQueryFonts(PULONG pcbMetrics, PVIOFONTINFO pVioFontInfo, PVOID pData, ULONG cbData, PULONG pFontID, PSZ pszFontName, HVIO hvio) {
    if (hvio != 0) return 1; /* ERROR_VIO_INVALID_HANDLE */
    
    /* Return 0 additional fonts to avoid subsystem crashes */
    if (pcbMetrics) *pcbMetrics = 0;
    
    return NO_ERROR;
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
    
    pStr_sel  = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 6);
    pStr_off  = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 4);
    cbString  = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 2);
    hvio_val  = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 0);

    host_string = (char*)mode16to32(pStr_sel, pStr_off);
    if (!host_string) return 87; /* ERROR_INVALID_PARAMETER */

    rc = os2_VioWrtTTY(host_string, (ULONG)cbString, (HVIO)hvia_val);
    
    return (uint16_t)rc;
}

uint16_t os2_Vio16GetMode(CPU286_Context* ctx) {
    uint16_t sp_offset = ctx->sp + 4;
    uint16_t pMode_sel, pMode_off;
    uint16_t hvio_val;
    void* host_struct;
    VIOMODEINFO mode32;
    APIRET rc;

    pMode_sel = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 2);
    pMode_off = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 0);
    hvio_val  = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 4); /* Pascal order */

    host_struct = mode16to32(pMode_sel, pMode_off);
    if (!host_struct) return 160; /* ERROR_VIO_INVALID_PARMS */

    /* Read cb defined by the 16-bit application */
    mode32.cb = *(uint16_t*)host_struct;
    
    rc = os2_VioGetMode(&mode32, (HVIO)hvio_val);
    if (rc == NO_ERROR) {
        /* Make Marshalling back from 32-bits to 16-bits */
        memcpy(host_struct, &mode32, mode32.cb > 14 ? 14 : mode32.cb); 
    }

    return (uint16_t)rc;
}

uint16_t os2_Vio16QueryFonts(CPU286_Context* ctx) {
    uint16_t sp_offset = ctx->sp + 4;
    uint16_t pMetrics_sel, pMetrics_off;
    uint32_t* host_metrics;
    ULONG metrics32 = 0;

    /* Using Pascal mapping, the first argument (pcbMetrics) is at higher offset */
    /* Total number of bytes by this calls = 22 bytes */
    pMetrics_sel = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 20);
    pMetrics_off = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 18);

    host_metrics = (uint32_t*)mode16to32(pMetrics_sel, pMetrics_off);
    
    /* Calling the 32-bit functionwith minimum effort */
    APIRET rc = os2_VioQueryFonts(&metrics32, NULL, NULL, 0, NULL, NULL, 0);
    
    if (rc == NO_ERROR && host_metrics) {
        *host_metrics = (uint32_t)metrics32;
    }

    return (uint16_t)rc;
}


====================================================================
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

        /* Ordinal 19 (Vio16WrtTTY): FarPtr(4) + USHORT(2) + USHORT(2) = 8 bytes */
        pfnRegister("VIOCALLS", 19, 8, os2_Vio16WrtTTY);

        /* Ordinal 21 (Vio16GetMode): FarPtr(4) + USHORT(2) = 6 bytes */
        pfnRegister("VIOCALLS", 21, 6, os2_Vio16GetMode);

        /* Ordinal 64 (Vio16QueryFonts): FarPtr(4)*4 + ULONG(4) + USHORT(2) = 22 bytes */
        pfnRegister("VIOCALLS", 64, 22, os2_Vio16QueryFonts);

        printf("[Viocalls] Autonomous 16-bit Callgate registration completed via runtime linking.\n");
        fflush(stdout);
    }
    return TRUE;
}
