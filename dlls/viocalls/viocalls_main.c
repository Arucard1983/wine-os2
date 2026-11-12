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

APIRET CDECL os2_VioQueryFonts(PULONG plRemfonts, PVIOFONTCELLSIZE pMetrics, ULONG lMetricsLength, PULONG plFonts, PSZ pszFacename, ULONG flOptions, HVPS hvps) {
    /* On AVIO, hvps can be a valid handle for != 0; for simple VIO, 0 is default */
    if (hvps != 0) {
        return ERROR_VIO_INVALID_HANDLE;
    }

    /* Case 1: Program is asking how many fonts exists (pMetrics == NULL ou *plFonts == 0) */
    if (pMetrics == NULL || plFonts == NULL || *plFonts == 0 || lMetricsLength < sizeof(VIOFONTCELLSIZE)) {
        if (plRemfonts) {
            *plRemfonts = 1; /* Report a single standard font (8x16) */
        }
        if (plFonts) {
            *plFonts = 0;    /* No standard font copied over */
        }
        return NO_ERROR;
    }

    /* Case 2: Program gets a buffer to receive the matrix cell size. */
    pMetrics[0].cx = 8;   /* Largura da célula: 8 píxeis */
    pMetrics[0].cy = 16;  /* Altura da célula: 16 píxeis */

    if (plFonts) {
        *plFonts = 1;     /* 1 struct filled */
    }
    if (plRemfonts) {
        *plRemfonts = 0;  /* No more fonts to read */
    }

    return NO_ERROR;
}

/* =========================================================================
 * 16-BIT EMULATED CORES (NE Subsystem - Corrected Stack Offsets & Pascal Cleanup)
 * ========================================================================= */

uint16_t os2_Vio16WrtTTY(CPU286_Context* ctx) {
    uint16_t cbString;
    uint16_t pStr_sel;
    uint16_t pStr_off;
    uint16_t hvio_val;
    char* host_string;
    APIRET rc;
    
    pStr_sel  = *(uint16_t*)mode16to32(ctx->ss, ctx->sp + 6);
    pStr_off  = *(uint16_t*)mode16to32(ctx->ss, ctx->sp + 4);
    cbString  = *(uint16_t*)mode16to32(ctx->ss, ctx->sp + 2);
    hvio_val  = *(uint16_t*)mode16to32(ctx->ss, ctx->sp + 0);

    host_string = (char*)mode16to32(pStr_sel, pStr_off);
    if (!host_string) return 87; /* ERROR_INVALID_PARAMETER */

    rc = os2_VioWrtTTY(host_string, (ULONG)cbString, (HVIO)hvio_val);
    
    return (uint16_t)rc;
}

uint16_t os2_Vio16GetMode(CPU286_Context* ctx) {
    uint16_t pMode_sel, pMode_off;
    uint16_t hvio_val;
    void* host_struct;
    VIOMODEINFO mode32;
    APIRET rc;

    pMode_sel = *(uint16_t*)mode16to32(ctx->ss, ctx->sp + 2);
    pMode_off = *(uint16_t*)mode16to32(ctx->ss, ctx->sp + 0);
    hvio_val  = *(uint16_t*)mode16to32(ctx->ss, ctx->sp + 4); /* Pascal order */

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
   
    /* Using Pascal mapping, the first argument (pcbMetrics) is at higher offset */
    /* Total number of bytes by this calls = 22 bytes */
    uint16_t plRemfonts_off = *(uint16_t*)mode16to32(ctx->ss, ctx->sp + 22);
    uint16_t plRemfonts_sel = *(uint16_t*)mode16to32(ctx->ss, ctx->sp + 24);

    uint16_t pMetrics_off   = *(uint16_t*)mode16to32(ctx->ss, ctx->sp + 18);
    uint16_t pMetrics_sel   = *(uint16_t*)mode16to32(ctx->ss, ctx->sp + 20);

    uint32_t lMetricsLength = *(uint32_t*)mode16to32(ctx->ss, ctx->sp + 14);

    uint16_t plFonts_off    = *(uint16_t*)mode16to32(ctx->ss, ctx->sp + 10);
    uint16_t plFonts_sel    = *(uint16_t*)mode16to32(ctx->ss, ctx->sp + 12);

    uint16_t pszFace_off    = *(uint16_t*)mode16to32(ctx->ss, ctx->sp + 6);
    uint16_t pszFace_sel    = *(uint16_t*)mode16to32(ctx->ss, ctx->sp + 8);

    uint32_t flOptions      = *(uint32_t*)mode16to32(ctx->ss, ctx->sp + 2);
    uint16_t hvps           = *(uint16_t*)mode16to32(ctx->ss, ctx->sp + 0);


    ULONG*            host_plRemfonts = plRemfonts_sel ? (ULONG*)mode16to32(plRemfonts_sel, plRemfonts_off) : NULL;
    PVIOFONTCELLSIZE  host_pMetrics   = (pMetrics_sel && lMetricsLength > 0) ? (PVIOFONTCELLSIZE)mode16to32(pMetrics_sel, pMetrics_off) : NULL;
    ULONG*            host_plFonts    = plFonts_sel ? (ULONG*)mode16to32(plFonts_sel, plFonts_off) : NULL;
    PSZ               host_pszFace    = pszFace_sel ? (PSZ)mode16to32(pszFace_sel, pszFace_off) : NULL;

    ULONG remFonts32 = 0;
    ULONG numFonts32 = host_plFonts ? *host_plFonts : 0;

    APIRET rc = os2_VioQueryFonts(
        host_plRemfonts ? &remFonts32 : NULL,
        host_pMetrics,
        lMetricsLength,
        host_plFonts ? &numFonts32 : NULL,
        host_pszFace,
        flOptions,
        (HVPS)hvps
    );

    if (rc == NO_ERROR) {
        if (host_plRemfonts) *host_plRemfonts = remFonts32;
        if (host_plFonts)    *host_plFonts    = numFonts32;
    }

    return (uint16_t)rc;
}


/*====================================================================
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

        /* Ordinal 64 (Vio16QueryFonts): FarPtr(4)*4 + ULONG(4)*2 + USHORT(2) = 26 bytes */
        pfnRegister("VIOCALLS", 64, 26, os2_Vio16QueryFonts);

        printf("[Viocalls] Autonomous 16-bit Callgate registration completed via runtime linking.\n");
        fflush(stdout);
    }
    return TRUE;
}
