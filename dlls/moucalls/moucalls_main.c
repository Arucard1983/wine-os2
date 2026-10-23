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

APIRET CDECL os2_MouGetNumButtons(PVOID pResult, HMOU hmou) {
    PUSHORT pButtons = (PUSHORT)pResult;
    
    if (hmou != 0) return 466; /* ERROR_MOU_INVALID_HANDLE */
    if (!pButtons) return 87;  /* ERROR_INVALID_PARAMETER */

    /* GetSystemMetrics returns the number of buttons from the host */
    *pButtons = (USHORT)GetSystemMetrics(SM_CMOUSEBUTTONS);

    /* To avoid an OS/2 hard failure, the absence of a mouse will place a fake one with two buttons */
    if (*pButtons == 0) {
        *pButtons = 2; 
    }

    return NO_ERROR;
}


APIRET CDECL os2_MouGetPtrPos(PVOID pCursorPos, HMOU hmou) {
    PPTRLOC pLoc = (PPTRLOC)pCursorPos;

    if (hmou != 0) return 466; /* ERROR_MOU_INVALID_HANDLE */
    if (!pLoc) return 87;      /* ERROR_INVALID_PARAMETER */

    /* Mapeamento de Coordenadas: Simula o rato no canto superior esquerdo (0,0) 
     * Podes futuramente ler via GetConsoleCursorInfo / GetCursorPos do Wine */
    pLoc->row = 0;
    pLoc->col = 0;

    return NO_ERROR;
}

/* =========================================================================
 * 16-BIT EMULATED CORES (NE Subsystem - Corrected Stack Offsets & Pascal Cleanup)
 * ========================================================================= */

uint16_t os2_Mou16GetNumButtons(CPU286_Context* ctx) {
    /* 16-bit Pascal stack with the following:
     * [SS:SP + 4] -> Selector of Far Pointer (pResult)
     * [SS:SP + 2] -> Offset of Far Pointer (pResult)
     * [SS:SP + 0] -> Handle og Rato (hmou)
     */
    uint16_t sp_offset = ctx->sp + 4; 
    uint16_t pResult_sel;
    uint16_t pResult_off;
    uint16_t hmou;
    void* host_ptr;
    APIRET rc;

    /* Extract the parameters from the emulated stack */
    pResult_sel = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 4);
    pResult_off = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 2);
    hmou        = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 0);

    /* Convert the segment stack to a linear space of 32-bits */
    host_ptr = mode16to32(pResult_sel, pResult_off);
    if (!host_ptr) {
        return 87; /* ERROR_INVALID_PARAMETER */
    }

    /* Call the native function */
    rc = os2_MouGetNumButtons(host_ptr, (HMOU)hmou);

    /* The DllMain will clear the 6 bytes of stack (Far Ptr = 4 bytes + Handle = 2 bytes) */
    return (uint16_t)rc;
}



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
    
    /* FIX: The stack is cleared by the emulator using the core parameters */
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

        /* Ordinal 4. Parameters: 1 Far Pointer (4 bytes) + 1 Handle (2 bytes) = 6 bytes */
        pfnRegister("MOUCALLS", 7, 6, os2_Mou16GetPtrPos);
        pfnRegister("MOUCALLS", 15, 6, os2_Mou16GetNumButtons);

        printf("[Moucalls] Autonomous 16-bit Callgate registration completed via runtime linking.\n");
        fflush(stdout);
    }
    return TRUE;
}
