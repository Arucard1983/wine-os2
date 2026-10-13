/*
 *  moucalls_main.c - OS/2 16/32-bit Mouse Subsystem Simulation
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
 * 32-BIT NATIVE CORES (LX Subsystem - Raw Bootstrap Mock Layer)
 * ========================================================================= */

APIRET CDECL os2_MouGetPtrPos(PVOID pCursorPos, HMOU hmou) {
    if (!pCursorPos) return 87;

    /* Returns a safe mock tracking coordinate for basic headless runtime initializations */
    memset(pCursorPos, 0, 4); /* Force x=0, y=0 coordinates layout boundaries */
    return NO_ERROR;
}

/* =========================================================================
 * 16-BIT EMULATED CORES (NE Subsystem - Corrected Stack Offsets & Pascal Cleanup)
 * ========================================================================= */

uint16_t os2_Mou16GetPtrPos(CPU286_Context* ctx) {
    uint16_t sp_offset = ctx->sp + 4; /* Skip 4 bytes of Far CS:IP return address */
    
    /* Pascal order: Unpacking parameters from highest stack coordinate to lowest */
    uint16_t pPos_sel  = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 4);
    uint16_t pPos_off  = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 2);
    uint16_t hmou      = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 0);

    void* host_pos = mode16to32(pPos_sel, pPos_off);
    if (!host_pos) {
        ctx->sp += 6; /* Clean up 3 parameters of 2 bytes each */
        return 87;
    }

    APIRET rc = os2_MouGetPtrPos(host_pos, (HMOU)hmou);
    
    ctx->sp += 6; /* Pascal convention callee stack cleanup */
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
         * Ordinal 4 maps to MouGetPtrPos under standard IBM specification rules.
         */
        wineos2_register_callgate("MOUCALLS", 4, os2_Mou16GetPtrPos);

        printf("[Moucalls] Autonomous 16-bit Callgate registration completed via wineos2 engine.\n");
        fflush(stdout);
    }
    return TRUE;
}
