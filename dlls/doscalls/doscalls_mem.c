/*
 *  dos_mem.c - OS/2 LDT & Flat Memory Segment Management
 *  (c) Arucard 2026 - Wine-OS/2 Project
 */

#define WIN32_LEAN_AND_MEAN
#define WINEOS2_DLL_MODULE
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

#include "os2types.h"
#include "wineos2_286cpu.h"

/* Shared from doscalls_main.c */
extern OS2_LDT_ENTRY* virtual_ldt;

/* =========================================================================
 * 32-BIT NATIVE CORES (LX Subsystem Memory Management)
 * ========================================================================= */

APIRET CDECL os2_DosAllocMem(PVOID *ppBaseAddress, ULONG cbSize, ULONG ulFlags, PVOID pParam4, PVOID pParam5, PVOID pParam6) {
    DWORD protect = PAGE_READWRITE;
    void* alloc_ptr;

    if (!ppBaseAddress || cbSize == 0) return 87; /* ERROR_INVALID_PARAMETER */

    if (ulFlags & 0x00000010) protect = PAGE_EXECUTE_READWRITE; /* OBJ_EXECUTE */

    /* Linear memory allocation for 32-bits LX*/
    alloc_ptr = VirtualAlloc(NULL, cbSize, MEM_COMMIT | MEM_RESERVE, protect);
    if (!alloc_ptr) return 8; /* ERROR_NOT_ENOUGH_MEMORY */

    *ppBaseAddress = alloc_ptr;
    return NO_ERROR;
}

/* =========================================================================
 * 16-BIT EMULATED CORES (NE Subsystem LDT Marshalling)
 * ========================================================================= */

/* Local helper to find a free LDT selector */
static uint16_t allocate_ldt_entry(void* linear_address, ULONG size) {
    if (!virtual_ldt) return 0;

    /* Scan the virtual LDT until find a free one (Ignore the first 16 for safety which is the first virtual megabyte of memory) */
    for (int i = 16; i < 8192; i++) {
        if (virtual_ldt[i].BaseLow == 0 && virtual_ldt[i].LimitLow == 0) {
            uintptr_t addr = (uintptr_t)linear_address;
            
            /* Configure the 16-bits data selector (Protected Mode x86) */
            virtual_ldt[i].BaseLow     = addr & 0xFFFF;
            virtual_ldt[i].BaseMid     = (addr >> 16) & 0xFF;
            virtual_ldt[i].BaseHigh    = (addr >> 24) & 0xFF;
            
            ULONG limit = size - 1;
            virtual_ldt[i].LimitLow    = limit & 0xFFFF;
            virtual_ldt[i].Flags       = 0x0093; /* Data Segment Prsent, Read/Write, DPL=3 */

            /* Transform the index to a valid LDT selector (TI=1, RPL=3) */
            return (uint16_t)((i << 3) | 0x0007);
        }
    }
    return 0;
}

uint16_t os2_Dos16Allocseg(CPU286_Context* ctx) {
    uint16_t sp_offset = ctx->sp + 4;
    
    uint16_t cbSize   = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 6);
    uint16_t pSel_sel = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 4);
    uint16_t pSel_off = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 2);
    uint16_t fsAlloc  = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 0);

    uint16_t* host_selector = (uint16_t*)mode16to32(pSel_sel, pSel_off);
    ULONG real_size = (cbSize == 0) ? 65536 : cbSize; /* 0 means complete 64KB block */
    void* heap_alloc;
    uint16_t selector;

    if (!host_selector) return 87;

    /* Allocate virtual linear memory for the Wine process */
    heap_alloc = VirtualAlloc(NULL, real_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!heap_alloc) return 8; /* ERROR_NOT_ENOUGH_MEMORY */

    /* Set the link between the hot pointer and the simulated LDT from 16-bits x86 */
    selector = allocate_ldt_entry(heap_alloc, real_size);
    if (selector == 0) {
        VirtualFree(heap_alloc, 0, MEM_RELEASE);
        return 8;
    }

    *host_selector = selector;
    return 0; /* NO_ERROR */
}

uint16_t os2_Dos16ReAllocseg(CPU286_Context* ctx) {
    uint16_t sp_offset = ctx->sp + 4;
    uint16_t cbNewSize = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 2);
    uint16_t selector  = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 0);

    uint16_t ldt_index = selector >> 3;
    if (!virtual_ldt || ldt_index >= 8192) return 5; /* ERROR_ACCESS_DENIED */

    /* Extract the linear memory adress to the LDT */
    uintptr_t current_addr = virtual_ldt[ldt_index].BaseLow | 
                             (virtual_ldt[ldt_index].BaseMid << 16) | 
                             (virtual_ldt[ldt_index].BaseHigh << 24);
    
    ULONG new_size = (cbNewSize == 0) ? 65536 : cbNewSize;

    /* Set the selector size to the memory allocation */
    void* realloc_ptr = VirtualAlloc((void*)current_addr, new_size, MEM_COMMIT, PAGE_READWRITE);
    if (!realloc_ptr) return 8;

    /* Update the upper limit of segment */
    ULONG limit = new_size - 1;
    virtual_ldt[ldt_index].LimitLow = limit & 0xFFFF;

    return 0;
}
