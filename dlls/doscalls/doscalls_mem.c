/*
*  doscalls_mem.c - OS/2 LDT & Flat Memory Segment Management via NTDLL
*  (c) Arucard 2026 - Wine-OS/2 Project
*/

#define WIN32_LEAN_AND_MEAN
#define WINEOS2_DLL_MODULE
#include <windows.h>
#include <winternl.h>
#include <ntstatus.h>
#include <stdio.h>
#include <stdlib.h>

#include "os2types.h"
#include "wineos2_286cpu.h"

/* Shared selector base from doscalls_main.c initialization sequence */
extern OS2_LDT_ENTRY* virtual_ldt;


/* =========================================================================
 * 32-BIT NATIVE CORES (LX Subsystem Memory Management - Pure NTDLL)
 * ========================================================================= */

APIRET CDECL os2_DosAllocMem(PVOID *ppBaseAddress, ULONG cbSize, ULONG ulFlags, PVOID pParam4, PVOID pParam5, PVOID pParam6) {
    ULONG protect = PAGE_READWRITE;
    SIZE_T region_size = cbSize;
    NTSTATUS status;

    if (!ppBaseAddress || cbSize == 0) return 87; /* ERROR_INVALID_PARAMETER */

        /* Map OS/2 memory execution right attributes */
        if (ulFlags & 0x00000010) protect = PAGE_EXECUTE_READWRITE; /* OBJ_EXECUTE tracking flag */

            *ppBaseAddress = NULL;

    /* Execute native low-level allocation bypassing KERNEL32 allocation wrappers */
    status = NtAllocateVirtualMemory(NtCurrentProcess(),
                                     ppBaseAddress,
                                     0,
                                     &region_size,
                                     MEM_COMMIT | MEM_RESERVE,
                                     protect);

    if (status != STATUS_SUCCESS) {
        return 8; /* ERROR_NOT_ENOUGH_MEMORY */
    }

    return NO_ERROR;
}

/* =========================================================================
 * 16-BIT EMULATED CORES (NE Subsystem LDT Marshalling - Pure NTDLL)
 * ========================================================================= */

/* Local helper to scan and claim an available dynamic LDT selector slot */
static uint16_t allocate_ldt_entry(void* linear_address, ULONG size) {
    int i;
    if (!virtual_ldt) return 0;

    /* Scan virtual LDT table. Skip the first 16 indexes to preserve real-mode vector maps safely */
    for (i = 16; i < 8192; i++) {
        /* FIX: Switched to matching flat 'base' and 'limit' fields from canonical 2026 header */
        if (virtual_ldt[i].base == 0 && virtual_ldt[i].limit == 0) {
            /* Configure the descriptor block tracking rules matching your 286 CPU emulator layout */
            virtual_ldt[i].base       = (uint32_t)(uintptr_t)linear_address;
            virtual_ldt[i].limit      = (uint32_t)(size - 1);
            virtual_ldt[i].present    = 1;
            virtual_ldt[i].type       = LDT_TYPE_SEGMENT;

            /* Transform index allocation integer to valid protected descriptor format (TI=1, RPL=3) */
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
    ULONG real_size = (cbSize == 0) ? 65536 : cbSize; /* 0 parameters default to full 64KB blocks */
    PVOID heap_alloc = NULL;
    SIZE_T region_size = real_size;
    uint16_t selector;
    NTSTATUS status;

    if (!host_selector) return 87;

    /* Secure the architecture virtual range layout space natively via NT subsystems directly */
    status = NtAllocateVirtualMemory(NtCurrentProcess(),
                                     &heap_alloc,
                                     0,
                                     &region_size,
                                     MEM_COMMIT | MEM_RESERVE,
                                     PAGE_READWRITE);

    if (status != STATUS_SUCCESS) return 8; /* ERROR_NOT_ENOUGH_MEMORY */

        /* Bind host address to virtual 16-bit x86 execution structures */
        selector = allocate_ldt_entry(heap_alloc, real_size);
    if (selector == 0) {
        region_size = 0;
        NtFreeVirtualMemory(NtCurrentProcess(), &heap_alloc, &region_size, MEM_RELEASE);
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

    /* FIX: Mixed declarations fix - moved all local variables to top of block block for C90 compliance */
    uintptr_t current_addr;
    ULONG new_size;
    PVOID realloc_ptr;
    SIZE_T region_size;
    NTSTATUS status;

    if (!virtual_ldt || ldt_index >= 8192) return 5; /* ERROR_ACCESS_DENIED */

        /* FIX: Extract the linear memory address correctly using the canonical 2026 'base' field layout */
        current_addr = (uintptr_t)virtual_ldt[ldt_index].base;
    new_size = (cbNewSize == 0) ? 65536 : cbNewSize;
    realloc_ptr = (PVOID)current_addr;
    region_size = new_size;

    /* Commit extended visibility page limits boundaries natively on the process context architecture */
    status = NtAllocateVirtualMemory(NtCurrentProcess(),
                                     &realloc_ptr,
                                     0,
                                     &region_size,
                                     MEM_COMMIT,
                                     PAGE_READWRITE);

    if (status != STATUS_SUCCESS) return 8;

    /* FIX: Updated the limit correctly using the canonical 2026 'limit' structure field */
    virtual_ldt[ldt_index].limit = (uint32_t)(new_size - 1);

    return 0;
}

