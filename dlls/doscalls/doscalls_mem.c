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

/* 32-bits OS/2 flags for DosAllocMem (ulFlags) */
#define OS2_PAG_READ      0x00000001  /* Read Permission */
#define OS2_PAG_WRITE     0x00000002  /* Write Permission */
#define OS2_PAG_EXECUTE   0x00000004  /* Execution Permission */
#define OS2_PAG_GUARD     0x00000008  /* Guard Page (Stack guard pages) */
#define OS2_OBJ_TILE      0x00000010  /* 16-bit compatible mapping (LDT) */
#define OS2_PAG_COMMIT    0x00000010  /* On some version share bit or set 0x10 */

/* LX call */
APIRET APIENTRY os2_DosAllocMem(PVOID *ppBaseAddress, ULONG cbSize, ULONG ulFlags) {
    ULONG protect = PAGE_NOACCESS;
    SIZE_T region_size = cbSize;
    NTSTATUS status;
    PVOID allocation_address = NULL;

    if (!ppBaseAddress || cbSize == 0) {
        return 87; /* ERROR_INVALID_PARAMETER */
    }

    /* 1. Mapping memory permission of OS/2 for Windows NT */
    if (ulFlags & OS2_PAG_EXECUTE) {
        if (ulFlags & OS2_PAG_WRITE)      protect = PAGE_EXECUTE_READWRITE;
        else if (ulFlags & OS2_PAG_READ) protect = PAGE_EXECUTE_READ;
        else                              protect = PAGE_EXECUTE;
    } else {
        if (ulFlags & OS2_PAG_WRITE)      protect = PAGE_READWRITE;
        else if (ulFlags & OS2_PAG_READ) protect = PAGE_READONLY;
        else                              protect = PAGE_NOACCESS;
    }

    /* Suport Native Guard if OS/2 requested */
    if (ulFlags & OS2_PAG_GUARD) {
        protect |= PAGE_GUARD;
    }

    /* 2. Settle the base adress
       If the aplicação OS/2 not specify an adress(default),
       then NTDLL select a random free adress. */
    if (ppBaseAddress && *ppBaseAddress != NULL) {
        /* If the process support random allocation */
        allocation_address = *ppBaseAddress;
    }

    /* 3. Call native memory allocation */
    status = NtAllocateVirtualMemory(NtCurrentProcess(),
                                     &allocation_address,
                                     0,
                                     &region_size,
                                     MEM_COMMIT | MEM_RESERVE,
                                     protect);

    if (status != STATUS_SUCCESS) {
        /* Mapping NT errors to OS/2 subsystem */
        if (status == STATUS_NO_MEMORY || status == STATUS_INSUFFICIENT_RESOURCES) {
            return 8; /* ERROR_NOT_ENOUGH_MEMORY */
        }
        return 87; /* ERROR_INVALID_PARAMETER */
    }

    /* Return the linear adress to LX environment */
    *ppBaseAddress = allocation_address;
    
    return 0; /* NO_ERROR (0) */
}


/* =========================================================================
 * 16-BIT EMULATED CORES (NE Subsystem LDT Marshalling)
 * ========================================================================= */

/* Local helper to scan and claim an available dynamic LDT selector slot */
static uint16_t allocate_ldt_entry(void* linear_address, ULONG size) {
    int i;
    if (!virtual_ldt) return 0;

    /* Scan virtual LDT table. Skip the first 16 indexes to preserve real-mode vector maps safely */
    for (i = 16; i < 8192; i++) {
        if (virtual_ldt[i].base == 0 && virtual_ldt[i].limit == 0) {
            virtual_ldt[i].base    = (uint32_t)(uintptr_t)linear_address;
            virtual_ldt[i].limit   = (uint32_t)(size - 1);
            virtual_ldt[i].present = 1;
            virtual_ldt[i].type    = LDT_TYPE_SEGMENT;

            /* Transform index allocation integer to valid protected descriptor format (TI=1, RPL=3) */
            return (uint16_t)((i << 3) | 0x0007);
        }
    }
    return 0;
}

/* API OS/2: DosAllocSeg(USHORT cbSize, PSEL pSel, USHORT fsAlloc) */
uint16_t os2_Dos16Allocseg(CPU286_Context* ctx) {
    uint16_t sp_base = ctx->sp + 4; /* Push the FAR jump (CS:IP) */
    
    /* Obtain the Pascal argument stack */
    uint16_t fsAlloc  = *(uint16_t*)mode16to32(ctx->ss, sp_base + 0);
    uint16_t pSel_off = *(uint16_t*)mode16to32(ctx->ss, sp_base + 2);
    uint16_t pSel_sel = *(uint16_t*)mode16to32(ctx->ss, sp_base + 4);
    uint16_t cbSize   = *(uint16_t*)mode16to32(ctx->ss, sp_base + 6);
    
    uint16_t* host_selector;
    ULONG real_size;
    void* heap_alloc;
    uint16_t selector;

    host_selector = (uint16_t*)mode16to32(pSel_sel, pSel_off);
    if (!host_selector) return 87; /* ERROR_INVALID_PARAMETER */

    real_size = (cbSize == 0) ? 65536 : cbSize; /* 0 means a full 64KB block */

    /* Using safer memory allocation functions */
    heap_alloc = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, real_size);
    if (!heap_alloc) return 8; /* ERROR_NOT_ENOUGH_MEMORY */

    /* settle memory adress to a free LDT */
    selector = allocate_ldt_entry(heap_alloc, real_size);
    if (selector == 0) {
        HeapFree(GetProcessHeap(), 0, heap_alloc);
        return 8; /* ERROR_NOT_ENOUGH_MEMORY */
    }

    *host_selector = selector;
    return 0; /* NO_ERROR */
}

/* API OS/2: DosReAllocSeg(USHORT cbNewSize, SEL selector) */
uint16_t os2_Dos16ReAllocseg(CPU286_Context* ctx) {
    uint16_t sp_base = ctx->sp + 4; 
    
    /* 16-bit Pascal extraction */
    uint16_t selector  = *(uint16_t*)mode16to32(ctx->ss, sp_base + 0);
    uint16_t cbNewSize = *(uint16_t*)mode16to32(ctx->ss, sp_base + 2);
    
    uint16_t ldt_index;
    ULONG new_size;
    void* old_host_ptr;
    void* new_host_ptr;

    ldt_index = selector >> 3;
    if (!virtual_ldt || ldt_index >= 8192 || !virtual_ldt[ldt_index].present) {
        return 5; /* ERROR_ACCESS_DENIED */
    }

    new_size = (cbNewSize == 0) ? 65536 : cbNewSize;

    /* Search the original selector */
    old_host_ptr = (void*)(uintptr_t)virtual_ldt[ldt_index].base;
    
    /* Update safely the selector */
    if (old_host_ptr) {
        new_host_ptr = HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, old_host_ptr, new_size);
    } else {
        new_host_ptr = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, new_size);
    }

    if (!new_host_ptr) return 8; /* ERROR_NOT_ENOUGH_MEMORY */

    /* Update the LDT table */
    virtual_ldt[ldt_index].base  = (uint32_t)(uintptr_t)new_host_ptr;
    virtual_ldt[ldt_index].limit = (uint32_t)(new_size - 1);

    return 0; /* NO_ERROR */
}
