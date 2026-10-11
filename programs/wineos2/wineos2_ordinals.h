/*
 *  wineos2_ordinals.h - OS/2 1.x Ordinal Resolution & Call Gate Dispatcher
 *  (c) Arucard 2026 - Wine-OS/2 Project
 */

#ifndef WINEOS2_ORDINALS_H
#define WINEOS2_ORDINALS_H

#include "wineos2_286cpu.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Structure to map an individual OS/2 Ordinal to its C implementation */
typedef struct {
    uint16_t ordinal;
    const char* name;
    uint16_t (*thunk_ptr)(CPU286_Context* ctx);
} OS2_ORDINAL_ENTRY;

/* Structure representing a complete imported module lookup table */
typedef struct {
    const char* module_name;
    const OS2_ORDINAL_ENTRY* entries;
} OS2_MODULE_TABLE;

/* =========================================================================
 * FORWARD DECLARATIONS OF NATIVE WINE THUNKS (OS/2 API Implementations)
 * ========================================================================= */
uint16_t os2_DosExit(CPU286_Context* ctx);
uint16_t os2_DosWrite(CPU286_Context* ctx);
uint16_t os2_DosAllocSeg(CPU286_Context* ctx);
uint16_t os2_DosOpen(CPU286_Context* ctx);
uint16_t os2_DosRead(CPU286_Context* ctx);
uint16_t os2_VioWrtTTY(CPU286_Context* ctx);

/* =========================================================================
 * SUBSYSTEM ORDINAL TABLES (IBM OS/2 1.3 Standards)
 * ========================================================================= */

/* DOSCALLS.DLL Ordinal Mapping */
static const OS2_ORDINAL_ENTRY doscalls_table[] = {
    { 5,   "DosExit",     os2_DosExit },
    { 32,  "DosWrite",    os2_DosWrite },
    { 34,  "DosAllocSeg", os2_DosAllocSeg },
    { 70,  "DosOpen",     os2_DosOpen },
    { 137, "DosRead",     os2_DosRead },
    { 0,   NULL,          NULL } /* Sentinel */
};

/* VIOCALLS.DLL Ordinal Mapping (Video Subsystem) */
static const OS2_ORDINAL_ENTRY viocalls_table[] = {
    { 5,  "VioWrtTTY", os2_VioWrtTTY },
    { 0,  NULL,        NULL } /* Sentinel */
};

/* Master System Directory for Dynamic DLL Name Routing */
static const OS2_MODULE_TABLE master_module_directory[] = {
    { "DOSCALLS", doscalls_table },
    { "VIOCALLS", viocalls_table },
    { NULL,       NULL } /* Sentinel */
};

/* =========================================================================
 * INTERNAL RESOLUTION AND CALL GATE ENGINE
 * ========================================================================= */

/* Scans the directory to find the targeted thunk by Module Name and Ordinal */
static inline uint16_t (*resolve_os2_api(const char* mod_name, uint16_t ordinal))(CPU286_Context*) {
    int m = 0;
    while (master_module_directory[m].module_name != NULL) {
        if (strcasecmp(master_module_directory[m].module_name, mod_name) == 0) {
            const OS2_ORDINAL_ENTRY* table = master_module_directory[m].entries;
            int e = 0;
            while (table[e].ordinal != 0) {
                if (table[e].ordinal == ordinal) {
                    return table[e].thunk_ptr;
                }
                e++;
            }
            break; /* Module matched but ordinal doesn't exist */
        }
        m++;
    }
    return NULL;
}

/*
 * Registers an OS/2 dependency into the Virtual LDT as a Protected Mode Call Gate.
 * Enforces allocation on high boundaries to prevent overlap with loaded binary segments.
 */
static inline uint16_t register_api_callgate(const char* mod_name, uint16_t ordinal) {
    /* Scan starting from index 256 (0x0100) to keep low selectors clean for EXE modules */
    for (uint16_t idx = 256; idx < LDT_MAX_ENTRIES; idx++) {
        if (!virtual_ldt[idx].present) {

            virtual_ldt[idx].present = 1;
            virtual_ldt[idx].type = LDT_TYPE_CALLGATE;
            virtual_ldt[idx].limit = ordinal;
            virtual_ldt[idx].wine_thunk = resolve_os2_api(mod_name, ordinal);

            /* Build the Protected Mode Selector (Index shifted left, TI=0, RPL=3) */
            return (idx << 3) | 3;
        }
    }
    printf("Critical Fault: LDT space exhausted during Call Gate allocation.\n");
    return 0;
}


/* =========================================================================
 * STUBBED NATIVE IMPLEMENTATIONS (WINE SIDE CODES)
 * ========================================================================= */

uint16_t os2_DosExit(CPU286_Context* ctx) {
    uint16_t sp_offset = ctx->sp;
    uint16_t result_code = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 4);
    uint16_t action_flags = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 6);

    printf("\n[OS/2 PROCESS TERMINATED via DosExit] Action: %d, Code: %d\n", action_flags, result_code);
    /* Safely release execution control back to the host operating system */
    exit(result_code);
    return 0;
}

uint16_t os2_DosAllocSeg(CPU286_Context* ctx) {
    /* Stack Layout:
     * [SP + 4]  -> pSelector (Far pointer 16:16 to receive the allocated selector)
     * [SP + 8]  -> AllocFlags (16-bit allocation/sharing attribute flags)
     * [SP + 10] -> Size (16-bit memory allocation size requested. 0 = Full 64KB)
     */
    uint16_t sp_offset = ctx->sp;
    uint16_t size       = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 10);
    uint16_t pSel_off   = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 6);
    uint16_t pSel_sel   = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 4);

    uint32_t alloc_bytes = (size == 0) ? 0x10000 : size;
    void* mem = malloc(alloc_bytes);
    if (!mem) return 8; /* ERROR_NOT_ENOUGH_MEMORY */
        memset(mem, 0, alloc_bytes);

    /* Search for a free slot in the Virtual LDT starting above low system indexes */
    for (uint16_t idx = 20; idx < LDT_MAX_ENTRIES; idx++) {
        if (!virtual_ldt[idx].present) {
            virtual_ldt[idx].base = (uint32_t)(uintptr_t)mem;
            virtual_ldt[idx].limit = alloc_bytes - 1;
            virtual_ldt[idx].present = 1;
            virtual_ldt[idx].type = LDT_TYPE_SEGMENT;

            uint16_t new_selector = (idx << 3) | 3; /* Enforce User Ring 3 RPL */
            uint16_t* host_pSel = (uint16_t*)mode16to32(pSel_sel, pSel_off);
            if (host_pSel) *host_pSel = new_selector;

            printf("[API DOSCALLS] DosAllocSeg: Allocated %u bytes at Selector 0x%04X\n", alloc_bytes, new_selector);
            ctx->sp += 8; /* Pascal calling convention stack cleanup */
            return 0; /* NO_ERROR */
        }
    }
    free(mem);
    return 8;
}

uint16_t os2_DosOpen(CPU286_Context* ctx) {
    /* Stack Layout:
     * [SP + 4]  -> pAction (16-bit Far ptr to receive action code taken)
     * [SP + 8]  -> OpenMode (16-bit mode flags)
     * [SP + 10] -> OpenFlag (16-bit flag specifying action if file exists/doesn't exist)
     * [SP + 12] -> cbFile (32-bit primary allocation size)
     * [SP + 16] -> FileAttribute (16-bit attributes)
     * [SP + 18] -> pHandle (16-bit Far ptr to receive the generated file descriptor)
     * [SP + 20] -> pName (16-bit Far ptr pointing to the ASCIIZ filename string)
     */
    uint16_t sp_offset = ctx->sp;
    uint16_t pName_off   = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 22);
    uint16_t pName_sel   = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 20);
    uint16_t pHandle_off = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 18);
    uint16_t pHandle_sel = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 16);

    char* filename = (char*)mode16to32(pName_sel, pName_off);
    uint16_t* host_handle = (uint16_t*)mode16to32(pHandle_sel, pHandle_off);

    printf("[API DOSCALLS] DosOpen targeted file: %s\n", filename ? filename : "NULL");

    if (host_handle) {
        *host_handle = 5; /* Provide a safe mock Handle ID structure for verification */
    }

    ctx->sp += 20; /* Pascal calling convention stack cleanup */
    return 0; /* NO_ERROR */
}

uint16_t os2_DosRead(CPU286_Context* ctx) {
    /* Stack Layout:
     * [SP + 4]  -> pBytesRead (16-bit Far ptr to receive count of bytes successfully read)
     * [SP + 6]  -> cbRead (16-bit requested read buffer length size)
     * [SP + 8]  -> pBuffer (16-bit Far ptr to target buffer inside virtual memory space)
     * [SP + 12] -> hFile (16-bit target active file handle descriptor)
     */
    uint16_t sp_offset = ctx->sp;
    uint16_t hFile      = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 12);
    uint16_t pBuf_off   = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 10);
    uint16_t pBuf_sel   = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 8);
    uint16_t cbRead     = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 6);
    uint16_t pRead_off  = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 4);
    uint16_t pRead_sel  = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 2);

    uint16_t* host_read = (uint16_t*)mode16to32(pRead_sel, pRead_off);
    uint8_t* host_buf = (uint8_t*)mode16to32(pBuf_sel, pBuf_off);

    printf("[API DOSCALLS] DosRead called on Handle %d, requesting %u bytes\n", hFile, cbRead);

    if (host_read) {
        host_read = 0; /* Inject structural End Of File (EOF) signal for safety control loops */
    }
    ctx->sp += 10; /* Pascal calling convention stack cleanup */
    return 0; /* NO_ERROR */
}

uint16_t os2_DosWrite(CPU286_Context* ctx) {
    /* Architectural Compliance: Skip the 4 bytes of Far Return tracking (CS:IP) */
    uint16_t sp_offset = ctx->sp + 4;

    uint16_t hFile      = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 10);
    uint16_t pBuf_off   = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 8);
    uint16_t pBuf_sel   = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 6);
    uint16_t cbWrite    = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 4);
    uint16_t pAct_off   = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 2);
    uint16_t pAct_sel   = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 0);

    /* FIX: Prioritize 0-byte handle verification tests before triggering
     * memory pointer translations that can fail on uninitialized compiler tables */
    if (cbWrite == 0) {
        uint16_t* host_actual = (uint16_t*)mode16to32(pAct_sel, pAct_off);
        if (host_actual) {
            *host_actual = 0;
        }
        ctx->sp += 12; /* Perform standard Pascal convention callee cleanup */
        return 0;      /* Return NO_ERROR (0x0000) */
    }

    uint16_t* host_actual = (uint16_t*)mode16to32(pAct_sel, pAct_off);
    char* host_buffer = (char*)mode16to32(pBuf_sel, pBuf_off);

    if (!host_buffer || !host_actual) {
        ctx->sp += 12;
        return 87; /* ERROR_INVALID_PARAMETER (0x0057) */
    }

    int written = 0;
    if (hFile == 1 || hFile == 2) { /* Standard terminal streaming output fallback redirection */
        printf("%.*s", cbWrite, host_buffer);
        fflush(stdout);
        written = cbWrite;
    }

    *host_actual = (uint16_t)written;

    ctx->sp += 12;
    return 0;
}




uint16_t os2_VioWrtTTY(CPU286_Context* ctx) {
    /* Skip the 4 bytes of Far Return Address (CS:IP) on top of the stack */
    uint16_t sp_offset = ctx->sp + 4; 
    
    uint16_t cbStr      = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 4);
    uint16_t pStr_off   = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 2);
    uint16_t pStr_sel   = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 0);

    char* host_str = (char*)mode16to32(pStr_sel, pStr_off);
    if (!host_str) return 355; /* ERROR_VIO_DETACHED */

    printf("%.*s", cbStr, host_str);
    fflush(stdout);

    /* Clean only the 6 bytes of parameters from the Pascal convention call */
    ctx->sp += 6; 
    return 0;
}



#endif /* WINEOS2_ORDINALS_H */

