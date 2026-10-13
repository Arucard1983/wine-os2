/*
 *  ne_paging.c - OS/2 1.x 16-bit New Executable (NE) Segment Loader & Relocation Engine
 *  (c) Arucard 2026 - Wine-OS/2 Project
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "os2types.h"
#include "wineos2_286cpu.h"

#pragma pack(push, 1)

/* NE Relocation Source Info Byte Structural Mapping */
typedef struct {
    uint8_t  source_type;   /* 2 = 16-bit offset, 3 = 16-bit selector, 5 = 32-bit far pointer */
    uint8_t  target_type;   /* 0 = Internal reference, 2 = Import by ordinal */
    uint16_t offset;        /* Offset within the segment where the patch must be applied */
} NE_RELOC_ITEM;

typedef struct {
    uint8_t  seg_number;
    uint8_t  reserved;
    uint16_t offset;
} NE_TARGET_INTERNAL;

typedef struct {
    uint16_t module_index;
    uint16_t ordinal;
} NE_TARGET_ORDINAL;

#pragma pack(pop)

/* Forward declaration for external callgate registration pipeline */
uint16_t register_api_callgate(const char* mod_name, uint16_t ordinal);

/* Resolves module string names out of the standard NE target import tables dynamically */
static void ne_resolve_module_name(FILE* file, uint32_t ne_base, uint16_t mod_ref_table_off, uint16_t import_name_table_off, uint16_t module_index, char* out_name) {
    uint16_t string_offset_in_table = 0;
    uint32_t absolute_ref_ptr = ne_base + mod_ref_table_off + ((module_index - 1) * sizeof(uint16_t));

    fseek(file, absolute_ref_ptr, SEEK_SET);
    if (fread(&string_offset_in_table, sizeof(uint16_t), 1, file) != 1) return;

    /* Position the descriptor directly into the specific Pascal String inside the Import Table */
    uint32_t absolute_str_ptr = ne_base + import_name_table_off + string_offset_in_table;
    fseek(file, absolute_str_ptr, SEEK_SET);

    uint8_t string_length = 0;
    if (fread(&string_length, sizeof(uint8_t), 1, file) != 1) return;

    fread(out_name, 1, string_length, file);
    out_name[string_length] = '\0';
}

/* Processes the complete relocation item table linked right after a segment block */
void ne_process_relocations(FILE* file, uint32_t reloc_table_offset, void* segment_memory, void* ne_header_ptr, uint32_t ne_base) {
    NE_HEADER* ne_hdr = (NE_HEADER*)ne_header_ptr;
    uint16_t reloc_count = 0;

    if (fseek(file, reloc_table_offset, SEEK_SET) != 0) return;
    if (fread(&reloc_count, sizeof(uint16_t), 1, file) != 1) return;

    if (reloc_count == 0 || reloc_count > 4096) return;

    for (uint16_t i = 0; i < reloc_count; i++) {
        NE_RELOC_ITEM item;
        if (fread(&item, sizeof(NE_RELOC_ITEM), 1, file) != 1) break;

        long next_item_pos = ftell(file);
        uint16_t resolved_selector = 0;
        uint16_t internal_offset = 0;
        int target_valid = 0;
        char resolved_dll_name[256];
        memset(resolved_dll_name, 0, sizeof(resolved_dll_name));

        if (item.target_type == 0) { /* Internal Segment Reference Link */
            NE_TARGET_INTERNAL target;
            if (fread(&target, sizeof(NE_TARGET_INTERNAL), 1, file) == 1) {
                resolved_selector = (target.seg_number << 3) | 3; /* Request user RPL=3 */
                internal_offset = target.offset;
                target_valid = 1;
            }
        }
        else if (item.target_type == 2) { /* External Subsystem API Import by Ordinal */
            NE_TARGET_ORDINAL target;
            if (fread(&target, sizeof(NE_TARGET_ORDINAL), 1, file) == 1) {
                ne_resolve_module_name(file, ne_base, ne_hdr->mod_ref_table, ne_hdr->import_name, target.module_index, resolved_dll_name);
                
                /* Fallback routing mechanism to catch missing descriptors gracefully */
                if (strlen(resolved_dll_name) == 0 || resolved_dll_name[0] < 'A' || resolved_dll_name[0] > 'z') {
                    strcpy(resolved_dll_name, "DOSCALLS");
                }

                /* Registers a clean Protected Mode Call Gate selector into the master LDT map */
                resolved_selector = register_api_callgate(resolved_dll_name, target.ordinal);
                target_valid = 1;
            }
        }

        /* Enforce absolute file pointer tracking restoration to skip target bytes structurally */
        fseek(file, next_item_pos + (item.target_type == 0 ? sizeof(NE_TARGET_INTERNAL) : sizeof(NE_TARGET_ORDINAL)), SEEK_SET);

        if (!target_valid || resolved_selector == 0) continue;

        /* Trace and patch sequential memory reference lookup links (Exponential Chain Patching) */
        uint32_t current_offset = item.offset;
        uint32_t chain_safety_counter = 0;

        while (current_offset != 0xFFFF) {
            if (current_offset >= 0x10000 || chain_safety_counter > 2048) break;
            chain_safety_counter++;

            uint8_t* patch_address = (uint8_t*)segment_memory + current_offset;
            uint16_t next_offset = *(uint16_t*)patch_address;

            if (item.target_type == 0) {
                if (item.source_type == 3) {
                    *(uint16_t*)patch_address = resolved_selector;
                }
                else if (item.source_type == 5) {
                    *(uint16_t*)patch_address = internal_offset;
                    *(uint16_t*)(patch_address + 2) = resolved_selector;
                }
            }
            else if (item.target_type == 2) {
                if (item.source_type == 3) {
                    *(uint16_t*)patch_address = resolved_selector;
                }
                else if (item.source_type == 5) {
                    *(uint16_t*)patch_address = 0x0000; /* Call Gate offset coordinate parameters are discarded */
                    *(uint16_t*)(patch_address + 2) = resolved_selector;
                }
            }
            current_offset = next_offset;
        }
    }
}

/* 
 * Processes, reads, and registers individual 16-bit segmented boundaries 
 * out of a New Executable application track into our runtime virtual LDT map.
 */
int lx_process_ne_segments(FILE* file, uint32_t ne_base, void* ne_header_ptr) {
    NE_HEADER* ne_hdr = (NE_HEADER*)ne_header_ptr;
    if (!file || !ne_hdr) return 0;

    uint32_t absolute_seg_table = ne_base + ne_hdr->seg_table;
    printf("[NE Loader] Mapped segments count trace: %u\n", ne_hdr->seg_count);

    for (int i = 0; i < ne_hdr->seg_count; i++) {
        fseek(file, absolute_seg_table + (i * sizeof(NE_SEG_ENTRY)), SEEK_SET);
        
        NE_SEG_ENTRY seg;
        if (fread(&seg, sizeof(NE_SEG_ENTRY), 1, file) != 1) break;

        /* Enforce absolute 64KB segmented boundaries configuration avoiding alignment clipping */
        uint32_t alloc_size = 0x10000; 

        /* Win32 Native virtual commitment ensuring predictable page boundaries */
        void* linear_mem = VirtualAlloc(NULL, alloc_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!linear_mem) {
            printf("[NE Loader Error] Failed to allocate memory frame block for Segment #%d\n", i + 1);
            return 0;
        }
        memset(linear_mem, 0, alloc_size);

        if (seg.sector_offset > 0) {
            /* Sector offset shift mapping defined by standard NE specification rules */
            uint32_t file_offset = (uint32_t)seg.sector_offset << ne_hdr->logical_sector;

            long current_pos = ftell(file);
            fseek(file, file_offset, SEEK_SET);
            fread(linear_mem, 1, seg.length, file);

            /* Calculate sector aligned relocation tracking checkpoints */
            uint32_t sector_size = 1 << ne_hdr->logical_sector;
            uint32_t padded_length = ((seg.length + sector_size - 1) / sector_size) * sector_size;

            long reloc_table_offset_aligned = file_offset + padded_length;
            long reloc_table_offset_raw = file_offset + seg.length;
            uint16_t check_count = 0;

            /* Checkpoint Match Variant A: Aligned boundary matching standard compilation linkers */
            fseek(file, reloc_table_offset_aligned, SEEK_SET);
            if (fread(&check_count, sizeof(uint16_t), 1, file) == 1 && check_count > 0 && check_count < 8192) {
                ne_process_relocations(file, reloc_table_offset_aligned, linear_mem, ne_hdr, ne_base);
            }
            /* Checkpoint Match Variant B: Packed raw byte structure trailing after static track sizes */
            else {
                fseek(file, reloc_table_offset_raw, SEEK_SET);
                if (fread(&check_count, sizeof(uint16_t), 1, file) == 1 && check_count > 0 && check_count < 8192) {
                    ne_process_relocations(file, reloc_table_offset_raw, linear_mem, ne_hdr, ne_base);
                }
            }
            fseek(file, current_pos, SEEK_SET);
        }

        /* Bind the mapped structural linear pointer context securely directly to our LDT slot */
        uint16_t ldt_index = i + 1;
        virtual_ldt[ldt_index].base       = (uintptr_t)linear_mem; /* Safe 64-bit address context storage */
        virtual_ldt[ldt_index].limit      = alloc_size - 1;
        virtual_ldt[ldt_index].present    = 1;
        virtual_ldt[ldt_index].read_write = 1;
        virtual_ldt[ldt_index].type       = LDT_TYPE_SEGMENT; 

        printf("[NE Loader] Segment #%d mapped at: %p | Selector registration: 0x%04X\n",
               ldt_index, linear_mem, (ldt_index << 3) | 3);
    }
    return 1;
}
