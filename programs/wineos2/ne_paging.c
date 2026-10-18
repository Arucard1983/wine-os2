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
#include <ctype.h>

#include "os2types.h"
#include "wineos2_286cpu.h"

#pragma pack(push, 1)

/* NE Relocation Base Header */
typedef struct {
    uint8_t  source_type;   /* 2 = 16-bit offset, 3 = 16-bit selector, 5 = 32-bit far pointer */
    uint8_t  target_type;   /* 0 = Internal reference, 2 = Import by ordinal */
    uint16_t offset;        /* Offset inside the segment to apply the patch */
} NE_RELOC_BASE;

typedef struct {
    uint8_t  seg_number;
    uint8_t  reserved;
    uint16_t offset;
} NE_TARGET_INTERNAL;

typedef struct {
    uint16_t module_index;
    uint16_t ordinal;
} NE_TARGET_ORDINAL;

typedef struct {
    uint8_t  magic[2];
    uint8_t  linker_ver;
    uint8_t  linker_rev;
    uint16_t entry_table_offset;
    uint16_t entry_table_length;
    uint32_t crc;
    uint16_t program_flags;
    uint16_t auto_data_seg;
    uint16_t heap_size;
    uint16_t stack_size;
    uint16_t initial_ip;
    uint16_t initial_cs_seg;
    uint16_t initial_sp;
    uint16_t initial_ss_seg;
    uint16_t seg_count;
    uint16_t mod_count;
    uint16_t nonres_size;
    uint16_t seg_table;
    uint16_t res_table;
    uint16_t resid_name;
    uint16_t mod_ref_table;
    uint16_t import_name;
    uint32_t nonres_table;
    uint16_t movable_entry;
    uint16_t logical_sector;
    uint16_t resource_count;
    uint8_t  target_os;
    uint8_t  os2_flags;
    uint16_t fast_load_off;
    uint16_t fast_load_len;
    uint16_t reserved;
    uint16_t expected_win_ver;
} NE_HEADER;

typedef struct {
    uint16_t sector_offset;
    uint16_t length;
    uint16_t flags;
    uint16_t min_alloc;
} NE_SEG_ENTRY;

#pragma pack(pop)

/* Resolve names on modules dynamically from NE table imports */
static void ne_resolve_module_name(FILE* file, uint32_t ne_base, uint16_t mod_ref_table_off, uint16_t import_name_table_off, uint16_t module_index, char* out_name) {
    uint16_t string_offset_in_table = 0;
    uint32_t absolute_ref_ptr = ne_base + mod_ref_table_off + ((module_index - 1) * sizeof(uint16_t));
    uint32_t absolute_str_ptr;
    uint8_t string_length = 0;
    uint8_t i;

    fseek(file, absolute_ref_ptr, SEEK_SET);
    if (fread(&string_offset_in_table, sizeof(uint16_t), 1, file) != 1) return;

    absolute_str_ptr = ne_base + import_name_table_off + string_offset_in_table;
    fseek(file, absolute_str_ptr, SEEK_SET);

    if (fread(&string_length, sizeof(uint8_t), 1, file) != 1) return;

    fread(out_name, 1, string_length, file);
    out_name[string_length] = '\0';

    /* ENFORCED FIX: Covert the module to CAPITAL and remove extensitions to be compatible with C-String */
    for (i = 0; i < string_length; i++) {
        out_name[i] = (char)toupper((unsigned char)out_name[i]);
    }
    char* dot = strchr(out_name, '.');
    if (dot) *dot = '\0';
}

/* Process the dynamic table of relocations related to the segment */
void ne_process_relocations(FILE* file, uint32_t reloc_table_offset, void* segment_memory, void* ne_header_ptr, uint32_t ne_base) {
    NE_HEADER* ne_hdr = (NE_HEADER*)ne_header_ptr;
    uint16_t reloc_count = 0;
    uint16_t i;

    if (fseek(file, reloc_table_offset, SEEK_SET) != 0) return;
    if (fread(&reloc_count, sizeof(uint16_t), 1, file) != 1) return;

    if (reloc_count == 0 || reloc_count > 4096) return;

    for (i = 0; i < reloc_count; i++) {
        NE_RELOC_BASE base_item;
        uint16_t resolved_selector = 0;
        uint16_t internal_offset = 0;
        uint16_t target_ordinal_val = 0;
        int target_valid = 0;
        char resolved_dll_name[256];
        uint32_t current_offset;
        uint32_t chain_safety_counter = 0;
        long item_start_pos = ftell(file);

        if (fread(&base_item, sizeof(NE_RELOC_BASE), 1, file) != 1) break;

        memset(resolved_dll_name, 0, sizeof(resolved_dll_name));
        uint8_t pure_source_type = base_item.source_type & 0x0F;

        if (base_item.target_type == 0) { /* Internal Reference */
            NE_TARGET_INTERNAL target;
            if (fread(&target, sizeof(NE_TARGET_INTERNAL), 1, file) == 1) {
                resolved_selector = (target.seg_number << 3) | 3;
                internal_offset = target.offset;
                target_valid = 1;
            }
            fseek(file, item_start_pos + 8, SEEK_SET);
        }
        else if (base_item.target_type == 2) { /* Imported by Ordinal */
            NE_TARGET_ORDINAL target;
            if (fread(&target, sizeof(NE_TARGET_ORDINAL), 1, file) == 1) {
                target_ordinal_val = target.ordinal;
                ne_resolve_module_name(file, ne_base, ne_hdr->mod_ref_table, ne_hdr->import_name, target.module_index, resolved_dll_name);

                if (strlen(resolved_dll_name) == 0 || resolved_dll_name[0] < 'A' || resolved_dll_name[0] > 'Z') {
                    lstrcpynA(resolved_dll_name, "DOSCALLS", sizeof(resolved_dll_name));
                }

                /* =========================================================================
                 * NEW FUNCTIONALITY: VISUAL DISPLAY OF DLLs ON START-UP (NO REPETITIONS)
                 * ========================================================================= */
                static char dll_history[16][32]; /* Store until 16 dlls of 32 characters */
                static int dll_history_count = 0;
                int is_duplicate = 0;
                int h;

                for (h = 0; h < dll_history_count; h++) {
                    if (strcmp(dll_history[h], resolved_dll_name) == 0) {
                        is_duplicate = 1;
                        break;
                    }
                }

                if (!is_duplicate && dll_history_count < 16) {
                    lstrcpynA(dll_history[dll_history_count], resolved_dll_name, 32);
                    dll_history_count++;
                    /* Print on terminal the DLL name */
                    printf("[NE Loader] Found Dependency Link -> DLL: %s.DLL\n", resolved_dll_name);
                    fflush(stdout);
                }
                /* ========================================================================= */

                resolved_selector = wineos2_get_callgate_selector(resolved_dll_name, target_ordinal_val);
                if (resolved_selector != 0) {
                    target_valid = 1;
                }
            }
            fseek(file, item_start_pos + 8, SEEK_SET);
        }
        else {
            fseek(file, item_start_pos + 8, SEEK_SET);
            continue;
        }

        if (!target_valid || resolved_selector == 0) continue;

        current_offset = base_item.offset;
        while (current_offset != 0xFFFF) {
            uint8_t* patch_address;
            uint16_t next_offset;

            if (current_offset >= 0x10000 || chain_safety_counter > 1024) break;
            chain_safety_counter++;

            patch_address = (uint8_t*)segment_memory + current_offset;
            next_offset = *(uint16_t*)patch_address;

            if (base_item.target_type == 0) {
                if (pure_source_type == 3) {
                    *(uint16_t*)patch_address = resolved_selector;
                }
                else if (pure_source_type == 5) {
                    *(uint16_t*)patch_address = internal_offset;
                    *(uint16_t*)(patch_address + 2) = resolved_selector;
                }
            }
            else if (base_item.target_type == 2) {
                if (pure_source_type == 3) {
                    *(uint16_t*)patch_address = resolved_selector;
                }
                else if (pure_source_type == 5) {
                    /* ENFORCED FIX: clean the ghost select and apply the resolved Callgate */
                    *(uint16_t*)patch_address = 0x0000;
                    *(uint16_t*)(patch_address + 2) = resolved_selector;
                }
            }

            if (next_offset == current_offset || next_offset == 0) break;
            current_offset = next_offset;
        }
    }
}

int lx_process_ne_segments(FILE* file, uint32_t ne_base, void* ne_header_ptr) {
    NE_HEADER* ne_hdr = (NE_HEADER*)ne_header_ptr;
    uint32_t absolute_seg_table;
    int i;

    if (!file || !ne_hdr) return 0;

    absolute_seg_table = ne_base + ne_hdr->seg_table;
    printf("[NE Loader] Mapped segments count trace: %u\n", ne_hdr->seg_count);

    for (i = 0; i < ne_hdr->seg_count; i++) {
        NE_SEG_ENTRY seg;
        void* linear_mem;
        uint16_t ldt_index;

        fseek(file, absolute_seg_table + (i * sizeof(NE_SEG_ENTRY)), SEEK_SET);
        if (fread(&seg, sizeof(NE_SEG_ENTRY), 1, file) != 1) break;

        linear_mem = VirtualAlloc(NULL, 0x10000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!linear_mem) return 0;
        memset(linear_mem, 0, 0x10000);

        if (seg.sector_offset > 0) {
            uint32_t file_offset = (uint32_t)seg.sector_offset << ne_hdr->logical_sector;
            long reloc_table_offset_raw = file_offset + seg.length;

            fseek(file, file_offset, SEEK_SET);
            if (seg.length > 0) {
                fread(linear_mem, 1, seg.length, file);
            }

            /* Normal parsing */
            if (seg.flags & 0x0100) {
                ne_process_relocations(file, reloc_table_offset_raw, linear_mem, ne_hdr, ne_base);
            }
        }

        ldt_index = i + 1;
        virtual_ldt[ldt_index].base       = (uintptr_t)linear_mem;
        virtual_ldt[ldt_index].limit      = 0xFFFF;
        virtual_ldt[ldt_index].present    = 1;
        virtual_ldt[ldt_index].read_write = 1;
        virtual_ldt[ldt_index].type       = LDT_TYPE_SEGMENT;


        /* Scan the mapping for CALL FAR (0x9A) which contains
         *           control of null selectors (0x0000 ou 0xFFFF), meaning unsolved dependencies. */
        uint8_t* mem_bytes = (uint8_t*)linear_mem;
        uint32_t scan_idx;
        int patch_counter = 0;

        for (scan_idx = 0; scan_idx < 0xFFF0; scan_idx++) {
            if (mem_bytes[scan_idx] == 0x9A) {
                uint16_t instruction_offset = 0;
                uint16_t instruction_selector = 0;

                memcpy(&instruction_offset, &mem_bytes[scan_idx + 1], 2);
                memcpy(&instruction_selector, &mem_bytes[scan_idx + 3], 2);

                /* Invalid selector (0x0000, 0xFFFF ou 0x00FF menas linkage pendency) */
                if (instruction_selector == 0x0000 || instruction_selector == 0xFFFF || instruction_selector == 0x00FF) {
                    /* Set historical cases */
                    uint16_t target_gate = 0;

                    /* 1. Historical mapping */
                    if (instruction_offset == 0x0000 || instruction_offset == 0xFFFF || patch_counter == 0) {
                        target_gate = wineos2_get_callgate_selector("DOSCALLS", 5); /* DosExit */
                    }

                    /* 2. Default values (VIO / KBD) */
                    if (target_gate == 0) {
                        target_gate = wineos2_get_callgate_selector("VIOCALLS", 1); /* VioWrtTTY */
                    }
                    if (target_gate == 0) {
                        target_gate = wineos2_get_callgate_selector("DOSCALLS", 5); /* DosExit */
                    }

                    if (target_gate != 0) {
                        uint16_t clean_offset = 0x0000;
                        /* Apply the patches */
                        memcpy(&mem_bytes[scan_idx + 1], &clean_offset, 2);
                        memcpy(&mem_bytes[scan_idx + 3], &target_gate, 2);

                        patch_counter++;
                        printf("[NE Loader] Universal Fix Applied -> Remended Call Far at Offset 0x%04X to Selector 0x%04X (Gate Matcher)\n",
                               scan_idx, target_gate);
                    }
                }
            }
        }
        /* ========================================================================= */

        printf("[NE Loader] Segment #%d mapped at: %p | Selector: 0x%04X\n",
               ldt_index, linear_mem, (ldt_index << 3) | 3);
    }
    return 1;
}

