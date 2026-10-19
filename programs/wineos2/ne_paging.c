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

typedef struct {
    uint8_t magic[2];      // 'MZ' (0x5A4D)
    uint8_t  e_reserved[58];
    uint32_t e_lfanew;     // Absolute offset for NE head
} DOS_Header;

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

/* Centralized Module Reference Cache Data Store */
static char **global_module_cache = NULL;
static int global_module_cache_count = 0;

/* External symbols from virtual environment */
extern OS2_LDT_ENTRY virtual_ldt[LDT_MAX_ENTRIES];
extern uint16_t wineos2_get_callgate_selector(const char* mod_name, uint16_t ordinal);

/* Destructor to safely clean up modular memory footprints */
void wineos2_free_module_cache(void) {
    if (global_module_cache != NULL) {
        for (int i = 0; i < global_module_cache_count; i++) {
            if (global_module_cache[i]) free(global_module_cache[i]);
        }
        free(global_module_cache);
        global_module_cache = NULL;
    }
    global_module_cache_count = 0;
}

/*
 * CRITICAL FIXED ALGORITHM: Build a lookahead cache of imported modules
 * before processing segment thunks to ensure proper identifier matching.
 */
void wineos2_build_module_cache(FILE* file, uint32_t ne_base, void* ne_header_ptr) {
    NE_HEADER* ne_hdr = (NE_HEADER*)ne_header_ptr;
    wineos2_free_module_cache();

    global_module_cache_count = ne_hdr->mod_count;
    if (global_module_cache_count <= 0) return;

    global_module_cache = (char**)malloc(global_module_cache_count * sizeof(char*));
    uint16_t *mod_offsets = (uint16_t*)malloc(global_module_cache_count * sizeof(uint16_t));

    fseek(file, ne_base + ne_hdr->mod_ref_table, SEEK_SET);
    fread(mod_offsets, sizeof(uint16_t), global_module_cache_count, file);

    long import_table_base = ne_base + ne_hdr->import_name;
    for (int i = 0; i < global_module_cache_count; i++) {
        fseek(file, import_table_base + mod_offsets[i], SEEK_SET);

        uint8_t len = 0;
        fread(&len, 1, 1, file);

        global_module_cache[i] = (char*)malloc(len + 1);
        fread(global_module_cache[i], 1, len, file);
        global_module_cache[i][len] = '\0';

        /* Set the dll same first */
        char dll_filename[256];
        snprintf(dll_filename, sizeof(dll_filename), "%s.DLL", global_module_cache[i]);

        /* Load the OS/2 DLL from memory */
        HMODULE hSubsystem = LoadLibraryA(dll_filename);
        if (!hSubsystem) {
            // If fails to lad the specific DLL  (ex: NLS.DLL), defaults to DOSCALLS
            hSubsystem = LoadLibraryA("DOSCALLS.DLL");
        }

        /* Clean names to uppercase and strip extensions for robust cross-matching */
        for (uint8_t j = 0; j < len; j++) {
            global_module_cache[i][j] = (char)toupper((unsigned char)global_module_cache[i][j]);
        }
        char *dot = strchr(global_module_cache[i], '.');
        if (dot) *dot = '\0';
    }
    free(mod_offsets);
}

const char* wineos2_resolve_cached_module(uint16_t module_index) {
    if (module_index > 0 && module_index <= global_module_cache_count && global_module_cache != NULL) {
        return global_module_cache[module_index - 1];
    }
    return "DOSCALLS"; // Safe OS/2 system-level fallback core
}


/*
 *  Processed the dynamic table of relocations related to the target segment.
 *  Fully aligned for unscaled 32-bit compilation targets to fix ordinal shift bug.
 */
void ne_process_relocations(FILE* file, uint32_t reloc_table_offset, void* segment_memory, void* ne_header_ptr, uint32_t ne_base) {
    NE_HEADER* ne_hdr = (NE_HEADER*)ne_header_ptr;
    uint16_t reloc_count = 0;
    uint16_t i;

    if (fseek(file, reloc_table_offset, SEEK_SET) != 0) return;
    if (fread(&reloc_count, sizeof(uint16_t), 1, file) != 1) return;

    if (reloc_count == 0 || reloc_count > 8192) return;

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
        uint8_t pure_source_type = base_item.source_type & 0x0F;

        memset(resolved_dll_name, 0, sizeof(resolved_dll_name));

        if (base_item.target_type == 0) { /* Internal Reference */
            NE_TARGET_INTERNAL target;
            if (fread(&target, sizeof(NE_TARGET_INTERNAL), 1, file) == 1) {
                resolved_selector = (target.seg_number << 3) | 3;
                internal_offset = target.offset;
                target_valid = 1;
            }
            fseek(file, item_start_pos + 8, SEEK_SET);
        }
        else if (base_item.target_type == 1 || base_item.target_type == 2) { /* External DLL Reference */
            NE_TARGET_ORDINAL target;
            if (fread(&target, sizeof(NE_TARGET_ORDINAL), 1, file) == 1) {
                target_ordinal_val = target.ordinal;

                const char* cached_name = wineos2_resolve_cached_module(target.module_index);
                lstrcpynA(resolved_dll_name, cached_name, sizeof(resolved_dll_name));

                printf("[NE Loader] Import Link -> (dll [%d] %s.DLL .... ordinal %d)\n",
                       target.module_index, resolved_dll_name, target_ordinal_val);
                fflush(stdout);

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

            if (current_offset >= 0x10000 || chain_safety_counter > 2048) break;
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
            else if (base_item.target_type == 1 || base_item.target_type == 2) {
                if (pure_source_type == 3) {
                    *(uint16_t*)patch_address = resolved_selector;
                }
                else if (pure_source_type == 5) {
                    *(uint16_t*)(patch_address + 2) = resolved_selector;
                }
            }

            if (next_offset == current_offset || next_offset == 0) break;
            current_offset = next_offset;
        }
    }
}


/* Segments processing cycle: */
int lx_process_ne_segments(FILE* file, uint32_t ne_base, void* ne_header_ptr) {
    NE_HEADER* ne_hdr = (NE_HEADER*)ne_header_ptr;
    uint32_t absolute_seg_table;
    int i;

    if (!file || !ne_hdr) return 0;

    /* Startiing the DLLs caching before processing */
    wineos2_build_module_cache(file, ne_base, ne_hdr);

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
            /*
            Sector size allignment
             */
            uint32_t sector_size = (uint32_t)(1 << ne_hdr->logical_sector);
            uint32_t file_offset = (uint32_t)seg.sector_offset * sector_size;

            /*
             Relocation Tables
             */
            long reloc_table_offset_raw = (long)(file_offset + seg.length);

            /* Fill legitimate data on emulated RAM */
            fseek(file, file_offset, SEEK_SET);
            if (seg.length > 0) {
                fread(linear_mem, 1, seg.length, file);
            }

            /* Fill dynamic fixups (0x0100) */
            if (seg.flags & 0x0100) {
                ne_process_relocations(file, reloc_table_offset_raw, linear_mem, ne_hdr, ne_base);
            }
        }

        ldt_index = i + 1;
        virtual_ldt[ldt_index].base       = (uint32_t)linear_mem;
        virtual_ldt[ldt_index].limit      = 0xFFFF;
        virtual_ldt[ldt_index].present    = 1;
        virtual_ldt[ldt_index].read_write = 1;
        virtual_ldt[ldt_index].type       = LDT_TYPE_SEGMENT;

        printf("[NE Loader] Segment #%d mapped at: %p | Selector: 0x%04X\n",
               ldt_index, linear_mem, (ldt_index << 3) | 3);
    }
    return 1;
}
