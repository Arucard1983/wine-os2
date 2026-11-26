/*
 *  lx_paging.c - OS/2 32-bit Linear Executable (LX) Paging & Decompression Engine
 *  (c) Arucard 2026 - Wine-OS/2 Project
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <ctype.h>
#include <string.h>

#include "os2types.h"

#pragma pack(push, 1)
typedef struct {
    uint32_t page_data_offset; 
    uint16_t data_size;        
    uint16_t flags;            
} LX_PAGE_ENTRY;

typedef struct {
    uint8_t  src_type;         
    uint8_t  flags;            
    uint16_t src_offset;       
    uint16_t module_index;     
    uint32_t ordinal;          
} LX_FIXUP_RECORD;

typedef struct {
    uint8_t  magic[2];               /* 0x00: 'LX' */
    uint8_t  border;                 /* 0x02 */
    uint8_t  worder;                 /* 0x03 */
    uint32_t level;                  /* 0x04 */
    uint16_t cpu_type;               /* 0x08 */
    uint16_t os_type;                /* 0x0A */
    uint32_t version;                /* 0x0C */
    uint32_t flags;                  /* 0x10 */
    uint32_t num_pages;              /* 0x14 */
    uint32_t eip_obj;                /* 0x18 */
    uint32_t eip;                    /* 0x1C */
    uint32_t esp_obj;                /* 0x20 */
    uint32_t esp;                    /* 0x24 */
    uint32_t page_size;              /* 0x28 */
    uint32_t pages_shift;            /* 0x2C */
    uint32_t fixup_sec_size;         /* 0x30 */
    uint32_t fixup_sec_chk;          /* 0x34 */
    uint32_t loader_sec_size;        /* 0x38 */
    uint32_t loader_sec_chk;         /* 0x3C */
    uint32_t obj_tbl_offset;         /* 0x40 */
    uint32_t num_objects;            /* 0x44 */
    uint32_t obj_map_offset;         /* 0x48 */
    uint32_t itermap_offset;         /* 0x4C */
    uint32_t rsrc_tbl_offset;        /* 0x50 */
    uint32_t num_rsrcs;              /* 0x54 */
    uint32_t resid_name_tbl_offset;  /* 0x58 */
    uint32_t entry_tbl_offset;       /* 0x5C */
    uint32_t mod_dir_offset;         /* 0x60 */
    uint32_t num_mod_dirs;           /* 0x64 */
    uint32_t fixup_page_tbl_offset;  /* 0x68 */
    uint32_t fixup_rec_tbl_offset;   /* 0x6C */
    uint32_t imp_mod_tbl_offset;     /* 0x70 */
    uint32_t num_imp_mods;           /* 0x74 */
    uint32_t imp_proc_tbl_offset;    /* 0x78 */
    uint32_t per_page_chk_offset;    /* 0x7C */
    uint32_t data_pages_offset;      /* 0x80: File ABSOLUTE offset! */
    uint32_t num_preload_pages;      /* 0x84 */
    uint32_t nonres_name_tbl_offset; /* 0x88: File ABSOLUTE offset! */
    uint32_t nonres_name_tbl_len;    /* 0x8C */
    uint32_t nonres_name_tbl_chk;    /* 0x90 */
    uint32_t auto_ds_obj;            /* 0x94 */
    uint32_t debug_info_offset;      /* 0x98 */
    uint32_t debug_info_len;         /* 0x9C */
    uint32_t num_inst_preload;       /* 0xA0 */
    uint32_t num_inst_demand;        /* 0xA4 */
    uint32_t heap_size;              /* 0xA8 */
    uint32_t stack_size;             /* 0xAC */
    uint8_t  reserved[20];           /* 0xB0..0xC3 */
} LX_HEADER_INTERNAL;

typedef struct {
    void* host_address;   
    uint32_t base_addr;   
    uint32_t size;        
} LX_ALLOCATED_OBJECT_INTERNAL;

typedef struct {
    uint32_t size;           
    uint32_t base_addr;      
    uint32_t flags;          
    uint32_t page_tbl_idx;   
    uint32_t num_pages;      
    uint32_t reserved;
} LX_OBJECT_INTERNAL;
#pragma pack(pop)

/* Official constants of Object Page Map Table from LX format (OS/2 2.x / Warp) */
#define LX_PAGE_VALID       0x0000  /* Raw Data (uncompressed) */
#define LX_PAGE_ITERATED    0x0001  /* Iterated Data (EXEPACK v1) */
#define LX_PAGE_INVALID     0x0002  /* Invalid Page */
#define LX_PAGE_ZEROED      0x0003  /* Filled with Zeroes (BSS) */
#define LX_PAGE_RANGE       0x0004  /* Range of pages */
#define LX_PAGE_COMPRESSED  0x0005  /* EXEPACK v2 (RLE + LZ77) */

static char **lx_module_cache = NULL;
static uint32_t lx_module_cache_count = 0;

void lx_free_module_cache(void) {
    if (lx_module_cache) {
        for (uint32_t i = 0; i < lx_module_cache_count; i++) {
            free(lx_module_cache[i]);
        }
        free(lx_module_cache);
        lx_module_cache = NULL;
    }
    lx_module_cache_count = 0;
}

/* Unpack Type 1: Iterated Data (0x0001) */
static int lx_decompress_iterated(const uint8_t* src, size_t src_size, uint8_t* dst, size_t dst_size) {
    size_t s = 0;
    size_t d = 0;

    memset(dst, 0, dst_size);

    while (s + 4 <= src_size && d < dst_size) {
        uint16_t iterations = (uint16_t)(src[s] | (src[s + 1] << 8));
        uint16_t count      = (uint16_t)(src[s + 2] | (src[s + 3] << 8));
        s += 4;

        if (iterations == 0 || count == 0) break;
        if (s + count > src_size) {
            fprintf(stderr, "[LX Decompress] Error: Iterated data truncated.\n");
            return 0;
        }

        for (uint16_t i = 0; i < iterations; i++) {
            size_t to_copy = (d + count <= dst_size) ? count : (dst_size - d);
            memcpy(dst + d, src + s, to_copy);
            d += to_copy;
            if (d >= dst_size) break;
        }
        s += count;
    }
    return 1;
}

/* Unpack Type 5: EXEPACK v2 / RLE-LZ (0x0005) */
static int lx_decompress_exepack2(const uint8_t* src, size_t src_size, uint8_t* dst, size_t dst_size) {
    size_t s = 0;
    size_t d = 0;

    memset(dst, 0, dst_size);

    while (s + 2 <= src_size && d < dst_size) {
        uint16_t cmd = (uint16_t)(src[s] | (src[s + 1] << 8));
        s += 2;

        if (cmd == 0x0000) break; /* End of compressed stream */

            uint8_t op = cmd & 0x03;

        if (op == 0x00) {
            /* Literal copy  of 'len' bytes */
            uint16_t len = (cmd >> 2) & 0x3F;
            if (len == 0) break;
            if (s + len > src_size || d + len > dst_size) {
                fprintf(stderr, "[LX Decompress] Error: EXEPACK2 Literal Overflow.\n");
                return 0;
            }
            memcpy(dst + d, src + s, len);
            s += len;
            d += len;
        }
        else if (op == 0x01) {
            /* Short Back-reference (3..10 bytes, distance until 2047) */
            uint16_t len  = ((cmd >> 2) & 0x07) + 3;
            uint16_t dist = (cmd >> 5) & 0x07FF;
            if (dist == 0 || dist > d || d + len > dst_size) {
                fprintf(stderr, "[LX Decompress] Error: Invalid short Back-refrence (dist=%u, d=%zu).\n", dist, d);
                return 0;
            }
            /* mandatory byte-to-byte copy (suport overlay style RLE) */
            for (uint16_t i = 0; i < len; i++) {
                dst[d] = dst[d - dist];
                d++;
            }
        }
        else if (op == 0x02) {
            /* RLE: Repeat 1 byte 'len' times */
            uint16_t len = ((cmd >> 2) & 0x3F) + 3;
            if (s + 1 > src_size || d + len > dst_size) {
                fprintf(stderr, "[LX Decompress] Error: EXEPACK2 RLE Overflow.\n");
                return 0;
            }
            uint8_t val = src[s++];
            memset(dst + d, val, len);
            d += len;
        }
        else if (op == 0x03) {
            /* Long Back-reference (3 bytes of comand: len 4..67, 16-bit distance) */
            if (s + 1 > src_size) {
                fprintf(stderr, "[LX Decompress] Error: EXEPACK2 Long Command truncated.\n");
                return 0;
            }
            uint32_t full = (uint32_t)cmd | ((uint32_t)src[s++] << 16);
            uint16_t len  = ((full >> 2) & 0x3F) + 4;
            uint16_t dist = (full >> 8) & 0xFFFF;
            if (dist == 0 || dist > d || d + len > dst_size) {
                fprintf(stderr, "[LX Decompress] Error: Invalid long Back-reference (dist=%u, d=%zu).\n", dist, d);
                return 0;
            }
            for (uint16_t i = 0; i < len; i++) {
                dst[d] = dst[d - dist];
                d++;
            }
        }
    }
    return 1;
}

/* Unified dispatcher called by lx_process_object_pages */
int lx_decompress_page(uint16_t page_type, const uint8_t* src, size_t src_size, uint8_t* dst, size_t dst_size) {
    if (!src || !dst) return 0;

    if (page_type == LX_PAGE_ITERATED) {
        return lx_decompress_iterated(src, src_size, dst, dst_size);
    }
    if (page_type == LX_PAGE_COMPRESSED) {
        return lx_decompress_exepack2(src, src_size, dst, dst_size);
    }
    return 0;
}


/* Similar to wineos2_build_module_cache of NE */
void lx_build_module_cache(FILE* file, uint32_t lx_base, LX_HEADER_INTERNAL* lx_hdr) {
    lx_free_module_cache();
    if (!lx_hdr || lx_hdr->num_imp_mods == 0) return;

    lx_module_cache_count = lx_hdr->num_imp_mods;
    lx_module_cache = (char**)calloc(lx_module_cache_count, sizeof(char*));

    fseek(file, lx_base + lx_hdr->imp_mod_tbl_offset, SEEK_SET);
    for (uint32_t i = 0; i < lx_module_cache_count; i++) {
        uint8_t len = 0;
        if (fread(&len, 1, 1, file) != 1) break;

        lx_module_cache[i] = (char*)calloc(len + 1, 1);
        if (len > 0) {
            fread(lx_module_cache[i], 1, len, file);
            for (uint8_t j = 0; j < len; j++) {
                lx_module_cache[i][j] = (char)toupper((unsigned char)lx_module_cache[i][j]);
            }
        }
        printf("[LX Loader] Imported Module [%u]: %s\n", i + 1, lx_module_cache[i]);
    }
}

static const char* lx_get_cached_module(uint32_t module_index) {
    if (module_index > 0 && module_index <= lx_module_cache_count && lx_module_cache[module_index - 1]) {
        return lx_module_cache[module_index - 1];
    }
    return "DOSCALLS";
}


/* Lê e imprime Resident Name Table, Non-Resident Name Table e Entry Table */
void lx_dump_exported_symbols(FILE* file, uint32_t lx_base, LX_HEADER_INTERNAL* lx_hdr) {
    uint8_t len = 0;
    char name[256] = {0};
    uint16_t ordinal = 0;

    printf("\n--- LX EXPORTED SYMBOLS (Resident & Non-Resident Names) ---\n");

    /* 1. Resident Name Table (offset relativo a lx_base) */
    if (lx_hdr->resid_name_tbl_offset > 0) {
        fseek(file, lx_base + lx_hdr->resid_name_tbl_offset, SEEK_SET);
        int idx = 0;
        while (fread(&len, 1, 1, file) == 1 && len > 0) {
            fread(name, 1, len, file);
            name[len] = '\0';
            fread(&ordinal, sizeof(uint16_t), 1, file);
            if (idx == 0) {
                printf("  [Module Name] %s\n", name);
            } else {
                printf("  [Resident]    Ordinal #%u -> %s\n", ordinal, name);
            }
            idx++;
        }
    }

    /* 2. Non-Resident Name Table (offset ABSOLUTO no ficheiro!) */
    if (lx_hdr->nonres_name_tbl_offset > 0 && lx_hdr->nonres_name_tbl_len > 0) {
        fseek(file, lx_hdr->nonres_name_tbl_offset, SEEK_SET);
        int idx = 0;
        while (fread(&len, 1, 1, file) == 1 && len > 0) {
            fread(name, 1, len, file);
            name[len] = '\0';
            fread(&ordinal, sizeof(uint16_t), 1, file);
            if (idx == 0) {
                printf("  [Description] %s\n", name);
            } else {
                printf("  [Non-Resid]   Ordinal #%u -> %s\n", ordinal, name);
            }
            idx++;
        }
    }

    /* 3. Entry Table (Pontos de Entrada por Ordinal) */
    if (lx_hdr->entry_tbl_offset > 0) {
        fseek(file, lx_base + lx_hdr->entry_tbl_offset, SEEK_SET);
        uint32_t current_ord = 1;
        while (1) {
            uint8_t count = 0, type = 0;
            if (fread(&count, 1, 1, file) != 1 || count == 0) break;
            if (fread(&type, 1, 1, file) != 1) break;

            if (type == 0x00) {
                current_ord += count;
            } else {
                uint16_t obj_num = 0;
                if (type != 0x04) fread(&obj_num, 2, 1, file);

                for (uint8_t i = 0; i < count; i++) {
                    uint8_t flags = 0;
                    fread(&flags, 1, 1, file);
                    if (type == 0x01) {
                        uint16_t off16 = 0;
                        fread(&off16, 2, 1, file);
                        printf("  [Entry 16b]   Ordinal #%u -> Obj %u : 0x%04X\n", current_ord, obj_num, off16);
                    } else if (type == 0x02) {
                        uint16_t off16 = 0, cg = 0;
                        fread(&off16, 2, 1, file);
                        fread(&cg, 2, 1, file);
                        printf("  [CallGate]    Ordinal #%u -> Obj %u : 0x%04X\n", current_ord, obj_num, off16);
                    } else if (type == 0x03) {
                        uint32_t off32 = 0;
                        fread(&off32, 4, 1, file);
                        printf("  [Entry 32b]   Ordinal #%u -> Obj %u : 0x%08X\n", current_ord, obj_num, off32);
                    } else if (type == 0x04) {
                        uint16_t mod_ord = 0;
                        uint32_t proc_off = 0;
                        fread(&mod_ord, 2, 1, file);
                        fread(&proc_off, 4, 1, file);
                        printf("  [Forwarder]   Ordinal #%u -> Mod #%u : 0x%08X\n", current_ord, mod_ord, proc_off);
                    }
                    current_ord++;
                }
            }
        }
    }
    printf("-----------------------------------------------------------\n\n");
    fflush(stdout);
}

/* Resolução de Fixups e Listagem Completa de Ordinais/Símbolos Importados */
int wineos2_resolve_lx_fixups(FILE* file, uint32_t lx_base, LX_HEADER_INTERNAL* lx_hdr,
                              LX_OBJECT_INTERNAL* objects, LX_ALLOCATED_OBJECT_INTERNAL* allocated_objects) {
    if (!file || !lx_hdr || !objects || !allocated_objects) return 0;

    lx_build_module_cache(file, lx_base, lx_hdr);
    lx_dump_exported_symbols(file, lx_base, lx_hdr);

    if (lx_hdr->fixup_sec_size == 0 || lx_hdr->num_pages == 0) return 1;

    uint32_t* fixup_page_offsets = (uint32_t*)malloc((lx_hdr->num_pages + 1) * sizeof(uint32_t));
    if (!fixup_page_offsets) return 0;

    fseek(file, lx_base + lx_hdr->fixup_page_tbl_offset, SEEK_SET);
    if (fread(fixup_page_offsets, sizeof(uint32_t), lx_hdr->num_pages + 1, file) != lx_hdr->num_pages + 1) {
        free(fixup_page_offsets);
        return 0;
    }

    uint32_t page_size = lx_hdr->page_size ? lx_hdr->page_size : 4096;
    uint32_t rec_tbl_base = lx_base + lx_hdr->fixup_rec_tbl_offset;

    printf("--- LX IMPORTED SYMBOLS & FIXUPS ---\n");

    for (uint32_t obj_idx = 0; obj_idx < lx_hdr->num_objects; obj_idx++) {
        LX_OBJECT_INTERNAL* obj = &objects[obj_idx];
        uint8_t* obj_mem = (uint8_t*)allocated_objects[obj_idx].host_address;
        if (!obj_mem || obj->num_pages == 0) continue;

        for (uint32_t p = 0; p < obj->num_pages; p++) {
            uint32_t global_page_idx = (obj->page_tbl_idx - 1) + p;
            if (global_page_idx >= lx_hdr->num_pages) break;

            uint32_t rec_start = fixup_page_offsets[global_page_idx];
            uint32_t rec_end   = fixup_page_offsets[global_page_idx + 1];
            uint8_t* page_host_addr = obj_mem + (p * page_size);

            fseek(file, rec_tbl_base + rec_start, SEEK_SET);

            while ((uint32_t)(ftell(file) - rec_tbl_base) < rec_end) {
                uint8_t src_type = 0, flags = 0;
                fread(&src_type, 1, 1, file);
                fread(&flags, 1, 1, file);

                uint8_t pure_src    = src_type & 0x0F;
                uint8_t has_srclist = (src_type & 0x20) != 0;
                uint8_t target_type = flags & 0x03;

                uint8_t srclist_cnt = 0;
                int16_t single_src_off = 0;

                if (has_srclist) {
                    fread(&srclist_cnt, 1, 1, file);
                } else {
                    fread(&single_src_off, sizeof(int16_t), 1, file);
                }

                uint32_t resolved_target_addr = 0;

                if (target_type == 0x00) {
                    /* Internal Reference */
                    uint16_t target_obj = 0;
                    uint32_t target_off = 0;
                    if (flags & 0x40) fread(&target_obj, 2, 1, file);
                    else { uint8_t o8 = 0; fread(&o8, 1, 1, file); target_obj = o8; }

                    if (pure_src != 0x02) {
                        if (flags & 0x10) fread(&target_off, 4, 1, file);
                        else { uint16_t off16 = 0; fread(&off16, 2, 1, file); target_off = off16; }
                    }
                    if (target_obj > 0 && target_obj <= lx_hdr->num_objects) {
                        resolved_target_addr = (uint32_t)(uintptr_t)allocated_objects[target_obj - 1].host_address + target_off;
                    }
                }
                else if (target_type == 0x01) {
                    /* Imported by Ordinal */
                    uint16_t mod_idx = 0;
                    uint32_t ord = 0;
                    if (flags & 0x40) fread(&mod_idx, 2, 1, file);
                    else { uint8_t m8 = 0; fread(&m8, 1, 1, file); mod_idx = m8; }

                    if (flags & 0x80) { uint8_t o8 = 0; fread(&o8, 1, 1, file); ord = o8; }
                    else if (flags & 0x10) fread(&ord, 4, 1, file);
                    else { uint16_t o16 = 0; fread(&o16, 2, 1, file); ord = o16; }

                    const char* mod_name = lx_get_cached_module(mod_idx);
                    printf("[LX Loader] Import Link -> Obj %u Page %u : (dll [%u] %s.DLL .... ordinal #%u)\n",
                           obj_idx + 1, p + 1, mod_idx, mod_name, ord);

                    char dll_name[256] = {0};
                    snprintf(dll_name, sizeof(dll_name), "%s.dll", mod_name);
                    HMODULE hMod = GetModuleHandleA(dll_name);
                    if (!hMod) hMod = LoadLibraryA(dll_name);
                    if (hMod) {
                        resolved_target_addr = (uint32_t)(uintptr_t)GetProcAddress(hMod, (LPCSTR)(uintptr_t)ord);
                    }
                }
                else if (target_type == 0x02) {
                    /* Imported by Name */
                    uint16_t mod_idx = 0;
                    uint32_t proc_name_off = 0;
                    if (flags & 0x40) fread(&mod_idx, 2, 1, file);
                    else { uint8_t m8 = 0; fread(&m8, 1, 1, file); mod_idx = m8; }

                    if (flags & 0x10) fread(&proc_name_off, 4, 1, file);
                    else { uint16_t p16 = 0; fread(&p16, 2, 1, file); proc_name_off = p16; }

                    long saved_pos = ftell(file);
                    fseek(file, lx_base + lx_hdr->imp_proc_tbl_offset + proc_name_off, SEEK_SET);
                    uint8_t name_len = 0;
                    char proc_name[256] = {0};
                    if (fread(&name_len, 1, 1, file) == 1 && name_len > 0) {
                        fread(proc_name, 1, name_len, file);
                        proc_name[name_len] = '\0';
                    }
                    fseek(file, saved_pos, SEEK_SET);

                    const char* mod_name = lx_get_cached_module(mod_idx);
                    printf("[LX Loader] Import Name -> Obj %u Page %u : (dll [%u] %s.DLL .... %s)\n",
                           obj_idx + 1, p + 1, mod_idx, mod_name, proc_name);

                    char dll_name[256] = {0};
                    snprintf(dll_name, sizeof(dll_name), "%s.dll", mod_name);
                    HMODULE hMod = GetModuleHandleA(dll_name);
                    if (!hMod) hMod = LoadLibraryA(dll_name);
                    if (hMod) {
                        resolved_target_addr = (uint32_t)(uintptr_t)GetProcAddress(hMod, proc_name);
                    }
                }
                else if (target_type == 0x03) {
                    /* Internal Entry Table Reference */
                    uint16_t entry_ord = 0;
                    if (flags & 0x40) fread(&entry_ord, 2, 1, file);
                    else { uint8_t e8 = 0; fread(&e8, 1, 1, file); entry_ord = e8; }
                    printf("[LX Loader] Internal Entry -> Ordinal #%u\n", entry_ord);
                }
                uint32_t additive = 0;
                if (flags & 0x04) {
                    if (flags & 0x20) fread(&additive, 4, 1, file);
                    else { uint16_t a16 = 0; fread(&a16, 2, 1, file); additive = a16; }
                }
                uint16_t count = has_srclist ? srclist_cnt : 1;
                for (uint16_t s = 0; s < count; s++) {
                    int16_t page_off = single_src_off;
                    if (has_srclist) fread(&page_off, sizeof(int16_t), 1, file);
                    if (resolved_target_addr != 0 && page_off >= 0 && (uint32_t)page_off < page_size) {
                        uint8_t* patch_ptr = page_host_addr + page_off;
                        uint32_t final_val = resolved_target_addr + additive;
                        if (pure_src == 0x07) {
                            *(uint32_t*)patch_ptr = final_val;
                        } else if (pure_src == 0x08) {
                            *(uint32_t*)patch_ptr = final_val - ((uint32_t)(uintptr_t)patch_ptr + 4);
                        }
                    }
                }
            }
        }
    }
    printf("------------------------------------\n\n");
    free(fixup_page_offsets);
    fflush(stdout);
    return 1;
}

int lx_process_object_pages(FILE* file, uint32_t lx_base, LX_HEADER_INTERNAL* hdr,
                            LX_OBJECT_INTERNAL* objects, LX_ALLOCATED_OBJECT_INTERNAL* allocated_objects) {
    if (!file || !hdr || !objects || !allocated_objects) return 0;

    uint32_t page_size = hdr->page_size ? hdr->page_size : 4096;
    uint32_t obj_map_base = lx_base + hdr->obj_map_offset;

    for (uint32_t i = 0; i < hdr->num_objects; i++) {
        LX_OBJECT_INTERNAL* obj = &objects[i];
        uint8_t* obj_host_base = (uint8_t*)allocated_objects[i].host_address;

        if (!obj_host_base || obj->num_pages == 0) continue;

        for (uint32_t p = 0; p < obj->num_pages; p++) {
            uint32_t global_page_idx = (obj->page_tbl_idx - 1) + p;
            uint32_t map_entry_offset = obj_map_base + (global_page_idx * sizeof(LX_PAGE_ENTRY));

            LX_PAGE_ENTRY page_entry;
            fseek(file, map_entry_offset, SEEK_SET);
            if (fread(&page_entry, sizeof(LX_PAGE_ENTRY), 1, file) != 1) {
                fprintf(stderr, "[LX Paging] Erro ao ler entrada %u da Object Page Map.\n", global_page_idx);
                return 0;
            }

            uint8_t* dest_addr = obj_host_base + (p * page_size);
            uint32_t file_data_pos = hdr->data_pages_offset + (page_entry.page_data_offset << hdr->pages_shift);

            switch (page_entry.flags) {
                case LX_PAGE_VALID: {
                    memset(dest_addr, 0, page_size);
                    if (page_entry.data_size > 0) {
                        size_t to_read = (page_entry.data_size < page_size) ? page_entry.data_size : page_size;
                        fseek(file, file_data_pos, SEEK_SET);
                        fread(dest_addr, 1, to_read, file);
                    }
                    break;
                }

                case LX_PAGE_ITERATED:
                case LX_PAGE_COMPRESSED: {
                    memset(dest_addr, 0, page_size);
                    if (page_entry.data_size > 0) {
                        uint8_t* comp_buf = (uint8_t*)malloc(page_entry.data_size);
                        if (!comp_buf) return 0;

                        fseek(file, file_data_pos, SEEK_SET);
                        fread(comp_buf, 1, page_entry.data_size, file);

                        if (!lx_decompress_page(page_entry.flags, comp_buf, page_entry.data_size, dest_addr, page_size)) {
                            fprintf(stderr, "[LX Paging] Falha na descompressão da página %u (flags=0x%04X).\n",
                                    global_page_idx, page_entry.flags);
                            free(comp_buf);
                            return 0;
                        }
                        free(comp_buf);
                    }
                    break;
                }

                case LX_PAGE_ZEROED:
                case LX_PAGE_INVALID:
                default:
                    memset(dest_addr, 0, page_size);
                    break;
            }
        }
    }

    return 1;
}

