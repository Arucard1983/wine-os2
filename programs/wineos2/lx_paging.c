/*
 *  lx_paging.c - OS/2 32-bit Linear Executable (LX) Paging & Decompression Engine
 *  (c) Arucard 2026 - Wine-OS/2 Project
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
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
    uint8_t  magic[2];     
    uint8_t  border;         
    uint8_t  worder;         
    uint32_t level;          
    uint16_t cpu_type;       
    uint16_t os_type;        
    uint32_t version;        
    uint32_t flags;          
    uint32_t num_pages;      
    uint32_t eip_obj;        
    uint32_t eip;            
    uint32_t esp_obj;        
    uint32_t esp;            
    uint32_t page_size;      
    uint32_t pages_shift;    
    uint32_t fixup_sec_size; 
    uint32_t fixup_sec_chk;  
    uint32_t loader_sec_size;
    uint32_t loader_sec_chk; 
    uint32_t obj_tbl_offset; 
    uint32_t num_objects;    
    uint32_t obj_map_offset; 
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

#define LX_PAGE_UNCOMPRESSED 0x0000
#define LX_PAGE_COMPRESSED   0x0001
#define LX_PAGE_ZEROFILL     0x0003

static void lx_resolve_module_name(FILE* file, uint32_t ne_base, LX_HEADER_INTERNAL* lx_hdr, uint32_t module_index, char* out_name) {
    uint32_t table_offset;
    uint32_t current_idx = 1;
    uint8_t len = 0;

    if (!file || !lx_hdr || module_index == 0 || !out_name) {
        strcpy(out_name, "DOSCALLS"); 
        return;
    }

    table_offset = ne_base + lx_hdr->obj_map_offset; 
    if (fseek(file, table_offset, SEEK_SET) != 0) {
        strcpy(out_name, "DOSCALLS");
        return;
    }
    
    while (current_idx <= 256) {
        if (fread(&len, sizeof(uint8_t), 1, file) != 1 || len == 0) break;

        if (current_idx == module_index) {
            uint8_t read_len = (len > 127) ? 127 : len;
            if (fread(out_name, 1, read_len, file) == read_len) {
                out_name[read_len] = '\0';
                if (len > read_len) fseek(file, len - read_len, SEEK_CUR);
                return;
            }
            break;
        }
        fseek(file, len, SEEK_CUR);
        current_idx++;
    }
    strcpy(out_name, "DOSCALLS");
}

int wineos2_resolve_lx_fixups(FILE* file, uint32_t ne_base, LX_HEADER_INTERNAL* lx_hdr, LX_ALLOCATED_OBJECT_INTERNAL* allocated_objects) {
    uint32_t fixup_table_pos, fixup_size, bytes_processed = 0;

    if (!file || !lx_hdr || !allocated_objects) return 0;

    fixup_table_pos = ne_base + lx_hdr->fixup_sec_chk; 
    fixup_size = lx_hdr->fixup_sec_size;

    if (fixup_size == 0) return 1;
    if (fseek(file, fixup_table_pos, SEEK_SET) != 0) return 0;

    while (bytes_processed < fixup_size) {
        uint8_t src_type = 0, flags = 0;

        if (fread(&src_type, sizeof(uint8_t), 1, file) != 1) break;
        if (fread(&flags, sizeof(uint8_t), 1, file) != 1) break;
        bytes_processed += 2;

        if ((src_type == 0x07) && (flags & 0x10)) {
            uint16_t src_offset = 0, module_index = 0;
            uint32_t target_ordinal = 0;
            uint8_t ordinal_size;
            char target_module[128], dll_filename[256];
            HMODULE hModule;

            if (fread(&src_offset, sizeof(uint16_t), 1, file) != 1) break;
            if (fread(&module_index, sizeof(uint16_t), 1, file) != 1) break;
            bytes_processed += 4;

            ordinal_size = (flags & 0x03); 
            if (ordinal_size == 1) {
                uint8_t ord8 = 0;
                if (fread(&ord8, 1, 1, file) != 1) break;
                target_ordinal = ord8;
                bytes_processed += 1;
            } else if (ordinal_size == 2) {
                uint16_t ord16 = 0;
                if (fread(&ord16, 2, 1, file) != 1) break;
                target_ordinal = ord16;
                bytes_processed += 2;
            } else {
                if (fread(&target_ordinal, 4, 1, file) != 1) break;
                bytes_processed += 4;
            }

            lx_resolve_module_name(file, ne_base, lx_hdr, module_index, target_module);
            snprintf(dll_filename, sizeof(dll_filename), "%s.dll", target_module);

            hModule = GetModuleHandleA(dll_filename);
            if (!hModule) hModule = LoadLibraryA(dll_filename);

            if (hModule) {
                FARPROC target_api_thunk = GetProcAddress(hModule, (LPCSTR)(uintptr_t)target_ordinal);
                if (target_api_thunk) {
                    void* target_patch_address = NULL;
                    uint32_t obj_idx;
                    
                    for (obj_idx = 0; obj_idx < lx_hdr->num_objects; obj_idx++) {
                        uint32_t start_range = allocated_objects[obj_idx].base_addr;
                        uint32_t end_range = start_range + allocated_objects[obj_idx].size;
                        if (src_offset >= start_range && src_offset < end_range) {
                            target_patch_address = (uint8_t*)allocated_objects[obj_idx].host_address + (src_offset - start_range);
                            break;
                        }
                    }

                    if (!target_patch_address && allocated_objects[0].host_address) {
                        target_patch_address = (uint8_t*)allocated_objects[0].host_address + src_offset;
                    }

                    if (target_patch_address && !IsBadWritePtr(target_patch_address, sizeof(uint32_t))) {
                        DWORD old_protect;
                        VirtualProtect(target_patch_address, sizeof(uint32_t), PAGE_READWRITE, &old_protect);
                        *(uint32_t*)target_patch_address = (uint32_t)(uintptr_t)target_api_thunk;
                        VirtualProtect(target_patch_address, sizeof(uint32_t), old_protect, &old_protect);
                    }
                }
            }
        } else {
            fseek(file, 2, SEEK_CUR);
            bytes_processed += 2;
        }
    }
    return 1;
}

static int lx_decompress_page(const uint8_t* src, uint32_t src_len, uint8_t* dest, uint32_t dest_len) {
    if (src_len == dest_len) {
        memcpy(dest, src, dest_len);
        return 1;
    }
    memset(dest, 0, dest_len);
    if (src_len <= dest_len) memcpy(dest, src, src_len);
    return 1;
}

int lx_process_object_pages(FILE* file, uint32_t ne_base, LX_HEADER_INTERNAL* hdr, LX_OBJECT_INTERNAL* obj, void* target_allocated_addr) {
    uint32_t page_size, page_map_offset, start_page_idx, total_pages, i;
    uint8_t *dest_ptr, *file_page_buffer;

    if (!file || !hdr || !obj || !target_allocated_addr) return 0;

    page_size = hdr->page_size ? hdr->page_size : 4096;
    page_map_offset = ne_base + hdr->obj_map_offset;
    start_page_idx = obj->page_tbl_idx - 1; 
    total_pages = obj->num_pages;

    dest_ptr = (uint8_t*)target_allocated_addr;
    file_page_buffer = (uint8_t*)malloc(page_size);
    if (!file_page_buffer) return 0;

    for (i = 0; i < total_pages; i++) {
        LX_PAGE_ENTRY page_entry;
        uint32_t entry_file_pos = page_map_offset + ((start_page_idx + i) * sizeof(LX_PAGE_ENTRY));
        uint8_t page_type;
        uint32_t current_page_dest_limit = page_size;

        fseek(file, entry_file_pos, SEEK_SET);
        if (fread(&page_entry, sizeof(LX_PAGE_ENTRY), 1, file) != 1) {
            free(file_page_buffer);
            return 0;
        }

        page_type = page_entry.flags & 0x000F;
        if ((i * page_size) + page_size > obj->size) {
            current_page_dest_limit = obj->size - (i * page_size);
        }

        switch (page_type) {
            case LX_PAGE_UNCOMPRESSED: {
                fseek(file, ne_base + (page_entry.page_data_offset << hdr->pages_shift), SEEK_SET);
                memset(dest_ptr, 0, current_page_dest_limit);
                fread(dest_ptr, 1, current_page_dest_limit, file);
                break;
            }
            case LX_PAGE_COMPRESSED: {
                fseek(file, ne_base + (page_entry.page_data_offset << hdr->pages_shift), SEEK_SET);
                fread(file_page_buffer, 1, page_entry.data_size, file);
                lx_decompress_page(file_page_buffer, page_entry.data_size, dest_ptr, current_page_dest_limit);
                break;
            }
            case LX_PAGE_ZEROFILL:
            default:
                memset(dest_ptr, 0, current_page_dest_limit);
                break;
        }
        dest_ptr += page_size;
    }

    free(file_page_buffer);
    return 1;
}
