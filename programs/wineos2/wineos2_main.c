/*
 *  wineos2_main.c - Executive NE/LX Loader Engine for Wine-OS/2 (Win32 Target)
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
#include "wineos2_env.h"

/* ENFORCED FIX: Centralized global memory allocation instance for the shared virtual LDT */
OS2_LDT_ENTRY virtual_ldt[LDT_MAX_ENTRIES];

/* Forward declarations for the loader components */
int lx_process_object_pages(FILE* file, uint32_t ne_base, void* hdr, void* obj, void* addr);
int lx_process_ne_segments(FILE* file, uint32_t ne_base, void* ne_header_ptr);
int wineos2_resolve_lx_fixups(FILE* file, uint32_t ne_base, void* lx_hdr, void* allocated_objects);
void wineos2_initialize_lx_stack(void* stack_ptr, uint32_t stack_size, CONTEXT* thread_ctx);

#pragma pack(push, 1)

/* OS/2 1.x / Win16 NE Header Structure */
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

/* OS/2 2.x+ LX (Linear Executable) Header Structure */
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
} LX_HEADER;

typedef struct {
    uint32_t size;
    uint32_t base_addr;
    uint32_t flags;
    uint32_t page_tbl_idx;
    uint32_t num_pages;
    uint32_t reserved;
} LX_OBJECT;

#define MAX_LX_OBJECTS 64
typedef struct {
    void* host_address;
    uint32_t base_addr;
    uint32_t size;
} LX_ALLOCATED_OBJECT;

typedef struct {
    uint8_t  source_type;
    uint8_t  target_flags;
    uint16_t source_offset;

    union {
        struct {
            uint16_t module_index;
            uint16_t ordinal;
        } imported_ordinal;
    } target;
} NE_RELOCATION_ENTRY;

#pragma pack(pop)

void wineos2_initialize_lx_stack(void* stack_ptr, uint32_t stack_size, CONTEXT* thread_ctx) {
    fprintf(stderr, "[FIXME] wineos2_initialize_lx_stack not functional.\n");
}

int wineos2_execute_lx_process_win32(FILE* file, uint32_t ne_lfanew, uint32_t active_pib_address) {
    LX_HEADER lx_hdr;
    LX_ALLOCATED_OBJECT allocated_objects[MAX_LX_OBJECTS];
    uint32_t target_entry_eip = 0;
    uint32_t absolute_obj_table;
    uint32_t i;

    if (!file) return 0;
    memset(allocated_objects, 0, sizeof(allocated_objects));

    if (fseek(file, ne_lfanew, SEEK_SET) != 0) return 0;
    if (fread(&lx_hdr, sizeof(LX_HEADER), 1, file) != 1) return 0;

    printf("[Loader] Parsing LX (Linear Executable) 32-bit OS/2 structure...\n");
    absolute_obj_table = ne_lfanew + lx_hdr.obj_tbl_offset;

    for (i = 0; i < lx_hdr.num_objects && i < MAX_LX_OBJECTS; i++) {
        LX_OBJECT obj;
        void* allocated_address;
        DWORD old_protect;

        fseek(file, absolute_obj_table + (i * sizeof(LX_OBJECT)), SEEK_SET);
        if (fread(&obj, sizeof(LX_OBJECT), 1, file) != 1) break;

        if (obj.size == 0) continue;

        allocated_address = VirtualAlloc((LPVOID)(uintptr_t)obj.base_addr, obj.size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!allocated_address) {
            printf("[LX Error] Critical memory allocation mapping failed at 0x%08X\n", obj.base_addr);
            return 0;
        }

        allocated_objects[i].host_address = allocated_address;
        allocated_objects[i].base_addr = obj.base_addr;
        allocated_objects[i].size = obj.size;

        lx_process_object_pages(file, ne_lfanew, &lx_hdr, &obj, allocated_address);

        if (obj.flags & 0x0004) {
            VirtualProtect(allocated_address, obj.size, PAGE_EXECUTE_READWRITE, &old_protect);
        } else {
            VirtualProtect(allocated_address, obj.size, PAGE_READWRITE, &old_protect);
        }

        if (i + 1 == lx_hdr.eip_obj) target_entry_eip = obj.base_addr + lx_hdr.eip;
    }

    wineos2_resolve_lx_fixups(file, ne_lfanew, &lx_hdr, allocated_objects);

    STARTUPINFOA si = { sizeof(STARTUPINFOA) };
    PROCESS_INFORMATION pi;
    CONTEXT thread_ctx;

    BOOL success = CreateProcessA(NULL, "wineos2_stub.exe", NULL, NULL, FALSE,
                                  CREATE_SUSPENDED, NULL, NULL, &si, &pi);
    if (!success) {
        printf("[LX Error] Failed to generate a clean isolated Win32 thread context.\n");
        return 0;
    }

    thread_ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(pi.hThread, &thread_ctx);

    wineos2_initialize_lx_stack((void*)(thread_ctx.Esp - 65536), 65536, &thread_ctx);
    thread_ctx.Eip = target_entry_eip;
    thread_ctx.Ebx = active_pib_address;

    SetThreadContext(pi.hThread, &thread_ctx);

    printf("\n--- EMBEDDED ENGINE SYSTEM TRACE END: RUNNING NATIVE 32-BIT LX CONTEXT ---\n\n");
    fflush(stdout);

    ResumeThread(pi.hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return 1;
}

int wineos2_execute_ne_process(FILE* file, uint32_t ne_lfanew, uint32_t active_pib_address) {
    NE_HEADER ne_hdr;
    CPU286_Context cpu_context;
    uint16_t auto_data_selector;

    fseek(file, ne_lfanew, SEEK_SET);
    if (fread(&ne_hdr, sizeof(NE_HEADER), 1, file) != 1) return 0;

    printf("[Loader] Parsing NE (New Executable) 16-bit OS/2 structure...\n");

    if (ne_hdr.target_os != 1) {
        printf("[NE Error] Unsupported target OS mode inside NE header: %d\n", ne_hdr.target_os);
        return 0;
    }

    if (!lx_process_ne_segments(file, ne_lfanew, &ne_hdr)) {
        printf("[NE Error] Critical segment table expansion mapping pipeline failed.\n");
        return 0;
    }

    memset(&cpu_context, 0, sizeof(CPU286_Context));

    cpu_context.cs = (ne_hdr.initial_cs_seg << 3) | 3;
    cpu_context.ip = ne_hdr.initial_ip;

    if (ne_hdr.initial_ss_seg == 0) {
        cpu_context.ss = 0x0013;
        cpu_context.sp = 0xFFFE;
    } else {
        cpu_context.ss = (ne_hdr.initial_ss_seg << 3) | 3;
        cpu_context.sp = ne_hdr.initial_sp;
    }

    /* ENFORCED FIX: Fix the bug of SP=0x0000 on start-up to avoid fake Stack Overflow */
    if (cpu_context.sp == 0x0000) {
        cpu_context.sp = 0xFFFE;
    }

    auto_data_selector = 0x0013;
    cpu_context.ax = auto_data_selector;
    cpu_context.ds = auto_data_selector;
    cpu_context.bx = 0x0100;
    cpu_context.cx = 0x4000;
    cpu_context.flags = 0x0202;

    uint16_t required_idx = 0x0013 >> 3; /* Índice 2 */
    if (!virtual_ldt[required_idx].present) {
        void* data_mem = VirtualAlloc(NULL, 0x10000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!data_mem) {
            printf("[NE Loader Error] Failed to allocate automatic data segment space.\n");
            return 0;
        }
        memset(data_mem, 0, 0x10000);

        virtual_ldt[required_idx].base       = (uintptr_t)data_mem;
        virtual_ldt[required_idx].limit      = 0xFFFF;
        virtual_ldt[required_idx].present    = 1;
        virtual_ldt[required_idx].read_write = 1;
        virtual_ldt[required_idx].type       = LDT_TYPE_SEGMENT;

        printf("[NE Loader] Emergency LDT Alloc -> Created Data/Stack Segment at: %p | Selector: 0x0013\n",
               data_mem);
    }

    printf("\n[NE Loader] Reconstructed environment -> CS:IP = 0x%04X:0x%04X | Auto Data DS: 0x%04X | SP: 0x%04X\n",
           cpu_context.cs, cpu_context.ip, cpu_context.ds, cpu_context.sp);
    printf("--- EMBEDDED INTERPRETER SYSTEM TRACE END: LAUNCHING 286 EMULATOR ---\n\n");
    fflush(stdout);

    while(1) {
        cpu286_execute_opcode(&cpu_context);
    }
    return 1;
}

__declspec(dllexport) void* CDECL wineos2_get_ldt_ptr(void) {
    return (void*)virtual_ldt;
}

__declspec(dllexport) uint16_t CDECL wineos2_register_callgate(const char* mod_name, uint16_t ordinal, uint16_t param_bytes, void* thunk_ptr) {
    uint16_t i;
    for (i = 500; i < LDT_MAX_ENTRIES; i++) {
        if (!virtual_ldt[i].present) {
            virtual_ldt[i].wine_thunk   = (uintptr_t)thunk_ptr; /* FIXED: Correct casting using uintptr_t */
            virtual_ldt[i].limit        = ordinal;
            virtual_ldt[i].param_bytes  = param_bytes;
            virtual_ldt[i].present      = 1;
            virtual_ldt[i].type         = LDT_TYPE_CALLGATE;

            if (mod_name) {
                lstrcpynA(virtual_ldt[i].mod_name, mod_name, sizeof(virtual_ldt[i].mod_name));
            } else {
                lstrcpynA(virtual_ldt[i].mod_name, "DOSCALLS", sizeof(virtual_ldt[i].mod_name));
            }
            return (i << 3) | 3;
        }
    }
    return 0;
}

uint16_t wineos2_get_callgate_selector(const char* mod_name, uint16_t ordinal) {
    uint16_t i;
    for (i = 500; i < LDT_MAX_ENTRIES; i++) {
        if (virtual_ldt[i].present && virtual_ldt[i].type == LDT_TYPE_CALLGATE &&
            virtual_ldt[i].limit == ordinal && strcmp(virtual_ldt[i].mod_name, mod_name) == 0) {
            return (i << 3) | 3;
            }
    }
    return 0;
}

int main(int argc, char *argv[]) {
    IMAGE_DOS_HEADER dos_header;
    uint8_t magic_sig[2];
    FILE *file;
    uint32_t active_pib_address = 0;

    if (argc < 2) {
        printf("Usage: wineos2.exe <target_os2_file.exe>\n");
        return 1;
    }

    file = fopen(argv[1], "rb");
    if (!file) {
        perror("Error opening target executable");
        return 1;
    }

    if (fread(&dos_header, sizeof(IMAGE_DOS_HEADER), 1, file) != 1 || dos_header.e_magic != 0x5A4D) {
        printf("Error: Invalid DOS stub header.\n");
        fclose(file);
        return 1;
    }
    if (fseek(file, dos_header.e_lfanew, SEEK_SET) != 0 || fread(magic_sig, 1, 2, file) != 2) {
        printf("Error: Missing extended header alignment.\n");
        fclose(file);
        return 1;
    }
    printf("==================================================\n");
    printf("  WINEOS2 EXECUTIVE UNIFIED LOADER (Win32 Target) \n");
    printf("==================================================\n");
    if (!wineos2_setup_lx_environment(&active_pib_address)) {
        printf("Error: Failed to initialize OS/2 simulation environment.\n");
        fclose(file);
        return 1;
    }
    if (magic_sig[0] == 'N' && magic_sig[1] == 'E') {
        wineos2_execute_ne_process(file, dos_header.e_lfanew, active_pib_address);
    }
    else if ((magic_sig[0] == 'L' && magic_sig[1] == 'X') || (magic_sig[0] == 'L' && magic_sig[1] == 'E')) {
        wineos2_execute_lx_process_win32(file, dos_header.e_lfanew, active_pib_address);
    }
    else {
        printf("Error: Unknown architecture signature (%c%c).\n", magic_sig[0], magic_sig[1]);
    }
    printf("==================================================\n");
    fclose(file);
    return 0;
}
