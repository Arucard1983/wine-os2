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

/*
 * Bug Fix: Re-declaration of virtual_ldt removed from here.
 * The included "wineos2_286cpu.h" header already allocates the static global LDT array context instance.
 */

#pragma pack(push, 1)

/*
 * Bug Fix: IMAGE_DOS_HEADER struct definition removed from here.
 * The standard <windows.h> (via <winnt.h>) already provides this official Win32 layout structure natively.
 */

/* OS/2 1.x / Win16 NE Header Structure */
typedef struct {
    uint8_t  magic[2];
    uint8_t  linker_ver;
    uint8_t  linker_rev;
    uint16_t entry_offset;
    uint16_t entry_size;
    uint32_t crc;
    uint16_t program_flags;
    uint16_t auto_data_seg;
    uint16_t heap_size;
    uint16_t stack_size;
    uint32_t cs_ip;
    uint32_t ss_sp;
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

/* LX Object Table Entry Descriptor */
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

#pragma pack(pop)

/* =========================================================================
 * LX SUBSYSTEM JUMP NATIVE CONTEXT
 * ========================================================================= */

void wineos2_jump_to_lx_kernel(uint32_t target_eip, uint32_t target_esp, uint32_t pib_ptr) {
    printf("[LX Kernel] Transferring execution control to native x86 space at EIP: 0x%08X (ESP: 0x%08X)\n", 
           target_eip, target_esp);
    fflush(stdout);

    // Place the values specified by the standard
    __asm__ __volatile__ (
        "movl %1, %%esp\n\t"   // Force ESP target_esp (from "edx")
        "pushl $0\n\t"         // Align the stack / Simulate a null return
        "jmp *%0\n\t"          // jump tp target_eip (from "eax")
        :
        : "a" (target_eip),    // "a" instruct the compiler to follow stricly the EAX
          "d" (target_esp),    // "d" instruct the compiler to follow stricly the EDX
          "b" (pib_ptr)        // "b" instruct the compiler to put stricly the PIB on EBX (a standard on OS/2 32-bit)
        : "memory"             // Memory clobber to obligate GCC to flush the registers
    );

    // The compiler knew that this point will never be reached
    __builtin_unreachable();
}


int wineos2_execute_lx_process(FILE* file, uint32_t ne_lfanew, uint32_t active_pib_address) {
    LX_HEADER lx_hdr;
    LX_ALLOCATED_OBJECT allocated_objects[MAX_LX_OBJECTS];
    uint32_t target_entry_eip = 0;
    uint32_t target_entry_esp = 0;
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
        if (i + 1 == lx_hdr.esp_obj) target_entry_esp = obj.base_addr + lx_hdr.esp;
    }

    wineos2_resolve_lx_fixups(file, ne_lfanew, &lx_hdr, allocated_objects);

    if (target_entry_esp == 0) {
    /* Allocate 64KB of real stack on free adress selected by Wine */
    void* lx_stack = VirtualAlloc(NULL, 65536, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    /* ESP points to the top of the memory heap (the stacks grows downward) */
    target_entry_esp = (uint32_t)(uintptr_t)lx_stack + 65535;
}


    printf("\n--- EMBEDDED ENGINE SYSTEM TRACE END: RUNNING NATIVE 32-BIT PROGRAM ---\n\n");
    fflush(stdout);

    wineos2_jump_to_lx_kernel(target_entry_eip, target_entry_esp, active_pib_address);
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
    
    // FIX: Extract correctly the segment number and IP from cs_ip
    uint16_t initial_seg_index = (uint16_t)((ne_hdr.cs_ip >> 16) & 0xFFFF);
    uint16_t initial_ip        = (uint16_t)(ne_hdr.cs_ip & 0xFFFF);

    // Adjust LDT selector (index << 3) with RPL=3 for Ring 3
    cpu_context.cs = (initial_seg_index << 3) | 3; 
    cpu_context.ip = initial_ip;

    if (ne_hdr.ss_sp == 0) {
        cpu_context.ss = (2 << 3) | 3; // Fallback to Segment #2
        cpu_context.sp = 0xFFFE;
    } else {
        // FIX: Extract the initial stack segment and SP from ss_sp
        uint16_t initial_stack_seg = (uint16_t)((ne_hdr.ss_sp >> 16) & 0xFFFF);
        uint16_t initial_sp        = (uint16_t)(ne_hdr.ss_sp & 0xFFFF);
        
        cpu_context.ss = (initial_stack_seg << 3) | 3;
        cpu_context.sp = initial_sp;
    }



    if (ne_hdr.ss_sp == 0) {
        cpu_context.ss = (2 << 3) | 3;
        cpu_context.sp = 0xFFFE;
    } else {
        cpu_context.ss = ((ne_hdr.ss_sp >> 16) << 3) | 3;
        cpu_context.sp = ne_hdr.ss_sp & 0xFFFF;
    }

    auto_data_selector = ne_hdr.auto_data_seg ? ((ne_hdr.auto_data_seg << 3) | 3) : cpu_context.ss;
    cpu_context.ax = auto_data_selector;
    cpu_context.ds = auto_data_selector;
    cpu_context.bx = 0x0100;
    cpu_context.cx = 0x4000;
    cpu_context.flags = 0x0202;

    printf("\n[NE Loader] Reconstructed environment -> CS:IP = 0x%04X:0x%04X | Auto Data DS: 0x%04X\n",
           cpu_context.cs, cpu_context.ip, cpu_context.ds);
    printf("--- EMBEDDED INTERPRETER SYSTEM TRACE END: LAUNCHING 286 EMULATOR ---\n\n");
    fflush(stdout);

    while(1) {
        cpu286_execute_opcode(&cpu_context);
    }
    return 1;
}

/* Enforced Fix: Added param_bytes to match standard 286 far callgate descriptors */
__declspec(dllexport) uint16_t CDECL wineos2_register_callgate(const char* mod_name, uint16_t ordinal, uint16_t param_bytes, void* thunk_ptr) {
    uint16_t i;
    for (i = 500; i < LDT_MAX_ENTRIES; i++) {
        if (!virtual_ldt[i].present) {
            virtual_ldt[i].wine_thunk   = (uint16_t (*)(CPU286_Context*))thunk_ptr;
            virtual_ldt[i].limit        = ordinal;
            virtual_ldt[i].param_bytes  = param_bytes; /* Storing the Pascal stack frame footprint */
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
    } /* Enforced fix: Correctly closed the for-loop context scope here */
    return 0;
}


/* Stable ANSI main entry point matching classical architecture standard requirements */
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
        wineos2_execute_lx_process(file, dos_header.e_lfanew, active_pib_address);
    }
    else {
        printf("Error: Unknown architecture signature (%c%c).\n", magic_sig[0], magic_sig[1]);
    }
    printf("==================================================\n");
    fclose(file);
    return 0;
}
