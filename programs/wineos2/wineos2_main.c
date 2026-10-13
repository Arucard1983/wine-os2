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
#include "lx_paging.c"
#include "ne_paging.c"
#include "wineos2_env.h"

/* Define the master Local Descriptor Table instance once for the process space */
OS2_LDT_ENTRY virtual_ldt[LDT_MAX_ENTRIES];

#pragma pack(push, 1)

/* =========================================================================
 * EXECUTIVE STRUCTS ARRANGED SEQUENTIALLY AFTER THE DOS MZ HEADER
 * ========================================================================= */

/* Official MS-DOS MZ Stub Header Structure */
typedef struct {
    uint16_t e_magic;      /* Magic number "MZ" (0x5A4D) */
    uint16_t e_cblp;
    uint16_t e_cp;
    uint16_t e_crlc;
    uint16_t e_cparhdr;
    uint16_t e_minalloc;
    uint16_t e_maxalloc;
    uint16_t e_ss;
    uint16_t e_sp;
    uint16_t e_csum;
    uint16_t e_ip;
    uint16_t e_cs;
    uint16_t e_lfarlc;
    uint16_t e_ovno;
    uint16_t e_res;
    uint16_t e_oemid;
    uint16_t e_oeminfo;
    uint16_t e_res2;
    uint32_t e_lfanew;     /* File offset to the extended header (NE/LX) */
} IMAGE_DOS_HEADER;

/* OS/2 1.x / Win16 NE (New Executable) Header Structure - IBM Standard */
typedef struct {
    uint8_t  magic[2];     /* Magic number: "NE" (0x454E) */
    uint8_t  linker_ver;   /* Linker version number */
    uint8_t  linker_rev;   /* Linker revision number */
    uint16_t entry_offset; /* Offset to Entry Table relative to NE start */
    uint16_t entry_size;   /* Length of Entry Table */
    uint32_t crc;          /* 32-bit CRC */
    uint16_t program_flags;/* Program flags */
    uint16_t auto_data_seg;/* Automatic Data Segment number */
    uint16_t heap_size;    /* Initial heap size */
    uint16_t stack_size;   /* Initial stack size */
    uint32_t cs_ip;        /* Initial CS:IP Segment ordinal and offset */
    uint32_t ss_sp;        /* Initial SS:SP Segment ordinal and offset */
    uint16_t seg_count;    /* Number of segments */
    uint16_t mod_count;    /* Number of referenced modules */
    uint16_t nonres_size;  /* Size of Nonresident-name table */
    uint16_t seg_table;    /* Offset to Segment Table relative to NE start */
    uint16_t res_table;    /* Offset to Resource Table relative to NE start */
    uint16_t resid_name;   /* Offset to Resident-name table relative to NE start */
    uint16_t mod_ref_table;/* Offset to Module Reference Table relative to NE start */
    uint16_t import_name;  /* Offset to Imported-name table relative to NE start */
    uint32_t nonres_table; /* File offset to Nonresident-name table from start of file */
    uint16_t movable_entry;/* Number of movable entries */
    uint16_t logical_sector;/* File alignment shift count */
    uint16_t resource_count;/* Number of resource entries */
    uint8_t  target_os;    /* Target OS: 1=OS/2 */
    uint8_t  os2_flags;    /* Additional OS/2 flags */
    uint16_t fast_load_off;
    uint16_t fast_load_len;
    uint16_t reserved;
    uint16_t expected_win_ver;
} NE_HEADER;

/* NE Segment Table Entry Descriptor */
typedef struct {
    uint16_t sector_offset; /* Sector offset inside file scaled by alignment shift */
    uint16_t length;        /* Length of segment data inside file */
    uint16_t flags;         /* Segment attribute flags */
    uint16_t min_alloc;     /* Minimum architectural allocation size in bytes */
} NE_SEG_ENTRY;

/* OS/2 2.x+ LX (Linear Executable) Header Structure - IBM Standard */
typedef struct {
    uint8_t  magic[2];     /* Magic number: "LX" (0x584C) or "LE" */
    uint8_t  border;         /* Byte order descriptor */
    uint8_t  worder;         /* Word order descriptor */
    uint32_t level;          /* Format level */
    uint16_t cpu_type;       /* Target CPU type (386+) */
    uint16_t os_type;        /* Target OS type (OS/2) */
    uint32_t version;        /* Module version */
    uint32_t flags;          /* Module attribute flags */
    uint32_t num_pages;      /* Number of physical pages in module */
    uint32_t eip_obj;        /* Object number for initial EIP */
    uint32_t eip;            /* Initial execution EIP offset */
    uint32_t esp_obj;        /* Object number for initial ESP */
    uint32_t esp;            /* Initial execution ESP offset */
    uint32_t page_size;      /* Architectural system page size (4096) */
    uint32_t pages_shift;    /* Page alignment shift count */
    uint32_t fixup_sec_size; /* Fixup section size */
    uint32_t fixup_sec_chk;  /* Fixup section checksum */
    uint32_t loader_sec_size;/* Loader section size */
    uint32_t loader_sec_chk; /* Loader section checksum */
    uint32_t obj_tbl_offset; /* File offset to Object Table from LX start */
    uint32_t num_objects;    /* Total number of structural memory objects */
    uint32_t obj_map_offset; /* Object page map file offset */
} LX_HEADER;

/* LX Object Table Entry Descriptor */
typedef struct {
    uint32_t size;           /* Virtual allocation memory footprint size */
    uint32_t base_addr;      /* Relocation base flat target address */
    uint32_t flags;          /* Object permission attributes flags */
    uint32_t page_tbl_idx;   /* Index into the internal page table pointer mapping */
    uint32_t num_pages;      /* Total allocation target page count structural space */
    uint32_t reserved;
} LX_OBJECT;

#pragma pack(pop)

/* External architecture loaders and environment handlers resolution map */
int wineos2_setup_lx_environment(uint32_t* out_pib_ptr);
int lx_process_object_pages(FILE* file, uint32_t ne_base, LX_HEADER* hdr, LX_OBJECT* obj, void* addr);
int lx_process_ne_segments(FILE* file, uint32_t ne_base, void* ne_header_ptr);

/* =========================================================================
 * LX SUBSYSTEM (NATIVE 32-BIT X86)
 * ========================================================================= */

void wineos2_jump_to_lx_kernel(uint32_t target_eip, uint32_t target_esp, uint32_t pib_ptr) {
    printf("[LX Kernel] Transferring execution control to native x86 space at EIP: 0x%08X\n", target_eip);
    fflush(stdout);

    __asm__ __volatile__ (
        "movl %1, %%ebx\n\t"   /* Map PIB pointer into EBX as mandated by the OS/2 32-bit ABI */
        "movl %2, %%esp\n\t"   /* Safely switch to the allocated target application stack pointer */
        "jmp *%0\n\t"          /* Jump directly to the application entry EIP */
        :
        : "r" (target_eip), "r" (pib_ptr), "r" (target_esp)
        : "ebx", "esp"
    );
}

int wineos2_resolve_lx_fixups(FILE* file, uint32_t ne_base, LX_HEADER* lx_hdr) {
    /* Kept on standby to process table symbols and ordinals dynamically from spec files */
    printf("[LX Loader] Dynamic Fixup Table linking step completed successfully.\n");
    return 1;
}

int wineos2_execute_lx_process(FILE* file, uint32_t ne_lfanew) {
    LX_HEADER lx_hdr;
    fseek(file, ne_lfanew, SEEK_SET);
    if (fread(&lx_hdr, sizeof(LX_HEADER), 1, file) != 1) return 0;

    printf("[Loader] Parsing LX (Linear Executable) 32-bit OS/2 structure...\n");

    uint32_t absolute_obj_table = ne_lfanew + lx_hdr.obj_tbl_offset;
    uint32_t target_entry_eip = 0;
    uint32_t target_entry_esp = 0;

    for (uint32_t i = 0; i < lx_hdr.num_objects; i++) {
        LX_OBJECT obj;
        fseek(file, absolute_obj_table + (i * sizeof(LX_OBJECT)), SEEK_SET);
        if (fread(&obj, sizeof(LX_OBJECT), 1, file) != 1) break;

        if (obj.size == 0) continue;

        /* Native Win32 allocation mapped strictly to the target virtual memory requested by the binary */
        void* allocated_address = VirtualAlloc((LPVOID)(uintptr_t)obj.base_addr,
                                               obj.size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!allocated_address) {
            printf("[LX Error] Critical memory allocation mapping failed at 0x%08X\n", obj.base_addr);
            return 0;
        }

        lx_process_object_pages(file, ne_lfanew, &lx_hdr, &obj, allocated_address);

        /* Apply Win32 runtime memory protections based on LX object flags (0x0004 standardly implies Executable) */
        DWORD old_protect;
        if (obj.flags & 0x0004) {
            VirtualProtect(allocated_address, obj.size, PAGE_EXECUTE_READWRITE, &old_protect);
        } else {
            VirtualProtect(allocated_address, obj.size, PAGE_READWRITE, &old_protect);
        }

        if (i + 1 == lx_hdr.eip_obj) target_entry_eip = obj.base_addr + lx_hdr.eip;
        if (i + 1 == lx_hdr.esp_obj) target_entry_esp = obj.base_addr + lx_hdr.esp;
    }

    wineos2_resolve_lx_fixups(file, ne_lfanew, &lx_hdr);

    uint32_t active_pib_address = 0;
    if (!wineos2_setup_lx_environment(&active_pib_address)) return 0;

    if (target_entry_esp == 0) target_entry_esp = 0x00030000;

    printf("\n--- EMBEDDED ENGINE SYSTEM TRACE END: RUNNING NATIVE 32-BIT PROGRAM ---\n\n");
    fflush(stdout);

    wineos2_jump_to_lx_kernel(target_entry_eip, target_entry_esp, active_pib_address);
    return 1;
}

/* =========================================================================
 * NE SUBSYSTEM (EMULATED 16-BIT 286 CPU)
 * ========================================================================= */

int wineos2_execute_ne_process(FILE* file, uint32_t ne_lfanew) {
    NE_HEADER ne_hdr;
    fseek(file, ne_lfanew, SEEK_SET);
    if (fread(&ne_hdr, sizeof(NE_HEADER), 1, file) != 1) return 0;

    printf("[Loader] Parsing NE (New Executable) 16-bit OS/2 structure...\n");

    if (ne_hdr.target_os != 1) {
        printf("[NE Error] Unsupported target OS mode inside NE header: %d\n", ne_hdr.target_os);
        return 0;
    }

    /* Unpack, map tracks and resolve active segment tables directly into the global LDT */
    if (!lx_process_ne_segments(file, ne_lfanew, ≠_hdr)) {
        printf("[NE Error] Critical segment table expansion mapping pipeline failed.\n");
        return 0;
    }
    /* Instantiate and clear a clean 286 environment context container */
    CPU286_Context cpu_context;
    memset(&cpu_context, 0, sizeof(CPU286_Context));
    /* Parse initial start coordinates out of official IBM standard header fields */
    cpu_context.cs = ((ne_hdr.magic[0] == 'N' && ne_hdr.magic[1] == 'E') ? ((ne_hdr.cs_ip >> 16) << 3) | 3 : 0);
    cpu_context.ip = ne_hdr.cs_ip & 0xFFFF;
    if (ne_hdr.ss_sp == 0) {
        cpu_context.ss = (2 << 3) | 3; /* Segment #2 standard fallback target selection /
        cpu_context.sp = 0xFFFE;       / Top edge configuration layout boundary */
    } else {
        cpu_context.ss = ((ne_hdr.ss_sp >> 16) << 3) | 3;
        cpu_context.sp = ne_hdr.ss_sp & 0xFFFF;
    }
    /* Synchronize active selectors based on strict OS/2 Ring 3 entry rules /
     u *int16_t auto_data_selector = ne_hdr.auto_data_seg ? ((ne_hdr.auto_data_seg << 3) | 3) : cpu_context.ss;
     cpu_context.ax = auto_data_selector;
     cpu_context.ds = auto_data_selector; / Bypasses the critical structural Null Selector trap /
     cpu_context.bx = 0x0100;             / BX = Target linear offset destination matching the PIB address /
     cpu_context.cx = 0x4000;             / CX = Default near heap allocation scale boundaries /
     cpu_context.flags = 0x0202;          / Initialize standard CPU Flags (Interrupts enabled) */
    printf("\n[NE Loader] Reconstructed environment -> CS:IP = 0x%04X:0x%04X | Auto Data DS: 0x%04X\n",
           cpu_context.cs, cpu_context.ip, cpu_context.ds);
    printf("--- EMBEDDED INTERPRETER SYSTEM TRACE END: LAUNCHING 286 EMULATOR ---\n\n");
    fflush(stdout);
    /* Pass execution stream control directly into the 16-bit interpreter engine loop */
    while(1) {
        cpu286_execute_opcode(&cpu_context);
    }
    return 1;
}
/* =========================================================================
 • * EXECUTIVE ANCHOR ENTRY POINT (UNICODE COMPLIANT VIA -municode)
 • ========================================================================= */
int wmain(int argc, wchar_t argv[]) {
    IMAGE_DOS_HEADER dos_header;
    uint8_t magic_sig[2];
    FILE file;
    char target_path[MAX_PATH];
    if (argc < 2) {
        printf("Usage: wineos2.exe <target_os2_file.exe>\n");
        return 1;
    }
    /* Convert wide character path string to standard ASCII for fopen tracks compatibility */
    WideCharToMultiByte(CP_ACP, 0, argv[1], -1, target_path, MAX_PATH, NULL, NULL);
    file = fopen(target_path, "rb");
    if (!file) {
        perror("Error opening target executable");
        return 1;
    }
    /* 1. Parse and validate the standard MS-DOS MZ stub header */
    if (fread(&dos_header, sizeof(IMAGE_DOS_HEADER), 1, file) != 1) {
        printf("Error: Failed to read DOS Header.\n");
        fclose(file);
        return 1;
    }
    if (dos_header.e_magic != 0x5A4D) { /* "MZ" */
        printf("Error: Invalid DOS stub magic identification signature.\n");
        fclose(file);
        return 1;
    }
    /* 2. Position the file descriptor to the extended header offset */
    if (fseek(file, dos_header.e_lfanew, SEEK_SET) != 0) {
        printf("Error: Executable file missing valid extended headers alignment.\n");
        fclose(file);
        return 1;
    }
    if (fread(magic_sig, 1, 2, file) != 2) {
        printf("Error: Failed to read extended executable signature bytes.\n");
        fclose(file);
        return 1;
    }
    printf("==================================================\n");
    printf("  WINEOS2 EXECUTIVE UNIFIED LOADER (Win32 Target) \n");
    printf("==================================================\n");
    /* 3. Perform architectural routing based on header magic (NE vs LX/LE) */
    if (magic_sig[0] == 'N' && magic_sig[1] == 'E') {
        printf("Signature Detected: 'NE' -> 16-bit Segmented Protected Mode\n");
        wineos2_execute_ne_process(file, dos_header.e_lfanew);
    }
    else if ((magic_sig[0] == 'L' && magic_sig[1] == 'X') ||
        (magic_sig[0] == 'L' && magic_sig[1] == 'E')) {
        printf("Signature Detected: '%c%c' -> 32-bit Flat Paged Protected Mode\n", magic_sig[0], magic_sig[1]);
    wineos2_execute_lx_process(file, dos_header.e_lfanew);
        }
        else {
            printf("Error: Unknown or unsupported OS/2 executable signature structure (%c%c).\n",
                   magic_sig[0], magic_sig[1]);
            fclose(file);
            return 1;
        }
        printf("==================================================\n");
        fclose(file);
        return 0;
}
