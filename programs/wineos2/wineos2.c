//(c) Arucard 2026 - Wine-OS/2 Project
//TODO: Fix formating

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#pragma pack(push, 1)

/* Official DOS MZ stub header structure */
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
    uint16_t e_res[4];
    uint16_t e_oemid;
    uint16_t e_oeminfo;
    uint16_t e_res2[10];
    uint32_t e_lfanew;     /* Offset to the extended header (strictly at byte 60) */
} IMAGE_DOS_HEADER;

/* OS/2 1.x / Win16 NE (New Executable) header structure */
typedef struct {
    uint8_t  magic[2];     /* Magic number: "NE" */
    uint8_t  linker_ver;   /* Linker version number */
    uint8_t  linker_rev;   /* Linker revision number */
    uint16_t entry_offset; /* Offset to Entry Table */
    uint16_t entry_size;   /* Length of Entry Table */
    uint32_t crc;          /* 32-bit CRC */
    uint16_t program_flags;/* Program flags */
    uint16_t auto_data_seg;/* Automatic Data Segment number */
    uint16_t heap_size;    /* Initial heap size */
    uint16_t stack_size;   /* Initial stack size */
    uint32_t cs_ip;        /* Initial CS:IP */
    uint32_t ss_sp;        /* Initial SS:SP */
    uint16_t seg_count;    /* Number of segments */
    uint16_t mod_count;    /* Number of referenced modules */
    uint16_t nonres_size;  /* Size of Nonresident-name table */
    uint16_t seg_table;    /* Offset to Segment Table */
    uint16_t res_table;    /* Offset to Resource Table */
    uint16_t resid_name;   /* Offset to Resident-name table */
    uint16_t mod_ref_table;/* Offset to Module Reference Table */
    uint16_t import_name;  /* Offset to Imported-name table */
    uint32_t nonres_table; /* File offset to Nonresident-name table */
    uint16_t movable_entry;/* Number of movable entries */
    uint16_t logical_sector;/* File alignment shift count */
    uint16_t resource_count;/* Number of resource entries */
    uint8_t  target_os;    /* Target OS: 1=OS/2, 2=Windows, 3=European MS-DOS 4... */
    uint8_t  os2_flags;    /* Additional OS/2 flags */
    uint16_t fast_load_off;
    uint16_t fast_load_len;
    uint16_t reserved;
    uint16_t expected_win_ver;
} NE_HEADER;

/* OS/2 2.x+ LX (Linear eXecutable) header structure */
typedef struct {
    uint8_t  magic[2];     /* Magic number: "LX" or "LE" */
    uint8_t  border;       /* Byte order */
    uint8_t  worder;       /* Word order */
    uint32_t level;
    uint16_t cpu_type;
    uint16_t os_type;      /* OS type: 1 = OS/2 */
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

/* Object Table Entry for LX */
typedef struct {
    uint32_t size;
    uint32_t base_addr;
    uint32_t flags;
    uint32_t page_tbl_idx;
    uint32_t num_pages;
    uint32_t reserved;
} LX_OBJECT;

#pragma pack(pop)

int main(int argc, char *argv[]) {
    FILE *file;
    IMAGE_DOS_HEADER dos_header;
    uint8_t magic[2];

    if (argc < 2) {
        printf("Usage: %s <os2_file.exe>\n", argv[0]);
        return 1;
    }

    file = fopen(argv[1], "rb");
    if (!file) {
        perror("Error opening file");
        return 1;
    }

    if (fread(&dos_header, sizeof(IMAGE_DOS_HEADER), 1, file) != 1) {
        printf("Error reading DOS header.\n");
        fclose(file);
        return 1;
    }

    if (dos_header.e_magic != 0x5A4D) {
        printf("Error: Invalid DOS header (expected MZ).\n");
        fclose(file);
        return 1;
    }

    /* Jump to the dynamic extended header offset */
    if (fseek(file, dos_header.e_lfanew, SEEK_SET) != 0) {
        printf("Error seeking to extended header offset (0x%X).\n", dos_header.e_lfanew);
        fclose(file);
        return 1;
    }

    /* Peek at the 2 magic bytes first to identify the architecture format */
    if (fread(magic, 1, 2, file) != 2) {
        printf("Error reading extended signature bytes.\n");
        fclose(file);
        return 1;
    }

    /* Rewind back to the start of the extended header */
    fseek(file, dos_header.e_lfanew, SEEK_SET);

    printf("=========================================\n");
    printf(" WINEOS2 LOADER - Executable Information \n");
    printf("=========================================\n");

    /* SCENARIO A: The file is a 16-bit NE (New Executable) */
    if (magic[0] == 'N' && magic[1] == 'E') {
        NE_HEADER ne_header;
        if (fread(&ne_header, sizeof(NE_HEADER), 1, file) != 1) {
            printf("Error reading NE header.\n");
            fclose(file);
            return 1;
        }

        printf("Format Detected: NE (New Executable) - 16-bit\n");
        
        /* Validate the Target OS field to verify if it belongs to OS/2 */
        if (ne_header.target_os == 1) {
            printf("Target OS: OS/2 1.x Subsystem (Compatible)\n");
        } else if (ne_header.target_os == 2) {
            printf("Target OS: Microsoft Windows 16-bit (Unsupported by wineos2)\n");
            fclose(file);
            return 1;
        } else {
            printf("Target OS: Unknown/Other (Code: %d)\n", ne_header.target_os);
        }

        printf("Number of Segments: %d\n", ne_header.seg_count);
        printf("Initial CS:IP offset: 0x%04X\n", (uint16_t)(ne_header.cs_ip & 0xFFFF));
        printf("Parser completed successfully for 16-bit module.\n");
    } 
    
    /* SCENARIO B: The file is a 32-bit LX/LE (Linear Executable) */
    else if ((magic[0] == 'L' && magic[1] == 'X') || (magic[0] == 'L' && magic[1] == 'E')) {
        LX_HEADER lx_header;
        uint32_t absolute_obj_tbl_offset;
        uint32_t i;

        if (fread(&lx_header, sizeof(LX_HEADER), 1, file) != 1) {
            printf("Error reading LX header.\n");
            fclose(file);
            return 1;
        }

        printf("Format Detected: %c%c (Linear Executable) - 32-bit\n", magic[0], magic[1]);
        printf("OS Type: OS/2 (Code: %d)\n", lx_header.os_type);
        printf("Expected CPU Architecture: x86 (Code: %d)\n", lx_header.cpu_type);
        printf("Initial Entry Point (EIP): Object %d : Offset 0x%08X\n", lx_header.eip_obj, lx_header.eip);
        printf("Number of Objects detected: %d\n\n", lx_header.num_objects);

        absolute_obj_tbl_offset = dos_header.e_lfanew + lx_header.obj_tbl_offset;
        if (fseek(file, absolute_obj_tbl_offset, SEEK_SET) != 0) {
            printf("Error seeking to Object Table.\n");
            fclose(file);
            return 1;
        }

        printf("--- MEMORY OBJECT TABLE ---\n");
        for (i = 0; i < lx_header.num_objects; i++) {
            LX_OBJECT obj;
            if (fread(&obj, sizeof(LX_OBJECT), 1, file) != 1) break;
            printf("Object #%d -> Base: 0x%08X | Size: %d bytes | Pages: %d\n", 
                   i + 1, obj.base_addr, obj.size, obj.num_pages);
        }
        printf("\nParser completed successfully for 32-bit module.\n");
    } 
    
    /* SCENARIO C: Unknown or modern Windows format (PE) */
    else {
        printf("Error: Unsupported executable signature (%c%c).\n", magic[0], magic[1]);
        fclose(file);
        return 1;
    }

    printf("=========================================\n");
    fclose(file);
    return 0;
}

