//(c) Arucard 2026 - Wine-OS/2 Project
//TODO: Fix formating

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#pragma pack(push, 1)

/* DOS MZ stub header structure */
typedef struct {
    uint16_t e_magic[2];      /* Magic number "MZ" (0x5A4D) */
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
    uint32_t e_lfanew;     /* Offset to the OS/2 LX header */
} IMAGE_DOS_HEADER;

/* OS/2 LX (Linear eXecutable) header structure */
typedef struct {
    uint8_t  magic[2];        /* Magic number "LX" (0x584C) */
    uint8_t  border;       /* Byte order (0 = Little Endian) */
    uint8_t  worder;       /* Word order (0 = Little Endian) */
    uint32_t level;        /* Format Level */
    uint16_t cpu_type;     /* CPU type (1=286, 2=386, 3=486...) */
    uint16_t os_type;      /* OS type (1 = OS/2) */
    uint32_t version;      /* Module version */
    uint32_t flags;        /* Module flags */
    uint32_t num_pages;    /* Total number of pages in the module */
    uint32_t eip_obj;      /* Initial EIP object (Entry point) */
    uint32_t eip;          /* Initial EIP */
    uint32_t esp_obj;      /* Initial ESP object (Stack) */
    uint32_t esp;          /* Initial ESP */
    uint32_t page_size;    /* Page size (usually 4096) */
    uint32_t pages_shift;  /* Left shift for page offsets */
    uint32_t fixup_sec_size;  /* Fixup section size */
    uint32_t fixup_sec_chk;   /* Fixup section checksum */
    uint32_t loader_sec_size; /* Loader section size */
    uint32_t loader_sec_chk;  /* Loader section checksum */
    uint32_t obj_tbl_offset;  /* Offset to the Object Table */
    uint32_t num_objects;     /* Number of objects in the file */
    uint32_t obj_map_offset;  /* Offset to the Object Page Map */
} LX_HEADER;

/* Object Table Entry (Segment/Section definition) */
typedef struct {
    uint32_t size;            /* Virtual size of the object in memory */
    uint32_t base_addr;       /* Suggested virtual base address */
    uint32_t flags;           /* Object attribute flags (permissions) */
    uint32_t page_tbl_idx;    /* Index in the page map table */
    uint32_t num_pages;       /* Number of pages occupied by this object */
    uint32_t reserved;
} LX_OBJECT;

#pragma pack(pop)

/* Common LX Object Flags */
#define OBJ_READABLE   0x0001
#define OBJ_WRITABLE   0x0002
#define OBJ_EXECUTABLE 0x0004

static void print_obj_flags(uint32_t flags) {
    printf("[");
    if (flags & OBJ_READABLE)   printf(" R");
    if (flags & OBJ_WRITABLE)   printf(" W");
    if (flags & OBJ_EXECUTABLE) printf(" X");
    printf(" ]");
}

int main(int argc, char *argv[]) {
    FILE *file;
    IMAGE_DOS_HEADER dos_header;
    LX_HEADER lx_header;
    uint32_t absolute_obj_tbl_offset;
    uint32_t i;

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

    /* Verify MZ Signature */
    if (dos_header.e_magic != 0x5A4D) {
        printf("Error: Invalid DOS header (expected MZ).\n");
        fclose(file);
        return 1;
    }

    /* Jump to the OS/2 LX header */
    if (fseek(file, dos_header.e_lfanew, SEEK_SET) != 0) {
        printf("Error seeking to LX offset (0x%X).\n", dos_header.e_lfanew);
        fclose(file);
        return 1;
    }

    if (fread(&lx_header, sizeof(LX_HEADER), 1, file) != 1) {
        printf("Error reading OS/2 LX header.\n");
        fclose(file);
        return 1;
    }

    /* Verify LX/LE Signature ('L' and 'X'/'E') */
    if (lx_header.magic[0] != 'L' || (lx_header.magic[1] != 'X' && lx_header.magic[1] != 'E')) {
        printf("Error: Invalid executable. LX/LE signature not found (Found: %c%c).\n", 
               lx_header.magic[0], lx_header.magic[1]);
        fclose(file);
        return 1;
    }

    printf("=========================================\n");
    printf(" WINEOS2 LOADER - Executable Information \n");
    printf("=========================================\n");
    printf("OS Type: OS/2 (Code: %d)\n", lx_header.os_type);
    printf("Expected CPU Architecture: x86 (Code: %d)\n", lx_header.cpu_type);
    printf("Initial Entry Point (EIP): Object %d : Offset 0x%08X\n", lx_header.eip_obj, lx_header.eip);
    printf("Initial Stack Pointer (ESP): Object %d : Offset 0x%08X\n", lx_header.esp_obj, lx_header.esp);
    printf("Page Size: %d bytes\n", lx_header.page_size);
    printf("Number of Objects detected: %d\n\n", lx_header.num_objects);

    /* Move file pointer to the Object Table (relative to LX header start) */
    absolute_obj_tbl_offset = dos_header.e_lfanew + lx_header.obj_tbl_offset;
    if (fseek(file, absolute_obj_tbl_offset, SEEK_SET) != 0) {
        printf("Error seeking to Object Table (Offset: 0x%X).\n", absolute_obj_tbl_offset);
        fclose(file);
        return 1;
    }

    printf("--- MEMORY OBJECT TABLE ---\n");
    for (i = 0; i < lx_header.num_objects; i++) {
        LX_OBJECT obj;
        if (fread(&obj, sizeof(LX_OBJECT), 1, file) != 1) {
            printf("Error reading object number %d.\n", i + 1);
            break;
        }

        printf("Object #%d:\n", i + 1);
        printf("  -> Suggested Base Address: 0x%08X\n", obj.base_addr);
        printf("  -> Virtual Size:           %d bytes\n", obj.size);
        printf("  -> Occupied Pages:         %d (Initial Page Index: %d)\n", obj.num_pages, obj.page_tbl_idx);
        printf("  -> Permissions / Flags:    0x%08X ", obj.flags);
        print_obj_flags(obj.flags);
        printf("\n\n");
    }

    printf("=========================================\n");
    printf("Parser completed successfully.\n");
    
    fclose(file);
    return 0;
}
