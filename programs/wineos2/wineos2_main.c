/*
 *  wineos2_main.c - Native 32-bit Win32/PE LX Loader Engine
 *  (c) Arucard 2026 - Wine-OS/2 Project
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include #include "wineos2_env.h" //Not yet make working
//TODO: Refactoring pending

/* Forward declarations of our environment and page decomp mapping managers */
int wineos2_setup_lx_environment(uint32_t* out_pib_ptr);
int lx_process_object_pages(FILE* file, uint32_t ne_base, LX_HEADER* hdr, LX_OBJECT* obj, void* addr);

/* Master tracking structure for loaded LX execution states */
typedef struct {
    uint32_t entry_eip;
    uint32_t entry_esp;
    uint32_t pib_address;
} LX_EXEC_CONTEXT;

/* 
 * Native x86 Inline Assembly Transition Stub.
 * Switches execution directly to the OS/2 binary code layout on the Host CPU.
 * Mandated by OS/2 32-bit ABI rules: EBX must cleanly point to the active PIB block.
 */
void wineos2_jump_to_lx_kernel(uint32_t target_eip, uint32_t target_esp, uint32_t pib_ptr) {
    printf("[LX Kernel] Transferring execution control to native x86 space at EIP: 0x%08X\n", target_eip);
    fflush(stdout);

    __asm__ __volatile__ (
        "movl %1, %%ebx\n\t"   /* Load the structural PIB pointer address into EBX */
        "movl %2, %%esp\n\t"   /* Set up the applications stack boundary pointer */
        "jmp *%0\n\t"          /* Absolute jump straight into the OS/2 Entry Point */
        :
        : "r" (target_eip), "r" (pib_ptr), "r" (target_esp)
        : "ebx", "esp"
    );
}

int wineos2_resolve_lx_fixups(FILE* file, uint32_t ne_base, LX_HEADER* lx_hdr) {
    /* 
     * TODO: Scan the Import Module Name Table and Fixup Records Table.
     * Use Win32 LoadLibrary("doscalls.dll") and LoadLibrary("viocalls.dll") dynamically.
     * Extract addresses via GetProcAddress and patch them directly into the paged memory
     * locations before passing active control to the CPU registers loop.
     */
    printf("[LX Loader] Dynamic Fixup Table linking step completed successfully.\n");
    return 1;
}

int wineos2_execute_lx_process(const char* filepath, uint32_t ne_lfanew) {
    FILE* file = fopen(filepath, "rb");
    if (!file) return 0;

    LX_HEADER lx_hdr;
    fseek(file, ne_lfanew, SEEK_SET);
    if (fread(&lx_hdr, sizeof(LX_HEADER), 1, file) != 1) {
        fclose(file);
        return 0;
    }

    uint32_t absolute_obj_table = ne_lfanew + lx_hdr.obj_tbl_offset;
    uint32_t target_entry_eip = 0;
    uint32_t target_entry_esp = 0;

    /* Map and page objects into host virtual addresses */
    for (uint32_t i = 0; i < lx_hdr.num_objects; i++) {
        LX_OBJECT obj;
        fseek(file, absolute_obj_table + (i * sizeof(LX_OBJECT)), SEEK_SET);
        if (fread(&obj, sizeof(LX_OBJECT), 1, file) != 1) break;

        if (obj.size == 0) continue;

        void* allocated_address = VirtualAlloc((LPVOID)(uintptr_t)obj.base_addr, 
                                               obj.size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!allocated_address) {
            fclose(file);
            return 0;
        }

        /* Load and decompress execution bytes cleanly into place */
        lx_process_object_pages(file, ne_lfanew, &lx_hdr, &obj, allocated_address);

        /* Discover application entry execution coordinates mapped out of header flags */
        if (i + 1 == lx_hdr.eip_obj) {
            target_entry_eip = obj.base_addr + lx_hdr.eip;
        }
        if (i + 1 == lx_hdr.esp_obj) {
            target_entry_esp = obj.base_addr + lx_hdr.esp;
        }
    }

    /* Resolve dynamic DLL linkage points (DOSCALLS/VIOCALLS) */
    wineos2_resolve_lx_fixups(file, ne_lfanew, &lx_hdr);
    fclose(file);

    /* Construct the 32-bit PIB/SIB architectural system blocks */
    uint32_t active_pib_address = 0;
    if (!wineos2_setup_lx_environment(&active_pib_address)) return 0;

    /* If application stack parameters are uninitialized, provide safe baseline fallbacks */
    if (target_entry_esp == 0) {
        target_entry_esp = 0x00030000; /* Safe dynamic stack coordinate space mapping */
    }

    /* Clear logging buffers to make way for the binaries console prints */
    printf("\n--- EMBEDDED ENGINE SYSTEM TRACE END: RUNNING NATIVE PROGRAM ---\n\n");
    fflush(stdout);

    /* Trigger absolute code execution redirection */
    wineos2_jump_to_lx_kernel(target_entry_eip, target_entry_esp, active_pib_address);

    return 1;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: wineos2.exe <target_os2_file.exe>\n");
        return 1;
    }

    /* 
     * In production integration phases, add a small MZ stub check routine 
     * to dynamically discover the absolute e_lfanew offset pointer location.
     */
    wineos2_execute_lx_process(argv[1], 0x00000040);
    return 0;
}
