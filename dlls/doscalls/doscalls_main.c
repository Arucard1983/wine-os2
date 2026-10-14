/*
 *  doscalls_main.c - OS/2 16/32-bit API Bridging routed through NTDLL
 *  (c) Arucard 2026 - Wine-OS/2 Project
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h> 
#include <ntstatus.h> /* Standard header for STATUS_SUCCESS and STATUS_PENDING */
#include <stdio.h>
#include <stdlib.h>

#include "os2types.h"
#include "wineos2_286cpu.h"

/* Define the function pointer type for the callgate registration routine */
typedef uint16_t (CDECL *PFN_wineos2_register_callgate)(const char* mod_name, uint16_t ordinal, void* thunk_ptr);

/* Manual redeclarations of NTDLL functions */
NTSYSAPI NTSTATUS NTAPI NtTerminateProcess(HANDLE handle, NTSTATUS exit_status);

/* Helper to map standard OS/2 console handles to NT native handles */
static inline HANDLE map_os2_handle_to_nt(ULONG hFile) {
    if (hFile == 1) return GetStdHandle(STD_OUTPUT_HANDLE);
    if (hFile == 2) return GetStdHandle(STD_ERROR_HANDLE);
    if (hFile == 0) return GetStdHandle(STD_INPUT_HANDLE);
    return (HANDLE)(uintptr_t)hFile;
}

/* =========================================================================
 * 32-BIT NATIVE CORES (LX Subsystem - Routes directly to NTDLL)
 * ========================================================================= */

APIRET CDECL os2_DosWrite(ULONG hFile, PVOID pBuffer, ULONG cbWrite, PULONG pBytesWritten) {
    IO_STATUS_BLOCK io_status;
    NTSTATUS status;
    HANDLE nt_handle = map_os2_handle_to_nt(hFile);

    if (cbWrite == 0) {
        if (pBytesWritten) *pBytesWritten = 0;
        return NO_ERROR;
    }

    status = NtWriteFile(nt_handle, NULL, NULL, NULL, &io_status, pBuffer, cbWrite, NULL, NULL);
    
    if (status == STATUS_PENDING) {
        WaitForSingleObject(nt_handle, INFINITE);
        status = io_status.Status;
    }

    if (status == STATUS_SUCCESS) {
        if (pBytesWritten) *pBytesWritten = io_status.Information;
        return NO_ERROR;
    }

    return 5; /* ERROR_ACCESS_DENIED */
}

APIRET CDECL os2_DosRead(ULONG hFile, PVOID pBuffer, ULONG cbRead, PULONG pBytesRead) {
    IO_STATUS_BLOCK io_status;
    NTSTATUS status;
    HANDLE nt_handle = map_os2_handle_to_nt(hFile);

    status = NtReadFile(nt_handle, NULL, NULL, NULL, &io_status, pBuffer, cbRead, NULL, NULL);
    
    if (status == STATUS_PENDING) {
        WaitForSingleObject(nt_handle, INFINITE);
        status = io_status.Status;
    }

    if (status == STATUS_SUCCESS) {
        if (pBytesRead) *pBytesRead = io_status.Information;
        return NO_ERROR;
    }

    return 232; /* ERROR_PIPE_NOT_CONNECTED */
}

APIRET CDECL os2_DosExit(ULONG action, ULONG result) {
    printf("[DOSCALLS] DosExit 32-bit cascading process termination down to NTDLL.\n");
    fflush(stdout);
    
    NtTerminateProcess(GetCurrentProcess(), (NTSTATUS)result);
    return NO_ERROR;
}

/* =========================================================================
 * 16-BIT EMULATED CORES (NE Subsystem - Corrected Stack Offsets)
 * ========================================================================= */

uint16_t os2_Dos16Exit(CPU286_Context* ctx) {
    uint16_t sp_offset = ctx->sp + 4; /* Skip 4 bytes of Far CS:IP return address */
    uint16_t result_code;
    uint16_t action_flags;
    
    /* Pascal order: Action Flags (Left) is at higher address, Result Code (Right) is at lower */
    result_code  = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 0);
    action_flags = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 2);

    os2_DosExit((ULONG)action_flags, (ULONG)result_code);
    return 0;
}

uint16_t os2_Dos16Write(CPU286_Context* ctx) {
    uint16_t sp_offset = ctx->sp + 4;
    ULONG bytes_written = 0; /* C90 Fix: Moved declaration to top of execution block */
    
    /* Fixed Pascal layout unpacking from highest address to lowest */
    uint16_t hFile      = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 10);
    uint16_t pBuf_sel   = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 8);
    uint16_t pBuf_off   = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 6);
    uint16_t cbWrite    = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 4);
    uint16_t pAct_sel   = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 2);
    uint16_t pAct_off   = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 0);

    char* host_buffer     = (char*)mode16to32(pBuf_sel, pBuf_off);
    uint16_t* host_actual = (uint16_t*)mode16to32(pAct_sel, pAct_off);
    APIRET rc;

    if (!host_buffer || !host_actual) {
        ctx->sp += 12;
        return 87; /* ERROR_INVALID_PARAMETER */
    }

    rc = os2_DosWrite((ULONG)hFile, host_buffer, (ULONG)cbWrite, &bytes_written);
    *host_actual = (uint16_t)bytes_written;

    ctx->sp += 12; /* Safely clear the 12 bytes of parameters */
    return (uint16_t)rc;
}

uint16_t os2_Dos16Read(CPU286_Context* ctx) {
    uint16_t sp_offset = ctx->sp + 4;
    ULONG bytes_read = 0; /* C90 Fix: Moved declaration to top of execution block */
    
    /* Fixed Pascal layout unpacking for Dos16Read */
    uint16_t hFile      = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 10);
    uint16_t pBuf_sel   = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 8);
    uint16_t pBuf_off   = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 6);
    uint16_t cbRead     = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 4);
    uint16_t pRead_sel  = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 2);
    uint16_t pRead_off  = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 0);

    uint8_t* host_buffer = (uint8_t*)mode16to32(pBuf_sel, pBuf_off);
    uint16_t* host_read  = (uint16_t*)mode16to32(pRead_sel, pRead_off);
    APIRET rc;

    if (!host_buffer || !host_read) {
        ctx->sp += 12;
        return 87;
    }

    rc = os2_DosRead((ULONG)hFile, host_buffer, (ULONG)cbRead, &bytes_read);
    *host_read = (uint16_t)bytes_read;

    ctx->sp += 12; 
    return (uint16_t)rc;
}

/* =========================================================================
 * SUBSYSTEM INITIALIZATION - AUTONOMOUS BOOTSTRAP PIPELINE
 * ========================================================================= */

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        HMODULE hCore;
        PFN_wineos2_register_callgate pfnRegister;

        DisableThreadLibraryCalls(hinstDLL);

        /* Dynamically look up the master engine core executable/DLL entry */
        hCore = GetModuleHandleA(NULL); /* NULL resolves to the host process image, wineos2.exe */
        if (!hCore) return FALSE;

        pfnRegister = (PFN_wineos2_register_callgate)GetProcAddress(hCore, "wineos2_register_callgate");
        if (!pfnRegister) {
            printf("[DOSCALLS] Error: Could not resolve wineos2_register_callgate dynamically.\n");
            fflush(stdout);
            return FALSE;
        }

        /* Register the 16-bit historical hooks into the master core LDT structures */
        pfnRegister("DOSCALLS", 5,   os2_Dos16Exit);
        pfnRegister("DOSCALLS", 137, os2_Dos16Read);
        pfnRegister("DOSCALLS", 138, os2_Dos16Write);

        printf("[Doscalls] Autonomous 16-bit Callgate registration completed via runtime linking.\n");
        fflush(stdout);
    }
    return TRUE;
}

