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

/* ENFORCED FIX: Updated function pointer signature to mandate param_bytes for automated stack balancing */
typedef uint16_t (CDECL *PFN_wineos2_register_callgate)(const char* mod_name, uint16_t ordinal, uint16_t param_bytes, void* thunk_ptr);

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
        if (pBytesWritten) *pBytesWritten = (ULONG)io_status.Information;
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
        if (pBytesRead) *pBytesRead = (ULONG)io_status.Information;
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
 * 16-BIT EMULATED CORES (NE Subsystem - Stack Preservation Fix)
 * ========================================================================= */

uint16_t os2_Dos16Exit(CPU286_Context* ctx) {
    /* Parameters sit exactly 4 bytes above the pushed mock CS:IP return frame */
    uint16_t sp_offset = ctx->sp + 4; 
    uint16_t result_code;
    uint16_t action_flags;
    
    /* Pascal Calling Convention: Arguments are passed Left-to-Right */
    action_flags = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 2);
    result_code  = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 0);

    os2_DosExit((ULONG)action_flags, (ULONG)result_code);
    return 0;
}

uint16_t os2_Dos16Write(CPU286_Context* ctx) {
    uint16_t sp_offset = ctx->sp + 4;
    ULONG bytes_written = 0; 
    
    /* Pascal Layout Extraction Frame for DosWrite (12 Total Parameter Bytes) */
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
        return 87; /* ERROR_INVALID_PARAMETER */
    }

    rc = os2_DosWrite((ULONG)hFile, host_buffer, (ULONG)cbWrite, &bytes_written);
    *host_actual = (uint16_t)bytes_written;

    return (uint16_t)rc;
}

uint16_t os2_Dos16Read(CPU286_Context* ctx) {
    uint16_t sp_offset = ctx->sp + 4;
    ULONG bytes_read = 0; 
    
    /* Pascal Layout Extraction Frame for DosRead (12 Total Parameter Bytes) */
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
        return 87; /* ERROR_INVALID_PARAMETER */
    }

    rc = os2_DosRead((ULONG)hFile, host_buffer, (ULONG)cbRead, &bytes_read);
    *host_read = (uint16_t)bytes_read;

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

        /* 
         * ENFORCED FIX: Register hooks passing the precise parameter byte footprint size.
         * DosExit:  2 arguments * 2 bytes = 4 bytes footprint.
         * DosRead:  4 arguments (16-bit, 32-bit far, 16-bit, 32-bit far) = 2 + 4 + 2 + 4 = 12 bytes footprint.
         * DosWrite: 4 arguments (16-bit, 32-bit far, 16-bit, 32-bit far) = 2 + 4 + 2 + 4 = 12 bytes footprint.
         */
        pfnRegister("DOSCALLS", 5,   4,  os2_Dos16Exit);
        pfnRegister("DOSCALLS", 137, 12, os2_Dos16Read);
        pfnRegister("DOSCALLS", 138, 12, os2_Dos16Write);

        printf("[Doscalls] Autonomous 16-bit Callgate registration completed via runtime linking.\n");
        fflush(stdout);
    }
    return TRUE;
}
