/*
 *  doscalls_main.c - OS/2 16/32-bit API Bridging routed through NTDLL
 *  (c) Arucard 2026 - Wine-OS/2 Project
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h> /* Access to NTDLL structures and function types */
#include <stdio.h>
#include <stdlib.h>

#include "os2types.h"
#include "wineos2_286cpu.h"

/* Import explicit NTDLL functions from the Wine/NT environment */
NTSYSAPI NTSTATUS NTAPI NtWriteFile(HANDLE handle, HANDLE event, PIO_APC_ROUTINE apc, 
                                    PVOID apc_context, PIO_STATUS_BLOCK io_status, 
                                    PVOID buffer, ULONG length, PLARGE_INTEGER offset, 
                                    PULONG key);

NTSYSAPI NTSTATUS NTAPI NtReadFile(HANDLE handle, HANDLE event, PIO_APC_ROUTINE apc, 
                                   PVOID apc_context, PIO_STATUS_BLOCK io_status, 
                                   PVOID buffer, ULONG length, PLARGE_INTEGER offset, 
                                   PULONG key);

NTSYSAPI NTSTATUS NTAPI NtTerminateProcess(HANDLE handle, NTSTATUS exit_status);

/* Helper to map standard OS/2 console handles (1=Stdout, 2=Stderr) to NT native handles */
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

    /* Perform a raw low-level syscall equivalent write into the NT kernel boundary */
    status = NtWriteFile(nt_handle, NULL, NULL, NULL, &io_status, pBuffer, cbWrite, NULL, NULL);
    
    if (status == STATUS_PENDING) {
        /* Wait safely for synchronous compliance if dealing with blocked file I/O descriptor streams */
        WaitForSingleObject(nt_handle, INFINITE);
        status = io_status.Status;
    }

    if (status == STATUS_SUCCESS) {
        if (pBytesWritten) *pBytesWritten = io_status.Information;
        return NO_ERROR;
    }

    return 5; /* ERROR_ACCESS_DENIED or translation fallback mapping */
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

    return 232; /* ERROR_PIPE_NOT_CONNECTED or EOF indicator */
}

APIRET CDECL os2_DosExit(ULONG action, ULONG result) {
    printf("[DOSCALLS] DosExit 32-bit cascading process termination down to NTDLL.\n");
    fflush(stdout);
    
    /* Terminate current active process context passing the evaluation exit status */
    NtTerminateProcess(GetCurrentProcess(), (NTSTATUS)result);
    return NO_ERROR;
}

/* =========================================================================
 * 16-BIT EMULATED CORES (NE Subsystem - Extracts Stack and Calls 32-bit Core)
 * ========================================================================= */

uint16_t os2_Dos16Exit(CPU286_Context* ctx) {
    uint16_t sp_offset = ctx->sp + 4; /* Advance past the 4 bytes of CS:IP far return tracking */
    uint16_t result_code = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 4);
    uint16_t action_flags = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 6);

    /* Call the 32-bit backend function directly */
    os2_DosExit((ULONG)action_flags, (ULONG)result_code);
    return 0;
}

uint16_t os2_Dos16Write(CPU286_Context* ctx) {
    uint16_t sp_offset = ctx->sp + 4;
    uint16_t hFile      = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 10);
    uint16_t pBuf_off   = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 8);
    uint16_t pBuf_sel   = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 6);
    uint16_t cbWrite    = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 4);
    uint16_t pAct_off   = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 2);
    uint16_t pAct_sel   = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 0);

    /* Map 16:16 pointers back into flat 32-bit pointer spaces safely */
    char* host_buffer     = (char*)mode16to32(pBuf_sel, pBuf_off);
    uint16_t* host_actual = (uint16_t*)mode16to32(pAct_sel, pAct_off);

    if (!host_buffer || !host_actual) {
        ctx->sp += 12;
        return 87; /* ERROR_INVALID_PARAMETER */
    }

    ULONG bytes_written = 0;
    
    /* Bridge directly into the 32-bit native NTDLL-based implementation core */
    APIRET rc = os2_DosWrite((ULONG)hFile, host_buffer, (ULONG)cbWrite, &bytes_written);
    
    *host_actual = (uint16_t)bytes_written;

    ctx->sp += 12; /* Perform standard Pascal convention callee cleanup */
    return (uint16_t)rc;
}

uint16_t os2_Dos16Read(CPU286_Context* ctx) {
    uint16_t sp_offset = ctx->sp + 4;
    uint16_t hFile      = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 12);
    uint16_t pBuf_off   = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 10);
    uint16_t pBuf_sel   = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 8);
    uint16_t cbRead     = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 6);
    uint16_t pRead_off  = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 4);
    uint16_t pRead_sel  = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 2);

    uint8_t* host_buffer = (uint8_t*)mode16to32(pBuf_sel, pBuf_off);
    uint16_t* host_read  = (uint16_t*)mode16to32(pRead_sel, pRead_off);

    if (!host_buffer || !host_read) {
        ctx->sp += 12;
        return 87;
    }

    ULONG bytes_read = 0;
    
    /* Bridge directly into the 32-bit native core */
    APIRET rc = os2_DosRead((ULONG)hFile, host_buffer, (ULONG)cbRead, &bytes_read);
    
    *host_read = (uint16_t)bytes_read;

    ctx->sp += 12;
    return (uint16_t)rc;
}

