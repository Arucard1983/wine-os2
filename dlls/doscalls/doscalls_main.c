/*
 *  doscalls_main.c - OS/2 16/32-bit API Bridging routed through NTDLL
 *  (c) Arucard 2026 - Wine-OS/2 Project
 */

#define WIN32_LEAN_AND_MEAN
#define WINEOS2_DLL_MODULE 
#include <windows.h>
#include <winternl.h> 
#include <ntstatus.h>
#include <stdio.h>
#include <stdlib.h>

#include "os2types.h"
#include "wineos2_286cpu.h"

OS2_LDT_ENTRY* virtual_ldt = NULL;

typedef uint16_t (CDECL *PFN_wineos2_register_callgate)(const char* mod_name, uint16_t ordinal, uint16_t param_bytes, void* thunk_ptr);
typedef void* (CDECL *PFN_wineos2_get_ldt_ptr)(void);

/* Manual redeclarations of NTDLL functions */
NTSYSAPI NTSTATUS NTAPI NtTerminateProcess(HANDLE handle, NTSTATUS exit_status);

/* =========================================================================
 * EXTERNAL LINKS TO DOMAIN LOGIC MODULES (File, Memory, Process, System)
 * ========================================================================= */
extern APIRET CDECL os2_DosOpen(long arg1, long arg2);
extern APIRET CDECL os2_DosClose(long arg1, long arg2);
extern APIRET CDECL os2_DosDelete(long arg1, long arg2);
extern APIRET CDECL os2_DosFindFirst(long arg1, long arg2);
extern APIRET CDECL os2_DosFindNext(long arg1, long arg2);
extern APIRET CDECL os2_DosSetFilePtr(long arg1, long arg2);
extern APIRET CDECL os2_DosSetFileSize(long arg1, long arg2);
extern APIRET CDECL os2_DosQueryFileInfo(long arg1, long arg2);
extern APIRET CDECL os2_DosQueryFileMode(long arg1, long arg2);
extern APIRET CDECL os2_DosSetFileMode(long arg1, long arg2);
extern APIRET CDECL os2_DosSetFileInfo(long arg1, long arg2);
extern APIRET CDECL os2_DosQueryHType(long arg1, long arg2);
extern APIRET CDECL os2_DosSearchPath(long arg1, long arg2);
extern APIRET CDECL os2_DosAllocMem(long a, long b, long c, long d, long e, long f);
extern APIRET CDECL os2_DosQuerySysInfo(long a, long b, long c, long d, long e, long f);
extern APIRET CDECL os2_DosExecPgm(long a, long b, long c, long d);
extern APIRET CDECL os2_DosSetVec(long arg1, long arg2);
extern APIRET CDECL os2_DosGetMachineMode(long arg1);

/* Handlers de 16-bits externos */
extern uint16_t os2_Dos16Allocseg(CPU286_Context* ctx);
extern uint16_t os2_Dos16ReAllocseg(CPU286_Context* ctx);
extern uint16_t os2_Dos16ChgFilePtr(CPU286_Context* ctx);
extern uint16_t os2_Dos16Close(CPU286_Context* ctx);
extern uint16_t os2_Dos16Delete(CPU286_Context* ctx);
extern uint16_t os2_Dos16FindFirst(CPU286_Context* ctx);
extern uint16_t os2_Dos16FindNext(CPU286_Context* ctx);
extern uint16_t os2_Dos16NewSize(CPU286_Context* ctx);
extern uint16_t os2_Dos16Open(CPU286_Context* ctx);
extern uint16_t os2_Dos16QFHandState(CPU286_Context* ctx);
extern uint16_t os2_Dos16QFileMode(CPU286_Context* ctx);
extern uint16_t os2_Dos16QHandType(CPU286_Context* ctx);
extern uint16_t os2_Dos16SetFileInfo(CPU286_Context* ctx);
extern uint16_t os2_Dos16SetFileMode(CPU286_Context* ctx);
extern uint16_t os2_Dos16SetVec(CPU286_Context* ctx);
extern uint16_t os2_Dos16ExecPgm(CPU286_Context* ctx);
extern uint16_t os2_Dos16SearchPath(CPU286_Context* ctx);

/* Helper to map standard OS/2 console handles to NT native handles */
static inline HANDLE map_os2_handle_to_nt(ULONG hFile) {
    if (hFile == 1) return GetStdHandle(STD_OUTPUT_HANDLE);
    if (hFile == 2) return GetStdHandle(STD_ERROR_HANDLE);
    if (hFile == 0) return GetStdHandle(STD_INPUT_HANDLE);
    return (HANDLE)(uintptr_t)hFile;
}

/* =========================================================================
 * 32-BIT NATIVE CORES (LX Subsystem - Routes directly to NTDLL / Domain Cores)
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

APIRET CDECL os2_DosGetVersion(PULONG pVersion) {
    if (!pVersion) return 87;
    /* Retorna a versão de API estável do OS/2 2.1 (0x140A) */
    *pVersion = 0x0000140A;
    return NO_ERROR;
}

/* =========================================================================
 * 16-BIT EMULATED CORES (NE Subsystem - Stack Preservation & Alignment Fix)
 * ========================================================================= */

uint16_t os2_Dos16Exit(CPU286_Context* ctx) {
    uint16_t sp_offset = ctx->sp + 4; 
    uint16_t action_flags = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 2);
    uint16_t result_code  = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 0);

    os2_DosExit((ULONG)action_flags, (ULONG)result_code);
    return 0;
}

uint16_t os2_Dos16Write(CPU286_Context* ctx) {
    uint16_t sp_offset = ctx->sp + 4;
    ULONG bytes_written = 0; 
    
    /* FIX: Correção dos Offsets da Stack Pascal para 12 bytes reais de footprint */
    uint16_t hFile      = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 10);
    uint16_t pBuf_sel   = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 8);
    uint16_t pBuf_off   = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 6);
    uint16_t cbWrite    = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 4);
    uint16_t pAct_sel   = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 2);
    uint16_t pAct_off   = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 0);

    char* host_buffer     = (char*)mode16to32(pBuf_sel, pBuf_off);
    uint16_t* host_actual = (uint16_t*)mode16to32(pAct_sel, pAct_off);
    APIRET rc;

    if (!host_buffer || !host_actual) return 87;

    rc = os2_DosWrite((ULONG)hFile, host_buffer, (ULONG)cbWrite, &bytes_written);
    *host_actual = (uint16_t)bytes_written;
    return (uint16_t)rc;
}

uint16_t os2_Dos16Read(CPU286_Context* ctx) {
    uint16_t sp_offset = ctx->sp + 4;
    ULONG bytes_read = 0; 
    
    /* FIX: Correção dos Offsets da Stack Pascal para 12 bytes reais de footprint */
    uint16_t hFile      = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 10);
    uint16_t pBuf_sel   = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 8);
    uint16_t pBuf_off   = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 6);
    uint16_t cbRead     = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 4);
    uint16_t pRead_sel  = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 2);
    uint16_t pRead_off  = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 0);

    uint8_t* host_buffer = (uint8_t*)mode16to32(pBuf_sel, pBuf_off);
    uint16_t* host_read  = (uint16_t*)mode16to32(pRead_sel, pRead_off);
    APIRET rc;

    if (!host_buffer || !host_read) return 87;

    rc = os2_DosRead((ULONG)hFile, host_buffer, (ULONG)cbRead, &bytes_read);
    *host_read = (uint16_t)bytes_read;
    return (uint16_t)rc;
}

uint16_t os2_Dos16GetVersion(CPU286_Context* ctx) {
    uint16_t sp_offset = ctx->sp + 4;
    uint16_t pVer_sel  = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 2);
    uint16_t pVer_off  = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 0);
    uint16_t* host_ver = (uint16_t*)mode16to32(pVer_sel, pVer_off);
    
    ULONG ver32 = 0;
    APIRET rc = os2_DosGetVersion(&ver32);
    if (rc == NO_ERROR && host_ver) {
        /* Converte para o layout de retorno de 16-bits do OS/2 (Major byte, Minor byte) */
        *host_ver = (uint16_t)((ver32 & 0xFF) << 8 | ((ver32 >> 8) & 0xFF));
    }
    return (uint16_t)rc;
}

uint16_t os2_Dos16GetMachineMode(CPU286_Context* ctx) {
    uint16_t sp_offset = ctx->sp + 4;
    uint16_t pMode_sel = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 2);
    uint16_t pMode_off = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 0);
    uint8_t* host_mode = (uint8_t*)mode16to32(pMode_sel, pMode_off);
    
    if (host_mode) {
        *host_mode = 1; /* MODE_PROTECTED (Sinaliza que corre em modo protegido) */
    }
    return 0;
}

/* =========================================================================
 * SUBSYSTEM INITIALIZATION - AUTONOMOUS BOOTSTRAP PIPELINE
 * ========================================================================= */

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        HMODULE hCore;
        PFN_wineos2_register_callgate pfnRegister;
        PFN_wineos2_get_ldt_ptr pfnGetLdt;
        
        DisableThreadLibraryCalls(hinstDLL);

        hCore = GetModuleHandleA(NULL);
        if (!hCore) return FALSE;
        
        pfnGetLdt = (PFN_wineos2_get_ldt_ptr)GetProcAddress(hCore, "wineos2_get_ldt_ptr");
        if (pfnGetLdt) virtual_ldt = (OS2_LDT_ENTRY*)pfnGetLdt();

        pfnRegister = (PFN_wineos2_register_callgate)GetProcAddress(hCore, "wineos2_register_callgate");
        if (!pfnRegister) return FALSE;

        /* Matrix Completa de 22 Ordinais Registados com Precisão de Bytes da Stack */
        pfnRegister("DOSCALLS", 5,   4,  os2_Dos16Exit);
        pfnRegister("DOSCALLS", 34,  8,  os2_Dos16Allocseg);
        pfnRegister("DOSCALLS", 38,  4,  os2_Dos16ReAllocseg);
        pfnRegister("DOSCALLS", 49,  4,  os2_Dos16GetMachineMode);
        pfnRegister("DOSCALLS", 58,  12, os2_Dos16ChgFilePtr);
        pfnRegister("DOSCALLS", 59,  2,  os2_Dos16Close);
        pfnRegister("DOSCALLS", 60,  6,  os2_Dos16Delete);
        pfnRegister("DOSCALLS", 64,  20, os2_Dos16FindFirst);
        pfnRegister("DOSCALLS", 65,  12, os2_Dos16FindNext);
        pfnRegister("DOSCALLS", 68,  6,  os2_Dos16NewSize);
        pfnRegister("DOSCALLS", 70,  24, os2_Dos16Open);
        pfnRegister("DOSCALLS", 74,  6,  os2_Dos16QFHandState);
        pfnRegister("DOSCALLS", 75,  6,  os2_Dos16QFileMode);
        pfnRegister("DOSCALLS", 77,  8,  os2_Dos16QHandType);
        pfnRegister("DOSCALLS", 83,  10, os2_Dos16SetFileInfo);
        pfnRegister("DOSCALLS", 84,  8,  os2_Dos16SetFileMode);
        pfnRegister("DOSCALLS", 89,  6,  os2_Dos16SetVec);
        pfnRegister("DOSCALLS", 92,  4,  os2_Dos16GetVersion);
        pfnRegister("DOSCALLS", 137, 12, os2_Dos16Read);
        pfnRegister("DOSCALLS", 138, 12, os2_Dos16Write);
        pfnRegister("DOSCALLS", 144, 20, os2_Dos16ExecPgm);
        pfnRegister("DOSCALLS", 151, 16, os2_Dos16SearchPath);

        printf("[Doscalls] Autonomous 16/32-bit Core Engine registration completed via NTDLL pipeline.\n");
        fflush(stdout);
      }
    return TRUE;
}
