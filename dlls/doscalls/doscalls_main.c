/*
 *  dos_main.c - OS/2 16/32-bit API Bridging routed through NTDLL
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

/* Manual redeclarations of NTDLL functions not conflicting with winternl.h */
NTSYSAPI NTSTATUS NTAPI NtTerminateProcess(HANDLE handle, NTSTATUS exit_status);

/* =========================================================================
 * EXTERNAL LINKS TO DOMAIN LOGIC MODULES (32-BIT LX)
 * ========================================================================= */
extern APIRET CDECL os2_DosOpen(const char* pszFileName, PULONG phFile, PULONG pulAction,
                                ULONG cbFile, ULONG ulAttribute, ULONG fsOpenFlags,
                                ULONG fsOpenMode, PVOID pEABuf);
extern APIRET CDECL os2_DosClose(ULONG hFile);
extern APIRET CDECL os2_DosDelete(const char* pszFileName, ULONG ulReserved);
extern APIRET CDECL os2_DosFindFirst(const char* pszFileSpec, PULONG phDir, ULONG ulAttribute,
                                     PVOID pFindBuf, ULONG cbFindBuf, PULONG pcFindCount, ULONG ulInfoLevel);
extern APIRET CDECL os2_DosFindNext(ULONG hDir, PVOID pFindBuf, ULONG cbFindBuf, PULONG pcFindCount);
extern APIRET CDECL os2_DosSetFilePtr(ULONG hFile, LONG ib, ULONG method, PULONG ibActual);
extern APIRET CDECL os2_DosSetFileSize(ULONG hFile, ULONG cbSize);
extern APIRET CDECL os2_DosQueryFileInfo(ULONG hFile, ULONG ulInfoLevel, PVOID pBuf, ULONG cbBuf);
extern APIRET CDECL os2_DosQueryFileMode(const char* pszFileName, PULONG pulAttribute, ULONG ulReserved);
extern APIRET CDECL os2_DosSetFileMode(const char* pszFileName, ULONG ulAttribute, ULONG ulReserved);
extern APIRET CDECL os2_DosSetFileInfo(ULONG hFile, ULONG ulInfoLevel, PVOID pBuf, ULONG cbBuf);
extern APIRET CDECL os2_DosQueryHType(ULONG hFile, PULONG pulHandleType, PULONG pulFlagWord);

extern APIRET CDECL os2_DosAllocMem(PVOID *ppBaseAddress, ULONG cbSize, ULONG ulFlags);
extern APIRET CDECL os2_DosSearchPath(ULONG flags, const char* pszPathRef, const char* pszFilename, PBYTE pBuf, ULONG cbBuf);
extern APIRET CDECL os2_DosQuerySysInfo(ULONG iStart, ULONG iLast, PVOID pData, ULONG cbData);
extern APIRET CDECL os2_DosSetVec(ULONG vecNum, PVOID pHandler, PVOID pPrevHandler);
extern APIRET CDECL os2_DosGetMachineMode(PBYTE pMode);

/* =========================================================================
 * EXTERNAL LINKS TO 16-BIT EMULATED HANDLERS (NE Subsystem)
 * ========================================================================= */
/* Memory, System and Process 16-bit modules */
extern uint16_t os2_Dos16Allocseg(CPU286_Context* ctx);
extern uint16_t os2_Dos16ReAllocseg(CPU286_Context* ctx);
extern uint16_t os2_Dos16GetMachineMode(CPU286_Context* ctx);
extern uint16_t os2_Dos16SetVec(CPU286_Context* ctx);
extern uint16_t os2_Dos16ExecPgm(CPU286_Context* ctx);
extern uint16_t os2_Dos16SearchPath(CPU286_Context* ctx);
extern uint16_t os2_Dos16GetVersion(CPU286_Context* ctx);

/* FIX: Restored missing file subsystem 16-bit external declarations */
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

    /* Perform a native synchronous NT write call operation (Inherited from winternl.h) */
    status = NtWriteFile(nt_handle, NULL, NULL, NULL, &io_status, pBuffer, cbWrite, NULL, NULL);

    /* Safely check for pending synchronous behavior operations */
    if (status == STATUS_PENDING) {
        NtWaitForSingleObject(nt_handle, FALSE, NULL);
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

    /* Perform a native synchronous NT read call operation (Inherited from winternl.h) */
    status = NtReadFile(nt_handle, NULL, NULL, NULL, &io_status, pBuffer, cbRead, NULL, NULL);

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

        /* Ordinal execution callback registration table for DOSCALLS */
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
        pfnRegister("DOSCALLS", 89,  10, os2_Dos16SetVec);
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
