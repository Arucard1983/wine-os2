/*
 *  dos_proc.c - OS/2 Process Management & Cascading Execution Core
 *  (c) Arucard 2026 - Wine-OS/2 Project
 */

#define WIN32_LEAN_AND_MEAN
#define WINEOS2_DLL_MODULE
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "os2types.h"
#include "wineos2_286cpu.h"

/* =========================================================================
 * 32-BIT NATIVE CORES (LX Subsystem Process APIs)
 * ========================================================================= */

APIRET CDECL os2_DosExecPgm(PCHAR pObjname, ULONG cbObjname, ULONG execFlags, 
                           PCHAR pArg, PCHAR pEnv, PVOID pResult, PCHAR pPgmname) {
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    char cmd_line[MAX_PATH * 2];
    BOOL success;
    DWORD exit_code;

    if (!pPgmname) return 87; /* ERROR_INVALID_PARAMETER */

    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    memset(&pi, 0, sizeof(pi));

    /* --- STEP 1: Starting the program using the OS/2 loader (wineos2) --- */
    snprintf(cmd_line, sizeof(cmd_line), "wineos2.exe \"%s\" %s", pPgmname, pArg ? pArg : "");
    
    success = CreateProcessA(NULL, cmd_line, NULL, NULL, FALSE, 0, pEnv, NULL, &si, &pi);
    
    if (success) {
        WaitForSingleObject(pi.hProcess, INFINITE);
        GetExitCodeProcess(pi.hProcess, &exit_code);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        /* If it worked using wineos2 (retorno 0), finishes here */
        if (exit_code == 0) {
            if (pResult) *(PULONG)pResult = 0; // OK
            return NO_ERROR;
        }
        
        printf("[DOSCALLS] wineos2 failed with code %d. Trying native wine fallback...\n", exit_code);
        fflush(stdout);
    }

    /* --- STEP 2: Normal Program Execution by Wine (16-bit, 32-bit and 64-bit Windows programs, including DOS) --- */
    snprintf(cmd_line, sizeof(cmd_line), "\"%s\" %s", pPgmname, pArg ? pArg : "");
    
    success = CreateProcessA(NULL, cmd_line, NULL, NULL, FALSE, 0, pEnv, NULL, &si, &pi);
    
    if (success) {
        if (execFlags == 0) { /* EXEC_SYNC */
            WaitForSingleObject(pi.hProcess, INFINITE);
            GetExitCodeProcess(pi.hProcess, &exit_code);
            if (pResult) *(PULONG)pResult = exit_code;
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            return NO_ERROR;
        } else { /* EXEC_ASYNC */
            if (pResult) *(PULONG)pResult = pi.dwProcessId; /* Return PID for Async */
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            return NO_ERROR;
        }
    }

    return 2; /* ERROR_FILE_NOT_FOUND */
}

/* =========================================================================
 * 16-BIT EMULATED CORES (NE Subsystem Process Marshalling)
 * ========================================================================= */

uint16_t os2_Dos16ExecPgm(CPU286_Context* ctx) {
    uint16_t sp_offset = ctx->sp + 4;

    uint16_t obj_sel    = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 18);
    uint16_t obj_off    = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 16);
    uint16_t cbObjName  = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 14);
    uint16_t execFlags  = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 12);
    uint16_t arg_sel    = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 10);
    uint16_t arg_off    = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 8);
    uint16_t env_sel    = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 6);
    uint16_t env_off    = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 4);
    uint16_t res_sel    = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 2);
    uint16_t res_off    = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 0);

    /* The 16-bits OS/2 program is usally passed to pObjName or stored on stack */
    char* host_objname  = (char*)mode16to32(obj_sel, obj_off);
    char* host_arg      = (char*)mode16to32(arg_sel, arg_off);
    char* host_env      = (char*)mode16to32(env_sel, env_off);
    void* host_result   = mode16to32(res_sel, res_off);

    if (!host_objname || !host_result) return 87;

    ULONG result32 = 0;
    /* With 16-bits, pObjName normally use their own executable to be launched */
    APIRET rc = os2_DosExecPgm(host_objname, (ULONG)cbObjName, (ULONG)execFlags, host_arg, host_env, &result32, host_objname);

    if (rc == NO_ERROR) {
        /* Maping 16-bits RESULTCODES to the return (TermCode + ResultCode) */
        *(uint32_t*)host_result = result32; 
    }

    return (uint16_t)rc;
}
