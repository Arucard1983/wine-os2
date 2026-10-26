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
 * 32-BIT NATIVE CORES (LX Subsystem Process APIs - KERNEL32 acceptable wrapper)
 * ========================================================================= */

APIRET CDECL os2_DosExecPgm(char* pObjname, ULONG cbObjname, ULONG execFlags,
                            const char* pArg, const char* pEnv, PVOID pResult, const char* pPgmname) {
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    char cmd_line[MAX_PATH * 2];
    BOOL success;
    DWORD exit_code;

    if (!pPgmname || !pResult) return 87; /* ERROR_INVALID_PARAMETER */

        memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    memset(&pi, 0, sizeof(pi));

    /* --- STEP 1: Attempt loading through the custom OS/2 interpreter loader binary (wineos2) --- */
    snprintf(cmd_line, sizeof(cmd_line), "wineos2.exe \"%s\" %s", pPgmname, pArg ? pArg : "");

    success = CreateProcessA(NULL, cmd_line, NULL, NULL, FALSE, 0, (LPVOID)pEnv, NULL, &si, &pi);

    if (success) {
        WaitForSingleObject(pi.hProcess, INFINITE);
        GetExitCodeProcess(pi.hProcess, &exit_code);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        /* Return exit success tracking status instantly if interpreter processed the file correctly */
        if (exit_code == 0) {
            *(PULONG)pResult = 0;
            return NO_ERROR;
        }

        printf("[DOSCALLS] wineos2 failed with code %d. Trying native wine fallback...\n", (int)exit_code);
        fflush(stdout);
    }

    /* --- STEP 2: Standard native Wine execution path fallback (Win16/Win32/Win64/DOS binaries) --- */
    snprintf(cmd_line, sizeof(cmd_line), "\"%s\" %s", pPgmname, pArg ? pArg : "");

    success = CreateProcessA(NULL, cmd_line, NULL, NULL, FALSE, 0, (LPVOID)pEnv, NULL, &si, &pi);

    if (success) {
        if (execFlags == 0) { /* EXEC_SYNC execution rules tracking path */
            WaitForSingleObject(pi.hProcess, INFINITE);
            GetExitCodeProcess(pi.hProcess, &exit_code);
            *(PULONG)pResult = exit_code;
            return NO_ERROR;
        } else { /* EXEC_ASYNC background execution decoupling */
            *(PULONG)pResult = pi.dwProcessId; /* Pass target PID parameters back safely */
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            return NO_ERROR;
        }
    }

    /* If execution fails, safely write the faulting module name into pObjname buffer if provided */
    if (pObjname && cbObjname > 0) {
        /* FIX: Replaced banned strncpy with a safe, bounded memcpy for Wine compile compliance */
        size_t fail_len = min(cbObjname - 1, 11);
        memcpy(pObjname, "LAUNCH_FAIL", fail_len);
        pObjname[fail_len] = '\0';
    }

    return 2; /* ERROR_FILE_NOT_FOUND */
                            }

/* ========================================================================
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

                /* FIX: Corrected semantic mapping pointers */
                char* host_objname  = (char*)mode16to32(obj_sel, obj_off);
                const char* host_arg = (const char*)mode16to32(arg_sel, arg_off);
                const char* host_env = (const char*)mode16to32(env_sel, env_off);
                void* host_result   = mode16to32(res_sel, res_off);

                if (!host_result) return 87; /* ERROR_INVALID_PARAMETER */

               /*
                * In OS/2 16-bit, the executable name path is actually passed via the
                * Application Name parameter, which often resides in the environment block
                * or is implicitly deduced. Assuming host_arg or a fallback mechanism provides the path.
                * We pass host_objname purely as the output buffer for failure tracking.
                */

               ULONG result32 = 0;

               /* Safely fallback to arg pointer if target program path isn't separate */
               const char* pgm_path = host_arg ? host_arg : "";

               APIRET rc = os2_DosExecPgm(host_objname, (ULONG)cbObjName, (ULONG)execFlags, host_arg, host_env, &result32, pgm_path);

                if (rc == NO_ERROR) {
                    /* Unpack and bind 32-bit results back onto 16-bit RESULTCODES (TermCode + ResultCode layouts) */
                    *(uint32_t*)host_result = result32;
                    }

                return (uint16_t)rc;
}
