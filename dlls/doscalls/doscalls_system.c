/*
 *  dos_system.c - OS/2 Environment, Vectors & System Information Subsystem
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

#define WINEOS2_REG_ENV "Software\\Wine\\WineOS2\\Environment"

/* Internal table to handle virtual interruptions (ex: INT 0x21, etc.) */
static void* os2_interrupt_vectors[256] = { NULL };

/* Internal auxiliary function for Registry handling */
static BOOL read_wineos2_reg_string(const char* value_name, char* out_buf, DWORD buf_size) {
    HKEY hKey;
    DWORD type;
    LONG res;

    res = RegOpenKeyExA(HKEY_LOCAL_MACHINE, WINEOS2_REG_ENV, 0, KEY_READ, &hKey);
    if (res != ERROR_SUCCESS) return FALSE;

    res = RegQueryValueExA(hKey, value_name, NULL, &type, (LPBYTE)out_buf, &buf_size);
    RegCloseKey(hKey);

    return (res == ERROR_SUCCESS && type == REG_SZ);
}

/* =========================================================================
 * 32-BIT NATIVE CORES (LX Subsystem Environment and System Info)
 * ========================================================================= */

APIRET CDECL os2_DosGetVersion(PULONG pVersion) {
    HKEY hKey;
    DWORD type;
    DWORD version_val = 0x0000140A; /* Default value: OS/2 2.1 (Major 20, Minor 10) */
    DWORD size = sizeof(version_val);
    LONG res;

    if (!pVersion) return 87; /* ERROR_INVALID_PARAMETER */

    res = RegOpenKeyExA(HKEY_LOCAL_MACHINE, WINEOS2_REG_ENV, 0, KEY_READ, &hKey);
    if (res == ERROR_SUCCESS) {
        /* Try to read the emulated version */
        res = RegQueryValueExA(hKey, "OS2Version", NULL, &type, (LPBYTE)&version_val, &size);
        RegCloseKey(hKey);
    }

    *pVersion = version_val;
    return NO_ERROR;
}

APIRET CDECL os2_DosGetMachineMode(PBYTE pMode) {
    HKEY hKey;
    DWORD type;
    DWORD mode_val = 1; /* 1 = MODE_PROTECTED */
    DWORD size = sizeof(mode_val);
    LONG res;

    if (!pMode) return 87;

    res = RegOpenKeyExA(HKEY_LOCAL_MACHINE, WINEOS2_REG_ENV, 0, KEY_READ, &hKey);
    if (res == ERROR_SUCCESS) {
        res = RegQueryValueExA(hKey, "OS2MachineMode", NULL, &type, (LPBYTE)&mode_val, &size);
        RegCloseKey(hKey);
    }

    *pMode = (BYTE)mode_val;
    return NO_ERROR;
}

APIRET CDECL os2_DosQuerySysInfo(ULONG iStart, ULONG iLast, PVOID pData, ULONG cbData) {
    ULONG* pulData = (ULONG*)pData;
    
    if (!pData || cbData < sizeof(ULONG)) return 87; /* ERROR_INVALID_PARAMETER */

    /* Fill the requested index by 32-bits LX */
    for (ULONG i = iStart; i <= iLast; i++) {
        ULONG idx = i - iStart;
        if ((idx + 1) * sizeof(ULONG) > cbData) break;

        switch (i) {
            case 1:  /* QSV_MAX_PATH_LENGTH */
                pulData[idx] = 260;
                break;
            case 2:  /* QSV_NUMPROCESSORS */
                pulData[idx] = 1; /* Until further improvement, hardcore to one CPU */
                break;
            case 4:  /* QSV_PROCESS_ID */
                pulData[idx] = GetCurrentProcessId();
                break;
            case 5:  /* QSV_THREAD_ID */
                pulData[idx] = GetCurrentThreadId();
                break;
            default:
                pulData[idx] = 0;
                break;
        }
    }
    return NO_ERROR;
}

APIRET CDECL os2_DosSearchPath(ULONG flags, const char* pszPathRef, const char* pszFilename, PBYTE pBuf, ULONG cbBuf) {
    char path_env[2048] = { 0 };

    if (!pszFilename || !pBuf || cbBuf == 0) return 87;

    /* Searching using OS2LibPath */
    if (flags & 0x02) { /* SEARCH_CUR_DIRECTORY / LibPath reference */
        if (!read_wineos2_reg_string("OS2LibPath", path_env, sizeof(path_env))) {
            /* Default value if missing key */
            strncpy(path_env, "C:\\OS2\\DLL;.", sizeof(path_env));
        }
    } else if (pszPathRef) {
        /* Search using the variable (ex: "PATH" ) */
        strncpy(path_env, pszPathRef, sizeof(path_env));
    }

    /* Using Windows API to search files */
    DWORD res = SearchPathA(path_env[0] ? path_env : NULL, pszFilename, NULL, cbBuf, (char*)pBuf, NULL);
    return (res > 0 && res < cbBuf) ? NO_ERROR : 2; /* ERROR_FILE_NOT_FOUND */
}


APIRET CDECL os2_DosSetVec(ULONG vecNum, PVOID pHandler, PVOID pPrevHandler) {
    if (vecNum >= 256) return 87;

    if (pPrevHandler) {
        *(PVOID*)pPrevHandler = os2_interrupt_vectors[vecNum];
    }
    os2_interrupt_vectors[vecNum] = pHandler;
    return NO_ERROR;
}

/* =========================================================================
 * 16-BIT EMULATED CORES (NE Subsystem Environment Marshalling)
 * ========================================================================= */

uint16_t os2_Dos16GetVersion(CPU286_Context* ctx) {
    uint16_t sp_offset = ctx->sp + 4;
    uint16_t pVer_sel  = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 2);
    uint16_t pVer_off  = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 0);
    uint16_t* host_ver = (uint16_t*)mode16to32(pVer_sel, pVer_off);
    
    ULONG ver32 = 0;
    APIRET rc = os2_DosGetVersion(&ver32);
    
    if (rc == NO_ERROR && host_ver) {
        /* O OS/2 1.x returns: Major in AL (lower) and Minor at AH (higher). 
           Ex: OS2 1.3 return 0x0D0A (13 major, 10 minor) */
        uint8_t major = (uint8_t)(ver32 >> 8);
        uint8_t minor = (uint8_t)(ver32 & 0xFF);
        *host_ver = (uint16_t)((minor << 8) | major);
    }
    return (uint16_t)rc;
}

uint16_t os2_Dos16GetMachineMode(CPU286_Context* ctx) {
    uint16_t sp_offset = ctx->sp + 4;
    uint16_t pMode_sel = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 2);
    uint16_t pMode_off = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 0);
    uint8_t* host_mode = (uint8_t*)mode16to32(pMode_sel, pMode_off);
    
    if (!host_mode) return 87;

    BYTE mode32 = 0;
    APIRET rc = os2_DosGetMachineMode(&mode32);
    
    if (rc == NO_ERROR) {
        *host_mode = mode32;
    }
    return (uint16_t)rc;
}
uint16_t os2_Dos16SearchPath(CPU286_Context* ctx) {
    uint16_t sp_offset = ctx->sp + 4;

    uint16_t flags       = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 14);
    uint16_t pref_sel    = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 12);
    uint16_t pref_off    = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 10);
    uint16_t name_sel    = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 8);
    uint16_t name_off    = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 6);
    uint16_t buf_sel     = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 4);
    uint16_t buf_off     = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 2);
    uint16_t cbBuf       = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 0);

    const char* host_ref  = (const char*)mode16to32(pref_sel, pref_off);
    const char* host_name = (const char*)mode16to32(name_sel, name_off);
    BYTE* host_buf        = (BYTE*)mode16to32(buf_sel, buf_off);

    if (!host_name || !host_buf) return 87;

    APIRET rc = os2_DosSearchPath((ULONG)flags, host_ref, host_name, host_buf, (ULONG)cbBuf);
    return (uint16_t)rc;
}


uint16_t os2_Dos16SetVec(CPU286_Context* ctx) {
    uint16_t sp_offset = ctx->sp + 4;

    uint16_t vecNum       = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 8);
    uint16_t hand_sel     = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 6);
    uint16_t hand_off     = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 4);
    uint16_t prev_sel     = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 2);
    uint16_t prev_off     = *(uint16_t*)mode16to32(ctx->ss, sp_offset + 0);

    void* host_hand = mode16to32(hand_sel, hand_off);
    void* host_prev = mode16to32(prev_sel, prev_off);

    APIRET rc = os2_DosSetVec((ULONG)vecNum, host_hand, host_prev);
    return (uint16_t)rc;
}
