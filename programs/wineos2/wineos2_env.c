/*
 *  wineos2_env.c - OS/2 Environment Subsystem Simulation (NT-Style)
 *  (c) Arucard 2026 - Wine-OS/2 Project
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h> /* Correção: Adicionado para expor o uint32_t sob o C90 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "os2types.h"

/* 
 * Emulates the OS/2 environment block creation by merging Wine/Host variables 
 * with the registry-defined CONFIG.SYS style constraints.
 */
int wineos2_setup_lx_environment(uint32_t* out_pib_ptr) {
    char wine_path[4096];
    char os2_path[8192];
    char system_root[512];
    HKEY hKey;

    /* 1. Fetch the existing Wine/Host active environment variables */
    GetEnvironmentVariableA("PATH", wine_path, sizeof(wine_path));
    GetEnvironmentVariableA("SystemRoot", system_root, sizeof(system_root));
    if (strlen(system_root) == 0) {
        strcpy(system_root, "C:\\WINDOWS"); /* Fallback standard layout */
    }

    /* 2. Open the WineOS2 configuration key to extract simulated CONFIG.SYS variables */
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "Software\\Wine\\WineOS2\\Environment", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        char reg_path[2048] = {0};
        DWORD type, size = sizeof(reg_path);
        
        if (RegQueryValueExA(hKey, "PATH", NULL, &type, (LPBYTE)reg_path, &size) == ERROR_SUCCESS) {
            /* Perform the smart merge: Combine C:\OS2 with the Host/Wine active PATH */
            snprintf(os2_path, sizeof(os2_path), "%s;%s", reg_path, wine_path);
        } else {
            snprintf(os2_path, sizeof(os2_path), "C:\\OS2;C:\\OS2\\SYSTEM;%s", wine_path);
        }
        RegCloseKey(hKey);
    } else {
        /* Default hardcoded fallback if registry entry is missing */
        snprintf(os2_path, sizeof(os2_path), "C:\\OS2;C:\\OS2\\SYSTEM;%s", wine_path);
    }

    /* 3. Apply the reconstructed variables back into the active loader context memory */
    SetEnvironmentVariableA("PATH", os2_path);
    SetEnvironmentVariableA("DPATH", "C:\\OS2;C:\\OS2\\SYSTEM");
    SetEnvironmentVariableA("LIBPATH", ".;C:\\OS2\\DLL;C:\\OS2\\SYSTEM");
    
    {
        char comspec_path[1024];
        snprintf(comspec_path, sizeof(comspec_path), "%s\\system32\\cmd.exe", system_root);
        SetEnvironmentVariableA("COMSPEC", comspec_path);
    }

    printf("[Env Loader] NT-Style OS/2 Environment Variables initialized.\n");
    printf("[Env Loader] PATH successfully joined with Wine Host environment.\n");
    fflush(stdout);

    /* Return standard simulated mock PIB base address allocation */
     void* safe_pib = VirtualAlloc(NULL, sizeof(OS2_PIB), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
     *out_pib_ptr = (uint32_t)(uintptr_t)safe_pib;
    return 1;
}

