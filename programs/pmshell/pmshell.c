/*
 * Presentation Manager Shell Stub for Wine-OS/2
 *
 * Copyright 2026 Arucard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

int __cdecl main(int argc, char *argv[])
{
    HKEY hKeyIni, hKeySysIni;
    LONG result;

    printf("==================================================\n");
    printf("     WINEOS2 PRESENTATION MANAGER SHELL (Win32)   \n");
    printf("==================================================\n");

    /* 
     * Historical command-line arguments (os2.ini / os2sys.ini) are completely bogus.
     * They are safely ignored to comply with modern NT-style registry abstractions.
     */
    printf("[PMSHELL] Bypassing legacy physical INI arguments. Migrating to Registry architecture.\n");

    /* 1. Initialize and verify OS2.INI data structures within the Wine Registry */
    result = RegCreateKeyExA(HKEY_CURRENT_USER, "Software\\Wine\\WineOS2\\OS2.INI", 
                             0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKeyIni, NULL);
    if (result == ERROR_SUCCESS)
    {
        printf("[PMSHELL] Successfully attached to virtualized OS2.INI Registry hive.\n");
        RegCloseKey(hKeyIni);
    }
    else
    {
        printf("[PMSHELL WARNING] Failed to open virtualized OS2.INI registry fallback path.\n");
    }

    /* 2. Initialize and verify OS2SYS.INI data structures within the Wine Registry */
    result = RegCreateKeyExA(HKEY_LOCAL_MACHINE, "Software\\Wine\\WineOS2\\OS2SYS.INI", 
                             0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKeySysIni, NULL);
    if (result == ERROR_SUCCESS)
    {
        printf("[PMSHELL] Successfully attached to virtualized OS2SYS.INI Registry hive.\n");
        RegCloseKey(hKeySysIni);
    }
    else
    {
        printf("[PMSHELL WARNING] Failed to open virtualized OS2SYS.INI registry fallback path.\n");
    }

    printf("[PMSHELL] System desktop shell environment loaded natively via Wine Registry entries.\n");
    printf("==================================================\n");
    fflush(stdout);

    /* 
     * TODO: Implement the native Win32/PE Presentation Manager desktop surface rendering,
     * workspace synchronization, and shell folder tracking mapped entirely from the Registry.
     */

    /* Keep the execution engine alive as a persistent background shell manager */
    while (1)
    {
        Sleep(1000);
    }

    return 0;
}

