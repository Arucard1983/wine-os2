/*
 *  wineos2.c - Wine-OS/2 Control Panel Applet Engine
 *  (c) Arucard 2026 - Wine-OS/2 Project
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cpl.h>
#include <stdio.h>
#include <stdlib.h>

#define WINEOS2_REG_ENV "Software\\Wine\\WineOS2\\Environment"

/* Dialog procedures tracking hook forward declarations */
INT_PTR CALLBACK DialogProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);

/* Registry writing helper bounded by compile rules template constraints */
static void save_reg_string(const char* value_name, const char* buffer) {
    HKEY hKey;
    if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, WINEOS2_REG_ENV, 0, NULL,
                        REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegSetValueExA(hKey, value_name, 0, REG_SZ, (const BYTE*)buffer, strlen(buffer) + 1);
        RegCloseKey(hKey);
    }
}

/* Registry reading helper bounded by compile rules template constraints */
static void load_reg_string(const char* value_name, char* buffer, DWORD size, const char* def_val) {
    HKEY hKey;
    DWORD type;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, WINEOS2_REG_ENV, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        if (RegQueryValueExA(hKey, value_name, NULL, &type, (BYTE*)buffer, &size) != ERROR_SUCCESS || type != REG_SZ) {
            snprintf(buffer, size, "%s", def_val);
        }
        RegCloseKey(hKey);
    } else {
        snprintf(buffer, size, "%s", def_val);
    }
}

/* =========================================================================
 * DIALOG INTERFACE MESSAGE PROCESSING HANDLER LOOP
 * ========================================================================= */
INT_PTR CALLBACK DialogProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    char buf[1024];

    switch (uMsg) {
        case WM_INITDIALOG: {
            /* Populate the interface tracking layouts with active configuration targets */
            load_reg_string("OS2Version", buf, sizeof(buf), "0000140A");
            SetDlgItemTextA(hDlg, 101, buf);

            load_reg_string("OS2MachineMode", buf, sizeof(buf), "1");
            SetDlgItemTextA(hDlg, 102, buf);

            load_reg_string("OS2LibPath", buf, sizeof(buf), "C:\\OS2\\DLL;.");
            SetDlgItemTextA(hDlg, 103, buf);
            return TRUE;
        }

        case WM_COMMAND: {
            switch (LOWORD(wParam)) {
                case IDOK: {
                    /* Read fields buffers and push data down to registry blocks mapping targets */
                    GetDlgItemTextA(hDlg, 101, buf, sizeof(buf));
                    save_reg_string("OS2Version", buf);

                    GetDlgItemTextA(hDlg, 102, buf, sizeof(buf));
                    save_reg_string("OS2MachineMode", buf);

                    GetDlgItemTextA(hDlg, 103, buf, sizeof(buf));
                    save_reg_string("OS2LibPath", buf);

                    EndDialog(hDlg, IDOK);
                    return TRUE;
                }
                case IDCANCEL:
                    EndDialog(hDlg, IDCANCEL);
                    return TRUE;
            }
            break;
        }
    }
    return FALSE;
}

/* =========================================================================
 * CANONICAL CPLAPPLET EXPORT INTERFACE ENTRY POINT (MAPPED BY CONTROL.EXE)
 * ========================================================================= */
LONG CALLBACK CPlApplet(HWND hwndCPl, UINT uMsg, LPARAM lParam1, LPARAM lParam2) {
    switch (uMsg) {
        case CPL_INIT:
            return TRUE; /* Initialization sequence success handshake confirmation */

        case CPL_GETCOUNT:
            return 1;    /* Expose single abstract subsystem applet configuration token */

        case CPL_INQUIRE: {
            CPLINFO *cplInfo = (CPLINFO *)lParam2;
            cplInfo->idIcon = 1;    /* Reference resource layout target matching numerical template icon ID */
            cplInfo->idName = 100;  /* Target name handle dialog template bindings */
            cplInfo->idInfo = -1;
            cplInfo->lData  = 0;
            break;
        }

        case CPL_DBLCLK:
            /* Spawn standard Win32 dialog frame layout decoupling configurations */
            DialogBoxA(GetModuleHandleA("wineos2.cpl"), MAKEINTRESOURCEA(100), hwndCPl, DialogProc);
            break;
    }
    return 0;
}
