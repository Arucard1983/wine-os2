/*
 * Minimalist Win32 Wrapper for Regina REXX Utilities (rxqueue / rxstack)
 * Wine-OS/2 Project
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string.h>
#include <stdio.h>

#ifndef RX_SWITCH
#error "RX_SWITCH must be defined (e.g. \"-q\" or \"-s\")"
#endif

static const char *skip_argv0(const char *cmdline)
{
    int in_quotes = 0;
    const char *p = cmdline;

    while (*p)
    {
        if (*p == '"')
        {
            in_quotes = !in_quotes;
        }
        else if (!in_quotes && (*p == ' ' || *p == '\t'))
        {
            break;
        }
        p++;
    }

    while (*p == ' ' || *p == '\t')
    {
        p++;
    }

    return p;
}

int main(void)
{
    char exe_path[MAX_PATH];
    char rexx_path[MAX_PATH];
    char *last_slash;
    const char *raw_cmdline;
    const char *args;
    char *new_cmdline;
    size_t total_len;
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    DWORD exit_code = 1;

    /* 1. Find the current directory of parent rexx.exe program */
    if (GetModuleFileNameA(NULL, exe_path, sizeof(exe_path)) == 0)
    {
        fprintf(stderr, "Error: Could not determine module path.\n");
        return 1;
    }

    memcpy(rexx_path, exe_path, strlen(exe_path) + 1);
    last_slash = strrchr(rexx_path, '\\');
    if (last_slash != NULL)
    {
        *(last_slash + 1) = '\0';
    }
    else
    {
        rexx_path[0] = '\0';
    }
    strcat(rexx_path, "rexx.exe");

    /* 2. Extract original arguments while perserving quotes and spaces */
    raw_cmdline = GetCommandLineA();
    args = skip_argv0(raw_cmdline);

    /* Format: "<path>\rexx.exe" -q <arguments> */
    total_len = strlen(rexx_path) + strlen(RX_SWITCH) + strlen(args) + 16;
    new_cmdline = (char *)HeapAlloc(GetProcessHeap(), 0, total_len);
    if (!new_cmdline)
    {
        fprintf(stderr, "Error: Out of memory.\n");
        return 1;
    }

    if (*args != '\0')
        sprintf(new_cmdline, "\"%s\" %s %s", rexx_path, RX_SWITCH, args);
    else
        sprintf(new_cmdline, "\"%s\" %s", rexx_path, RX_SWITCH);

    /* 3. Configure handles heritance (needed for dir | rxqueue) */
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput  = GetStdHandle(STD_INPUT_HANDLE);
    si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    si.hStdError  = GetStdHandle(STD_ERROR_HANDLE);

    memset(&pi, 0, sizeof(pi));

    /* 4. Execute rexx.exe and wait to finish */
    if (!CreateProcessA(
            rexx_path,
            new_cmdline,
            NULL,
            NULL,
            TRUE,   /* bInheritHandles = TRUE to pipes stdin/stdout */
            0,      /* No DETACHED_PROCESS to maintain OS/2 console */
            NULL,
            NULL,
            &si,
            &pi))
    {
        fprintf(stderr, "Error: Failed to launch %s (Win32 error %lu).\n", rexx_path, GetLastError());
        HeapFree(GetProcessHeap(), 0, new_cmdline);
        return 1;
    }

    WaitForSingleObject(pi.hProcess, INFINITE);
    GetExitCodeProcess(pi.hProcess, &exit_code);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    HeapFree(GetProcessHeap(), 0, new_cmdline);

    return (int)exit_code;
}

