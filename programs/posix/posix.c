/*
 * POSIX host execution bridge (PE side) for Wine / Wine-OS/2
 */

#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "unixlib.h"

extern char * CDECL wine_get_unix_file_name(LPCWSTR dosW);

/*
 * Verifica os magic bytes do ficheiro alvo para confirmar que é um binário
 * nativo do anfitrião (ELF, Mach-O ou script shebang #!).
 */
static BOOL is_native_host_binary(const char *path)
{
    HANDLE hFile;
    BYTE magic[4] = { 0 };
    DWORD bytesRead = 0;
    BOOL valid = FALSE;

    hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ,
                        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return FALSE;

    if (ReadFile(hFile, magic, sizeof(magic), &bytesRead, NULL) && bytesRead >= 2)
    {
        /* Shebang script: #! */
        if (magic[0] == '#' && magic[1] == '!')
            valid = TRUE;
        /* ELF binary (Linux/BSD): 0x7F 'E' 'L' 'F' */
        else if (bytesRead == 4 &&
                 magic[0] == 0x7F && magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F')
            valid = TRUE;
        /* Mach-O binary (macOS 32/64/Fat) */
        else if (bytesRead == 4 && (
            (magic[0] == 0xFE && magic[1] == 0xED && magic[2] == 0xFA && (magic[3] == 0xCE || magic[3] == 0xCF)) ||
            ((magic[0] == 0xCE || magic[0] == 0xCF) && magic[1] == 0xFA && magic[2] == 0xED && magic[3] == 0xFE) ||
            (magic[0] == 0xCA && magic[1] == 0xFE && magic[2] == 0xBA && magic[3] == 0xBE)))
            valid = TRUE;
    }

    CloseHandle(hFile);
    return valid;
}

static BOOL looks_like_dos_path(const char *arg)
{
    if (!arg || !arg[0])
        return FALSE;
    if (isalpha((unsigned char)arg[0]) && arg[1] == ':')
        return TRUE;
    if (strchr(arg, '\\') != NULL)
        return TRUE;
    return FALSE;
}

static char *translate_to_unix(const char *path)
{
    WCHAR wide_path[MAX_PATH];
    char *unix_path;
    char *result;

    if (MultiByteToWideChar(CP_ACP, 0, path, -1, wide_path, MAX_PATH) == 0)
        return strdup(path);

    unix_path = wine_get_unix_file_name(wide_path);
    if (!unix_path)
        return strdup(path);

    result = strdup(unix_path);
    HeapFree(GetProcessHeap(), 0, unix_path);
    return result;
}

int __cdecl main(int argc, char *argv[])
{
    struct exec_host_params params = { 0 };
    WCHAR win_cwd[MAX_PATH];
    char *unix_cwd = NULL;
    char **host_argv;
    int arg_idx = 1;
    int out_idx = 0;
    NTSTATUS status;

    if (getenv("POSIX_KEEP_WINE_ENV") != NULL)
        params.keep_wine_env = 1;

    while (arg_idx < argc && argv[arg_idx][0] == '-')
    {
        if (strcmp(argv[arg_idx], "--keep-wine-env") == 0)
        {
            params.keep_wine_env = 1;
            arg_idx++;
        }
        else if (strcmp(argv[arg_idx], "--clean-wine-env") == 0)
        {
            params.keep_wine_env = 0;
            arg_idx++;
        }
        else if (strcmp(argv[arg_idx], "--") == 0)
        {
            arg_idx++;
            break;
        }
        else
        {
            break;
        }
    }

    if (arg_idx >= argc)
    {
        fprintf(stderr, "Usage: posix.exe [--keep-wine-env|--clean-wine-env] <host_binary> [args...]\n");
        return 127;
    }

    if ((looks_like_dos_path(argv[arg_idx]) || strchr(argv[arg_idx], '/') != NULL) &&
        !is_native_host_binary(argv[arg_idx]))
    {
        fprintf(stderr, "posix.exe: '%s' is not a valid native host executable (ELF/Mach-O/script)\n", argv[arg_idx]);
        return 126;
    }

    if (__wine_init_unix_call())
    {
        fprintf(stderr, "posix.exe: failed to initialize unixlib\n");
        return 127;
    }

    if (GetCurrentDirectoryW(MAX_PATH, win_cwd) > 0)
        unix_cwd = wine_get_unix_file_name(win_cwd);

    host_argv = calloc((size_t)(argc - arg_idx + 1), sizeof(char *));
    if (!host_argv)
    {
        if (unix_cwd)
            HeapFree(GetProcessHeap(), 0, unix_cwd);
        return 127;
    }

    for (; arg_idx < argc; arg_idx++, out_idx++)
    {
        if (out_idx == 0 || looks_like_dos_path(argv[arg_idx]))
            host_argv[out_idx] = translate_to_unix(argv[arg_idx]);
        else
            host_argv[out_idx] = strdup(argv[arg_idx]);
    }
    host_argv[out_idx] = NULL;

    fflush(stdout);
    fflush(stderr);

    params.cwd = unix_cwd;
    params.argv = host_argv;

    status = WINE_UNIX_CALL(unix_exec_host, &params);

    for (int i = 0; i < out_idx; i++)
        free(host_argv[i]);
    free(host_argv);
    if (unix_cwd)
        HeapFree(GetProcessHeap(), 0, unix_cwd);

    return status ? 127 : params.exit_code;
}

