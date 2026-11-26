/*
 * POSIX host execution bridge (Unixlib side)
 */

#if 0
#pragma makedep unix
#endif

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include "unixlib.h"

static void sanitize_host_environment(void)
{
    unsetenv("WINELOADER");
    unsetenv("WINEPREFIX");
    unsetenv("WINEDLLOVERRIDES");
    unsetenv("WINEDLLPATH");
    unsetenv("WINESERVERSOCKET");
}

static NTSTATUS exec_host(void *args)
{
    struct exec_host_params *params = args;
    pid_t pid;
    int status;

    pid = fork();
    if (pid < 0)
        return STATUS_UNSUCCESSFUL;

    if (pid == 0)
    {
        if (params->cwd && chdir(params->cwd) != 0)
            perror("posix.so: chdir warning");

        if (!params->keep_wine_env)
            sanitize_host_environment();

        execvp(params->argv[0], params->argv);
        perror("posix.so: execvp failed");
        _exit(127);
    }

    if (waitpid(pid, &status, 0) < 0)
        return STATUS_UNSUCCESSFUL;

    if (WIFEXITED(status))
        params->exit_code = WEXITSTATUS(status);
    else if (WIFSIGNALED(status))
        params->exit_code = 128 + WTERMSIG(status);
    else
        params->exit_code = 1;

    return STATUS_SUCCESS;
}

const unixlib_entry_t __wine_unix_call_funcs[] =
{
    exec_host,
};

#ifdef _WIN64
static NTSTATUS wow64_exec_host(void *args)
{
    struct
    {
        ULONG cwd;
        ULONG argv;
        int keep_wine_env;
        int exit_code;
    } *params32 = args;

    ULONG *argv32 = ULongToPtr(params32->argv);
    int count = 0;
    char **argv64;
    struct exec_host_params params64;
    NTSTATUS status;

    while (argv32[count])
        count++;

    argv64 = calloc((size_t)count + 1, sizeof(char *));
    if (!argv64)
        return STATUS_NO_MEMORY;

    for (int i = 0; i < count; i++)
        argv64[i] = ULongToPtr(argv32[i]);

    params64.cwd = ULongToPtr(params32->cwd);
    params64.argv = argv64;
    params64.keep_wine_env = params32->keep_wine_env;
    params64.exit_code = 0;

    status = exec_host(&params64);
    params32->exit_code = params64.exit_code;
    free(argv64);
    return status;
}

const unixlib_entry_t __wine_unix_call_wow64_funcs[] =
{
    wow64_exec_host,
};
#endif

