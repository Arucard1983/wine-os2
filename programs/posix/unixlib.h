#ifndef __WINE_POSIX_UNIXLIB_H
#define __WINE_POSIX_UNIXLIB_H

#include <stdarg.h>
#include <ntstatus.h>
#include <windef.h>
#include <winbase.h>
#include <wine/unixlib.h>

struct exec_host_params
{
    const char *cwd;          /* Diretório de trabalho Unix (ou NULL) */
    char * const *argv;       /* Array de argumentos traduzidos terminado em NULL */
    int keep_wine_env;        /* 1 = mantém WINE*, 0 = limpa variáveis Wine */
    int exit_code;            /* Código de saída devolvido pelo waitpid() */
};

enum posix_funcs
{
    unix_exec_host,
    unix_funcs_count
};

#endif /* __WINE_POSIX_UNIXLIB_H */

