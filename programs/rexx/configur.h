/* 
 *  configur.h - Custom file for IBM OS/2 Subsystem Compatibility to Regina REXX
 *  (c) Arucard 2026 - Wine-OS/2 Project
 */
 
#ifndef REGINA_CONFIG_H_INCLUDED
#define REGINA_CONFIG_H_INCLUDED

#define HAVE_STDINT_H 1
#include <stdint.h>
#define MAX_INDEX_LENGTH 1024

/* Metadata */
#define REGINA_VERSION_MAJOR "3"
#define REGINA_VERSION_MINOR "9"
#define REGINA_VERSION_RELEASE "5"
#define REGINA_VERSION_SUPP ""
#define REGINA_VERSION_DATE "25 Jun 2022"

/* Basic 32 bits types (ENABLE_ARCHS = i386) */
#define REGINA_BITS 32
#define SIZEOF_INT 4
#define SIZEOF_LONG 4
#define SIZEOF_VOID_P 4

/* Platform identification */
#define WIN32 1
#define _WIN32 1
#define REGINA_PLATFORM "WIN32"

/* Headers delivered by Wine/MinGW */
#define HAVE_ASSERT_H 1
#define HAVE_CTYPE_H 1
#define HAVE_ERRNO_H 1
#define HAVE_FCNTL_H 1
#define HAVE_LIMITS_H 1
#define HAVE_MALLOC_H 1
#define HAVE_MEMORY_H 1
#define HAVE_PROCESS_H 1
#define HAVE_SETJMP_H 1
#define HAVE_SIGNAL_H 1
#define HAVE_STDARG_H 1
#define HAVE_STDDEF_H 1
#define HAVE_STDIO_H 1
#define HAVE_STDLIB_H 1
#define HAVE_STRING_H 1
#define HAVE_SYS_STAT_H 1
#define HAVE_SYS_TYPES_H 1
#define HAVE_TIME_H 1
#define HAVE_WINDOWS_H 1
#define HAVE_IO_H 1
#define HAVE_DIRECT_H 1

/* Required by MSVCRT/UCRT from Wine */
#define HAVE_MEMCPY 1
#define HAVE_MEMMOVE 1
#define HAVE_STRERROR 1
#define HAVE_STRFTIME 1
#define HAVE_SYSTEM 1
#define HAVE_GETENV 1
#define HAVE_PUTENV 1
#define HAVE_FTRUNCATE 1
#define HAVE_GETCWD 1
#define HAVE__FULLPATH 1
#define HAVE_FTIME 1

/* Disable redundant Unix/POSIX types */
#undef HAVE_UNISTD_H
#undef HAVE_DLFCN_H
#undef HAVE_SYS_WAIT_H
#undef HAVE_SYS_RESOURCE_H
#undef HAVE_TERMIOS_H
#undef HAVE_PWD_H
#undef HAVE_GRP_H
#undef HAVE_GCI

/* Fundamental Types */
#define RETSIGTYPE void
#define YY_CHAR_TYPE unsigned char
#define REGINA_STATIC 1
#define MAX_EXPONENT 999999999

/*  Path Win32/OS2 */
#define FILE_SEPARATORS "\\/"
#define FILE_SEPARATOR "\\/"
#define FILE_SEPARATOR_STR "\\"
#define PATH_SEPARATOR ';'

/* Compatibility _access (MSVCRT) */
#include <io.h>
#ifndef F_OK
#define F_OK 0
#define X_OK 1
#define W_OK 2
#define R_OK 4
#endif
#define access _access

/* Fundamental macros */
#define ftruncate _chsize
#ifndef S_ISCHR
#define S_ISCHR(m) (((m) & 0xF000) == 0x2000)
#endif
#ifndef S_ISREG
#define S_ISREG(m) (((m) & 0xF000) == 0x8000)
#endif

#ifndef TRC_STATIC
#define TRC_STATIC 1
#endif

/* Regina Metadata */
#ifndef EXTERNAL_TO_REGINA
# define REGINA_ENGINE 1
# define IS_REGINA_ENGINE 1
#endif


/* Removing unused features on OS/2 */
#undef SUBVERSION
#define DEFAULT_AREXX_BIFS 0
#undef HAVE_AREXX_EXTENSIONS
#define DEFAULT_CMS_BIFS 0

/* Standard Values*/
#define DEFAULT_NUMERIC_SIZE 9
#define DEFAULT_NUMERIC_FUZZ 0
#define DEFAULT_MATH_TYPE 0
#define DEFAULT_LINEOUTTRUNC 0
#define DEFAULT_FLUSHSTACK 0
#define DEFAULT_MAKEBUF_BIF 1
#define DEFAULT_DROPBUF_BIF 1
#define DEFAULT_DESBUF_BIF 1
#define DEFAULT_BUFTYPE_BIF 1
#define DEFAULT_CACHEEXT 1
#define DEFAULT_PRUNE_TRACE 0
#define DEFAULT_EXT_COMMANDS_AS_FUNCS 1
#define DEFAULT_STDOUT_FOR_STDERR 0
#define DEFAULT_TRACE_HTML 0
#define DEFAULT_FAST_LINES_BIF_DEFAULT 1
#define DEFAULT_STRICT_ANSI 0
#define DEFAULT_INTERNAL_QUEUES 0
#define DEFAULT_REGINA_BIFS 1
#define DEFAULT_STRICT_WHITE_SPACE_COMPARISONS 0
#define DEFAULT_AREXX_SEMANTICS 0
#define DEFAULT_CALLS_AS_FUNCS 0
#define DEFAULT_QUEUES_301 0
#define DEFAULT_HALT_ON_EXT_CALL_FAIL 0
#define DEFAULT_SINGLE_INTERPRETER 1
#define DEFAULT_BROKEN_ADDRESS_COMMAND 0
#define DEFAULT_SINGLE_LINE_COMMENTS 0

#define NO_REGINA_BALLOCS 1
#define MONOLITHIC 1



#endif /* REGINA_CONFIG_H_INCLUDED */

