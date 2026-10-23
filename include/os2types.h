/* 
 *  os2types.h - Base Architectural Types for IBM OS/2 Subsystem Compatibility
 *  (c) Arucard 2026 - Wine-OS/2 Project
 */

#ifndef __WINE_OS2TYPES_H
#define __WINE_OS2TYPES_H

/* 1. BASE INTEGER TYPES */
typedef unsigned char  UCHAR;   /* 8 bits */
typedef char           CHAR;    /* 8 bits */
typedef unsigned char  BYTE;    /* 8 bits */
typedef unsigned short USHORT;  /* 16 bits */
typedef unsigned long  ULONG;   /* 32 bits */

/* 2. RETURN CODES AND HANDLES */
typedef ULONG          APIRET;   /* Native 32-bit (LX) return code */
typedef USHORT         APIRET16; /* Native 16-bit (NE) return code */
typedef ULONG          HVIO;     /* VIO handle (0 = Default) */
typedef ULONG          HKBD;     /* KBD handle */
typedef ULONG          HMOU;     /* MOU handle */

/* Fix: Protected against duplicate definitions from windows.h / winerror.h */
#ifndef NO_ERROR
#define NO_ERROR       0L
#endif

#define ERROR_VIO_INVALID_HANDLE    421L

/* 3. FLAT POINTERS (Emulator performs Map16to32 into these types) */
typedef void          *PVOID;
typedef CHAR          *PCH;
typedef CHAR          *PCHAR;
typedef char          *PSZ;

#pragma pack(push, 1)

/* 4. VIDEO INPUT/OUTPUT (VIO) STRUCTURES */
typedef struct _VIOCURSORINFO {
    USHORT yStart;   /* Cursor start line (scanline) */
    USHORT cEnd;     /* Cursor end line */
    USHORT cx;       /* Cursor width (0 = default) */
    USHORT attr;     /* Cursor attributes (-1 = Hidden) */
} VIOCURSORINFO, *PVIOCURSORINFO;

typedef struct _VIOMODEINFO {
    USHORT cb;       /* Structure size */
    UCHAR  fbType;   /* Display type (Mono, Color, Graphics) */
    UCHAR  color;    /* Number of colors (bits per pixel) */
    USHORT col;      /* Number of text columns */
    USHORT row;      /* Number of text rows */
    USHORT hres;     /* Horizontal resolution in pixels */
    USHORT vres;     /* Vertical resolution in pixels */
    UCHAR  fmt_ID;   /* Format identifier */
    UCHAR  attrib;   /* Additional attributes */
    ULONG  buf_addr; /* Physical address of videobuffer */
} VIOMODEINFO, *PVIOMODEINFO;

typedef struct _VIOFONTINFO {
    USHORT cb;
    USHORT type;
    USHORT cxCell;
    USHORT cyCell;
    PVOID  pFontData;
    USHORT cBytes;
} VIOFONTINFO, *PVIOFONTINFO;

/* 5. KEYBOARD (KBD) STRUCTURES */
typedef struct _KBDKEYINFO {
    UCHAR  chChar;    /* ASCII character code */
    UCHAR  chScan;    /* Keyboard scan code */
    UCHAR  fbStatus;  /* State of character */
    UCHAR  bNlsShift; /* National Language Support shift status */
    USHORT fsState;   /* Shift, Ctrl, Alt key states */
    ULONG  time;      /* Event timestamp */
} KBDKEYINFO, *PKBDKEYINFO;

typedef struct _STRINGINBUF {
    USHORT cb;        /* Maximum buffer length allocated by app */
    USHORT cchIn;     /* Number of bytes read (returned) */
} STRINGINBUF, *PSTRINGINBUF;

typedef struct _KBDSTATUS {
    USHORT cb;        /* Structure size */
    USHORT fsMask;    /* Action mask */
    USHORT chTurnAround; /* Turnaround character */
    USHORT fsInterim; /* Interim console flags */
    USHORT fsState;   /* Shift/Ctrl/Alt state flags */
} KBDSTATUS, *PKBDSTATUS;

/* --- Estruturas de Tempo e Data do OS/2 (Usadas em Sistemas de Ficheiros) --- */
typedef struct _FDATE {
    USHORT day   : 5;   /* 1-31 */
    USHORT month : 4;   /* 1-12 */
    USHORT year  : 7;   /* Ano desde 1980 */
} FDATE, *PFDATE;

typedef struct _FTIME {
    USHORT twosecs : 5; /* Segundos divididos por 2 */
    USHORT minutes : 6; /* 0-59 */
    USHORT hours   : 5; /* 0-23 */
} FTIME, *PFTIME;

/* --- Directory Structures (DOSCALLS) --- */
typedef struct _FILEFINDBUF3 {
    ULONG  oNextEntryOffset; /* Offset to next entry (0 if last) */
    FDATE  fdateCreation;   /* File creation Day */
    FTIME  ftimeCreation;   /* File creation Hour*/
    FDATE  fdateLastAccess; /* Last Date access  */
    FTIME  ftimeLastAccess; /* Last Hour access */
    FDATE  fdateLastWrite;  /* Last change date */
    FTIME  ftimeLastWrite;  /* Last change hour */
    ULONG  cbFile;          /* File size (End of File) */
    ULONG  cbFileAlloc;     /* File disk size */
    ULONG  attrFile;        /* File attributes (ReadOnly, Hidden, Dir, etc.) */
    UCHAR  cchName;         /* Name lenght (in bytes) */
    CHAR   achName[256];    /* Buffer with ASCIZ name file */
} FILEFINDBUF3, *PFILEFINDBUF3;


/* =========================================================================
 * 32-BIT OS/2 PROCESS INFORMATION BLOCK (PIB) STRUCT
 * ========================================================================= */
typedef struct _OS2_PIB {
    ULONG  pib_ulpid;      /* Process ID (PID) */
    ULONG  pib_ulppid;     /* Parent Process ID (PPID) */
    ULONG  pib_ulhmte;     /* Module handle of the executable */
    PCH    pib_pchcmd;     /* Command line string flat pointer */
    PCH    pib_pchenv;     /* Environment block flat pointer */
    ULONG  pib_flstatus;   /* Process status flags */
    ULONG  pib_ultype;     /* Process type (0 = VIO Window, 1 = PM, etc.) */
} OS2_PIB, *POS2_PIB;

#pragma pack(pop)


#endif /* __WINE_OS2TYPES_H */

