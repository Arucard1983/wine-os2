/* include/os2types.h */
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

#define NO_ERROR       0L
#define ERROR_VIO_INVALID_HANDLE    421L

/* 3. FLAT POINTERS (Emulator performs Map16to32 into these types) */
typedef void          *PVOID;
typedef CHAR          *PCH;
typedef CHAR          *PCHAR;

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

/* 5. KEYBOARD (KBD) STRUCTURES */
typedef struct _KBDKEYINFO {
    UCHAR  chChar;    /* ASCII character code */
    UCHAR  chScan;    /* Keyboard scan code */
    UCHAR  fbStatus;  /* State of character */
    UCHAR  bNlsShift; /* National Language Support shift status */
    USHORT fsState;   /* Shift, Ctrl, Alt key states */
    ULONG  time;      /* Event timestamp */
} KBDKEYINFO, *PKBDKEYINFO;

#endif /* __WINE_OS2TYPES_H */
