# kbdcalls.spec - OS/2 Keyboard Subsystem Ordinal Mapping Descriptor

# 16-bit Legacy OS/2 APIs (NE) - Handled as generic callbacks receiving the CPU context pointer
4   cdecl Kbd16CharIn(ptr) os2_Kbd16CharIn
9   cdecl Kbd16StringIn(ptr) os2_Kbd16StringIn
11  cdecl Kbd16SetStatus(ptr) os2_Kbd16SetStatus
42  cdecl Kbd16GetLayout(str ptr long) os2_Kbd16GetLayout
64  cdecl VioQueryFonts(ptr) os2_VioQueryFonts

# 32-bit Native OS/2 APIs (LX) - Called natively by 32-bit flat binaries
19 cdecl KbdStringIn(ptr ptr long long) os2_KbdStringIn
29 cdecl KbdSetStatus(ptr long) os2_KbdSetStatus
42 cdecl KbdGetLayout(str ptr long) os2_KbdGetLayout
104 cdecl KbdCharIn(ptr long long) os2_KbdCharIn

