# kbdcalls.spec - OS/2 Keyboard Subsystem Ordinal Mapping Descriptor

# 16-bit Legacy OS/2 APIs (NE) - Handled as generic callbacks receiving the CPU context pointer
4   cdecl Kbd16CharIn(ptr) os2_Kbd16CharIn
9   cdecl Kbd16StringIn(ptr) os2_Kbd16StringIn
19  cdecl Kbd16SetStatus(ptr) os2_Kbd16SetStatus
29  cdecl Kbd16GetStaus(ptr) os2_Kbd16GetStatus
42  cdecl Kbd16FlushBuffer(ptr) os2_Kbd16FlushBuffer

# 32-bit Native OS/2 APIs (LX) - Called natively by 32-bit flat binaries
104 cdecl KbdCharIn(long long) os2_KbdCharIn
109 cdecl KbdStringIn(ptr ptr long) os2_KbdStringIn
111 cdecl KbdSetStatus(ptr long) os2_KbdSetStatus
110 cdecl KbdGetStaus(ptr long) os2_KbdGetStatus
113 cdecl KbdFlushBuffer(ptr) os2_KbdFlushBuffer
