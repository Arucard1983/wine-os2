# kbdcalls.spec - OS/2 Keyboard Subsystem Ordinal Mapping Descriptor

# 16-bit Legacy OS/2 APIs (NE) - Called by 286 Emulator Call Gates
4   pascal Kbd16CharIn(ptr long long) os2_Kbd16CharIn

# 32-bit Native OS/2 APIs (LX) - Called natively by 32-bit flat binaries
104 cdecl  KbdCharIn(ptr long long) os2_KbdCharIn
