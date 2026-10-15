# kbdcalls.spec - OS/2 Keyboard Subsystem Ordinal Mapping Descriptor

# 16-bit Legacy OS/2 APIs (NE) - Handled as generic callbacks receiving the CPU context pointer
4   cdecl Kbd16CharIn(ptr) os2_Kbd16CharIn

# 32-bit Native OS/2 APIs (LX) - Called natively by 32-bit flat binaries
104 cdecl KbdCharIn(ptr long long) os2_KbdCharIn

