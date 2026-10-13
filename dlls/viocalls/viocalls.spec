# viocalls.spec - OS/2 Video Subsystem Ordinal Mapping Descriptor

# 16-bit Legacy OS/2 APIs (NE) - Called by 286 Emulator Call Gates
5   pascal Vio16WrtTTY(long long long) os2_Vio16WrtTTY

# 32-bit Native OS/2 APIs (LX) - Called natively by 32-bit flat binaries
115 cdecl  VioWrtTTY(ptr long long) os2_VioWrtTTY
