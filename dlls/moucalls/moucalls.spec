# moucalls.spec - OS/2 Mouse Subsystem Ordinal Mapping Descriptor

# 16-bit Legacy OS/2 APIs (NE) - Called by 286 Emulator Call Gates
4   pascal Mou16GetPtrPos(long long) os2_Mou16GetPtrPos

# 32-bit Native OS/2 APIs (LX) - Called natively by 32-bit flat binaries
104 cdecl  MouGetPtrPos(ptr long) os2_MouGetPtrPos
