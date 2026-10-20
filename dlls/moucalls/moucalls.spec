# moucalls.spec - OS/2 Mouse Subsystem Ordinal Mapping Descriptor

# 16-bit Legacy OS/2 APIs (NE) - Handled as generic callbacks receiving the CPU context pointer
8     cdecl Mou16GetNumButtons(ptr) os2_Mou16GetNumButtons
19    cdecl Mou16GetPtrPos(ptr) os2_Mou16GetPtrPos

# 32-bit Native OS/2 APIs (LX) - Called natively by 32-bit flat binaries
10008 cdecl MouGetNumButtons(ptr long) os2_MouGetNumButtons
10019 cdecl MouGetPtrPos(ptr long) os2_MouGetPtrPos
