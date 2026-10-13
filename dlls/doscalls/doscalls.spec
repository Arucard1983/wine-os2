# doscalls.spec - OS/2 Core Subsystem Ordinal Mapping using NTDLL Backends

# 16-bit Legacy OS/2 APIs (NE) - Called by 286 Emulator Call Gates
5   pascal Dos16Exit(long long) os2_Dos16Exit
137 pascal Dos16Read(long ptr long ptr) os2_Dos16Read
138 pascal Dos16Write(long ptr long ptr) os2_Dos16Write

# 32-bit Native OS/2 APIs (LX) - Called natively by 32-bit flat binaries
234 cdecl  DosExit(long long) os2_DosExit
281 cdecl  DosRead(long ptr long ptr) os2_DosRead
282 cdecl  DosWrite(long ptr long ptr) os2_DosWrite
