# doscalls.spec - OS/2 Core Subsystem Ordinal Mapping using NTDLL Backends

# 16-bit Legacy OS/2 APIs (NE) - Handled as generic callbacks receiving the CPU context pointer
5   cdecl Dos16Exit(ptr) os2_Dos16Exit
137 cdecl Dos16Read(ptr) os2_Dos16Read
138 cdecl Dos16Write(ptr) os2_Dos16Write

# 32-bit Native OS/2 APIs (LX) - Mapped correctly with standard architecture types
234 cdecl DosExit(long long) os2_DosExit
281 cdecl DosRead(long ptr long ptr) os2_DosRead
282 cdecl DosWrite(long ptr long ptr) os2_DosWrite

