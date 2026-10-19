# doscalls.spec - OS/2 Core Subsystem Ordinal Mapping using NTDLL Backends

# 16-bit Legacy OS/2 APIs (NE) - Handled as generic callbacks receiving the CPU context pointer
5   cdecl Dos16Exit(ptr) os2_Dos16Exit
34  cdecl Dos16Exit(ptr) os2_Dos16Allocseg
38  cdecl Dos16Exit(ptr) os2_Dos16ReAllocseg
49  cdecl Dos16Exit(ptr) os2_Dos16GetMachineMode
58  cdecl Dos16Exit(ptr) os2_Dos16ChgFilePtr
59  cdecl Dos16Exit(ptr) os2_Dos16Close
64  cdecl Dos16Exit(ptr) os2_Dos16FindFirst
65  cdecl Dos16Exit(ptr) os2_Dos16FindNext
70  cdecl Dos16Exit(ptr) os2_Dos16Open
74  cdecl Dos16Exit(ptr) os2_Dos16QFHandState
75  cdecl Dos16Exit(ptr) os2_Dos16QFileMode
77  cdecl Dos16Exit(ptr) os2_Dos16QHandType
83  cdecl Dos16Exit(ptr) os2_Dos16SetFileInfo
84  cdecl Dos16Exit(ptr) os2_Dos16SetFileMode
89  cdecl Dos16Exit(ptr) os2_Dos16SetVec
92  cdecl Dos16Exit(ptr) os2_Dos16GetEnv
137 cdecl Dos16Read(ptr) os2_Dos16Read
138 cdecl Dos16Write(ptr) os2_Dos16Write
144 cdecl Dos16Write(ptr) os2_Dos16ExecPgm
151 cdecl Dos16Write(ptr) os2_Dos16SearchPath

# 32-bit Native OS/2 APIs (LX) - Mapped correctly with standard architecture types
49  cdecl DosGetMachineMode(long) os2_DosGetMachineMode
234 cdecl DosExit(long long) os2_DosExit
256 cdecl DosExit(long long) os2_DosSetFilePtr
257 cdecl DosExit(long long) os2_DosClose
264 cdecl DosExit(long long) os2_DosFindFirt
265 cdecl DosExit(long long) os2_DosFindNext
273 cdecl DosExit(long long) os2_DosOpen
279 cdecl DosExit(long long) os2_DosQuerFileInfo
281 cdecl DosRead(long ptr long ptr) os2_DosRead
282 cdecl DosWrite(long ptr long ptr) os2_DosWrite
299 cdecl DosWrite(long ptr long ptr long ptr) os2_DosAllocSeg
