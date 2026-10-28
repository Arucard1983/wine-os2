# doscalls.spec - OS/2 Core Subsystem Ordinal Mapping using NTDLL Backends
# (c) Arucard 2026 - Wine-OS/2 Project

# =========================================================================
# 16-BIT LEGACY OS/2 APIs (NE Subsystem)
# Handled as generic callbacks receiving the CPU context pointer
# =========================================================================
5   cdecl Dos16Exit(ptr) os2_Dos16Exit
34  cdecl Dos16Allocseg(ptr) os2_Dos16Allocseg
38  cdecl Dos16ReAllocseg(ptr) os2_Dos16ReAllocseg
49  cdecl Dos16GetMachineMode(ptr) os2_Dos16GetMachineMode
58  cdecl Dos16ChgFilePtr(ptr) os2_Dos16ChgFilePtr
59  cdecl Dos16Close(ptr) os2_Dos16Close
60  cdecl Dos16Delete(ptr) os2_Dos16Delete
64  cdecl Dos16FindFirst(ptr) os2_Dos16FindFirst
65  cdecl Dos16FindNext(ptr) os2_Dos16FindNext
68  cdecl Dos16NewSize(ptr) os2_Dos16NewSize
70  cdecl Dos16Open(ptr) os2_Dos16Open
74  cdecl Dos16QFHandState(ptr) os2_Dos16QFHandState
75  cdecl Dos16QFileMode(ptr) os2_Dos16QFileMode
77  cdecl Dos16QHandType(ptr) os2_Dos16QHandType
83  cdecl Dos16SetFileInfo(ptr) os2_Dos16SetFileInfo
84  cdecl Dos16SetFileMode(ptr) os2_Dos16SetFileMode
89  cdecl Dos16SetVec(ptr) os2_Dos16SetVec
92  cdecl Dos16GetVersion(ptr) os2_Dos16GetVersion
137 cdecl Dos16Read(ptr) os2_Dos16Read
138 cdecl Dos16Write(ptr) os2_Dos16Write
144 cdecl Dos16ExecPgm(ptr) os2_Dos16ExecPgm
151 cdecl Dos16SearchPath(ptr) os2_Dos16SearchPath

# =========================================================================
# 32-BIT NATIVE OS/2 APIs (LX Subsystem)
# Mapped accurately with correct architecture types (long vs ptr)
# =========================================================================
10049 cdecl DosGetMachineMode(ptr) os2_DosGetMachineMode
10075 cdecl DosQueryFileMode(ptr ptr long) os2_DosQueryFileMode
10084 cdecl DosSetFileMode(ptr long long) os2_DosSetFileMode
10089 cdecl DosSetVec(long ptr ptr) os2_DosSetVec
10218 cdecl DosSetFileInfo(long long ptr long) os2_DosSetFileInfo
10224 cdecl DosQueryHType(long ptr ptr) os2_DosQueryHType
10228 cdecl DosSearchPath(long ptr ptr ptr long) os2_DosSearchPath
10234 cdecl DosExit(long long) os2_DosExit
10256 cdecl DosSetFilePtr(long long long ptr) os2_DosSetFilePtr
10257 cdecl DosClose(long) os2_DosClose
10259 cdecl DosDelete(ptr long) os2_DosDelete
10264 cdecl DosFindFirst(ptr ptr long ptr long ptr long) os2_DosFindFirst
10265 cdecl DosFindNext(long ptr long ptr) os2_DosFindNext
10272 cdecl DosSetFileSize(long long) os2_DosSetFileSize
10273 cdecl DosOpen(ptr ptr ptr long long long long ptr) os2_DosOpen
10279 cdecl DosQueryFileInfo(long long ptr long) os2_DosQueryFileInfo
10281 cdecl DosRead(long ptr long ptr) os2_DosRead
10282 cdecl DosWrite(long ptr long ptr) os2_DosWrite
10283 cdecl DosExecPgm(ptr long long ptr ptr ptr ptr) os2_DosExecPgm
10299 cdecl DosAllocMem(ptr long long) os2_DosAllocMem
10348 cdecl DosQuerySysInfo(long long ptr long) os2_DosQuerySysInfo

