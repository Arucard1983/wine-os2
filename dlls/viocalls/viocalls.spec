# viocalls.spec - Native OS/2 Video Subsystem API Dynamic Link Library
# (c) Arucard 2026 - Wine-OS/2 Project

# 16-bit Legacy Protected Mode Entries (NE Call Gates)
5  pascal Vio16WrtTTY(ptr long long) os2_Vio16WrtTTY
13 pascal Vio16SetCurPos(long long long) os2_Vio16SetCurPos

# 32-bit Native Flat Entries (LX Fixups)
3  stdcall -norelay VioWrtCharStr(ptr long long long long) os2_VioWrtCharStr
5  stdcall -norelay VioWrtTTY(ptr long long) os2_VioWrtTTY
13 stdcall -norelay VioSetCurPos(long long long) os2_VioSetCurPos

