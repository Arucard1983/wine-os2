# viocalls.spec - Native OS/2 Video Subsystem API Dynamic Link Library
# (c) Arucard 2026 - Wine-OS/2 Project

5 stdcall -norelay VioWrtTTY(ptr long long) os2_VioWrtTTY
3 stdcall -norelay VioWrtCharStr(ptr long long long long) os2_VioWrtCharStr
13 stdcall -norelay VioSetCurPos(long long long) os2_VioSetCurPos
