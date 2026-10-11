#
# viocalls.spec - Native OS/2 Video Subsystem API Dynamic Link Library
# (c) Arucard 2026 - Wine-OS/2 Project
#

@ stdcall -norelay VioWrtTTY(ptr long long)
@ stdcall -norelay VioWrtCharStr(ptr long long long long)
@ stdcall -norelay VioSetCurPos(long long long)
