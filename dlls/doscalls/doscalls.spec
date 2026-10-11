#
# doscalls.spec - Native OS/2 Core API Dynamic Link Library
# (c) Arucard 2026 - Wine-OS/2 Project
#

@ stdcall -norelay DosWrite(long ptr long ptr)
@ stdcall -norelay DosAllocSeg(long ptr long)
@ stdcall -norelay DosOpen(ptr ptr ptr long long long long ptr)
@ stdcall -norelay DosExit(long long)
