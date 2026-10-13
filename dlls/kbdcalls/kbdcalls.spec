# moucalls.spec - Native OS/2 Mouse Subsystem API Dynamic Link Library
# (c) Arucard 2026 - Wine-OS/2 Project

# 16-bit
10 pascal Mou16GetNumButtons(ptr long) os2_Mou16GetNumButtons

# 32-bit
10 stdcall -norelay MouGetNumButtons(ptr long) os2_MouGetNumButtons

