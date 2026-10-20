# viocalls.spec - OS/2 Video Subsystem Ordinal Mapping Descriptor

# 16-bit Legacy OS/2 APIs (NE) - Handled as generic callbacks receiving the CPU context pointer
5   cdecl Vio16WrtTTY(ptr) os2_Vio16WrtTTY
64  cdecl Vio16QueryFonts(ptr ptr ptr long ptr str long) os2_Vio16QueryFonts


# 32-bit Native OS/2 APIs (LX) - Called natively by 32-bit flat binaries
115 cdecl VioWrtTTY(ptr long long) os2_VioWrtTTY
164 cdecl VioQueryFonts(ptr ptr ptr long ptr str long) os2_VioQueryFonts
