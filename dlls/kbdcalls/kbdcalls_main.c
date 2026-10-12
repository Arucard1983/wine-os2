#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "os2types.h"

/* OS/2 32-bit KbdCharIn: Reads a character object from the keyboard stream */
APIRET WINAPI os2_KbdCharIn(PKBDKEYINFO pKbdKeyInfo, ULONG fWait, ULONG hKbd) {
    if (hKbd != 0) return 1; /* ERROR_KBD_INVALID_HANDLE */
    if (!pKbdKeyInfo) return NO_ERROR;

    /* Minimal stub: read from standard console input if waiting is requested */
    if (fWait == 0) {
        HANDLE host_stdin = GetStdHandle(STD_INPUT_HANDLE);
        INPUT_RECORD ir;
        DWORD read;
        
        if (PeekConsoleInputA(host_stdin, &ir, 1, &read) && read > 0) {
            if (ir.EventType == KEY_EVENT && ir.Event.KeyEvent.bKeyDown) {
                ReadConsoleInputA(host_stdin, &ir, 1, &read);
                pKbdKeyInfo->chChar = ir.Event.KeyEvent.uChar.AsciiChar;
                pKbdKeyInfo->chScan = ir.Event.KeyEvent.wVirtualScanCode;
                return NO_ERROR;
            }
        }
    }
    return NO_ERROR;
}
