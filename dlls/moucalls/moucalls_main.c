#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "os2types.h"

// Get the number of mouse buttons. Notice the cleaniless to use Wine's own Win32API to get the required information!
APIRET WINAPI os2_MouGetNumButtons(PUSHORT pNumberOfButtons, ULONG hMou) {
    if (hMou != 0) return 1; /* ERROR_MOU_INVALID_HANDLE */
    if (!pNumberOfButtons) return 0; /* NO_ERROR */

    /* SM_CMOUSEBUTTONS = 43. Returns the exact number of mouse buttons */
    int buttons = GetSystemMetrics(SM_CMOUSEBUTTONS);
    
    if (buttons == 0) {
        *pNumberOfButtons = 2; /* Fallback safe para o OS/2 */
    } else {
        *pNumberOfButtons = (USHORT)buttons;
    }
    
    return NO_ERROR;
}
