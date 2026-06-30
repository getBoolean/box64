// KurokoNX shim — <sys/termios.h>. newlib's <termios.h> includes this but only ships
// <machine/termios.h>; redirect to it.
#pragma once
#ifdef __SWITCH__
#include <machine/termios.h>
#endif // __SWITCH__
