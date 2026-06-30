// KurokoNX shim — <pty.h> (no PTYs on Horizon; stubbed for link in kuro_posix.c).
#pragma once
#ifdef __SWITCH__
#include <sys/types.h>
struct termios;
struct winsize;
int openpty(int *amaster, int *aslave, char *name, const struct termios *termp, const struct winsize *winp);
int forkpty(int *amaster, char *name, const struct termios *termp, const struct winsize *winp);
#endif // __SWITCH__
