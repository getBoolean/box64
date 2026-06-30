// KurokoNX shim — <sys/random.h> (getrandom; backed by libnx randomGet in kuro_posix.c).
#pragma once
#ifdef __SWITCH__
#include <sys/types.h>
#define GRND_NONBLOCK 0x0001
#define GRND_RANDOM   0x0002
#define GRND_INSECURE 0x0004
ssize_t getrandom(void *buf, size_t buflen, unsigned int flags);
#endif // __SWITCH__
