// box64-nx shim — <sys/eventfd.h> (Horizon has no eventfd; stubbed in nx_posix.c).
#pragma once
#ifdef __SWITCH__
#include <stdint.h>

typedef uint64_t eventfd_t;

#define EFD_SEMAPHORE 00000001
#define EFD_CLOEXEC   02000000
#define EFD_NONBLOCK  00004000

int eventfd(unsigned int initval, int flags);
int eventfd_read(int fd, eventfd_t *value);
int eventfd_write(int fd, eventfd_t value);

#endif // __SWITCH__
