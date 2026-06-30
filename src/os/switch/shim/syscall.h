// KurokoNX shim — bare <syscall.h> (glibc alias for <sys/syscall.h>).
#pragma once
#ifdef __SWITCH__
#include <sys/syscall.h>
#endif // __SWITCH__
