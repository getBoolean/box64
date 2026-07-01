// box64-nx shim — <sys/timerfd.h> (Linux timerfd; stubbed for link).
#pragma once
#ifdef __SWITCH__
#include <time.h>
#define TFD_CLOEXEC   02000000
#define TFD_NONBLOCK  00004000
#define TFD_TIMER_ABSTIME 1
int timerfd_create(int clockid, int flags);
int timerfd_settime(int fd, int flags, const struct itimerspec *new_value, struct itimerspec *old_value);
int timerfd_gettime(int fd, struct itimerspec *curr_value);
#endif // __SWITCH__
