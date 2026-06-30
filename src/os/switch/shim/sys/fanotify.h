// KurokoNX shim — <sys/fanotify.h> (Linux fanotify; stubbed for link).
#pragma once
#ifdef __SWITCH__
int fanotify_init(unsigned int flags, unsigned int event_f_flags);
int fanotify_mark(int fanotify_fd, unsigned int flags, unsigned long long mask, int dirfd, const char *pathname);
#endif // __SWITCH__
