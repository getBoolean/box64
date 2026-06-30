// KurokoNX shim — <poll.h> (Horizon has no poll; stubbed in kuro_posix.c).
#pragma once
#ifdef __SWITCH__
typedef unsigned long nfds_t;

struct pollfd {
    int   fd;
    short events;
    short revents;
};

#define POLLIN     0x001
#define POLLPRI    0x002
#define POLLOUT    0x004
#define POLLERR    0x008
#define POLLHUP    0x010
#define POLLNVAL   0x020
#define POLLRDNORM 0x040
#define POLLRDBAND 0x080
#define POLLWRNORM 0x100
#define POLLWRBAND 0x200

int poll(struct pollfd *fds, nfds_t nfds, int timeout);

#endif // __SWITCH__
