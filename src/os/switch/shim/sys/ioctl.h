// box64-nx shim — <sys/ioctl.h> (Horizon has no device ioctls; stubbed in nx_posix.c).
#pragma once
#ifdef __SWITCH__
int ioctl(int fd, unsigned long request, ...);
#endif // __SWITCH__
