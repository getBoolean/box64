// KurokoNX shim — <sys/ioctl.h> (Horizon has no device ioctls; stubbed in kuro_posix.c).
#pragma once
#ifdef __SWITCH__
int ioctl(int fd, unsigned long request, ...);
#endif // __SWITCH__
