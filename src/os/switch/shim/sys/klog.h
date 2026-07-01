// box64-nx shim — <sys/klog.h> (Linux kernel log; stubbed for link).
#pragma once
#ifdef __SWITCH__
int klogctl(int type, char *bufp, int len);
#endif // __SWITCH__
