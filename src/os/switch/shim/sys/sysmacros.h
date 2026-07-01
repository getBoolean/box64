// box64-nx shim — <sys/sysmacros.h> (device-number macros).
#pragma once
#ifdef __SWITCH__
#define major(dev)        ((unsigned int)(((dev) >> 8) & 0xff))
#define minor(dev)        ((unsigned int)((dev) & 0xff))
#define makedev(ma, mi)   ((((unsigned int)(ma)) << 8) | ((unsigned int)(mi)))
#endif // __SWITCH__
