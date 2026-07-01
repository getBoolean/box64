// box64-nx shim — <sys/personality.h> (Linux execution domain; stubbed for link).
#pragma once
#ifdef __SWITCH__
#define ADDR_NO_RANDOMIZE 0x0040000
#define ADDR_COMPAT_LAYOUT 0x0200000
#define ADDR_LIMIT_32BIT  0x0800000
#define ADDR_LIMIT_3GB    0x8000000
#define READ_IMPLIES_EXEC 0x0400000
#define PER_LINUX         0x0000
#define PER_LINUX32       0x0008
int personality(unsigned long persona);
#endif // __SWITCH__
