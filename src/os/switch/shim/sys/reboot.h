// box64-nx shim — <sys/reboot.h> (Linux reboot; stubbed for link).
#pragma once
#ifdef __SWITCH__
#define RB_AUTOBOOT     0x01234567
#define RB_HALT_SYSTEM  0xcdef0123
#define RB_ENABLE_CAD   0x89abcdef
#define RB_DISABLE_CAD  0x00000000
#define RB_POWER_OFF    0x4321fedc
int reboot(int howto);
#endif // __SWITCH__
