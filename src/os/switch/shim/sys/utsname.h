// KurokoNX shim — <sys/utsname.h>. uname() is implemented in kuro_posix.c with
// plausible KurokoNX/Horizon values so guests that probe the kernel get an answer.
#pragma once
#ifdef __SWITCH__
#define _UTSNAME_LENGTH 65

struct utsname {
    char sysname[_UTSNAME_LENGTH];
    char nodename[_UTSNAME_LENGTH];
    char release[_UTSNAME_LENGTH];
    char version[_UTSNAME_LENGTH];
    char machine[_UTSNAME_LENGTH];
    char domainname[_UTSNAME_LENGTH];
};

int uname(struct utsname *buf);

#endif // __SWITCH__
