// KurokoNX shim — <gnu/libc-version.h> (box64 presents a glibc identity to guests).
#pragma once
#ifdef __SWITCH__
const char *gnu_get_libc_version(void);
const char *gnu_get_libc_release(void);
#endif // __SWITCH__
