// KurokoNX shim — <sys/fsuid.h> (Linux fs uid/gid; stubbed for link).
#pragma once
#ifdef __SWITCH__
#include <sys/types.h>
int setfsuid(uid_t fsuid);
int setfsgid(gid_t fsgid);
#endif // __SWITCH__
