// box64-nx shim — <sys/quota.h> (Linux disk quotas; stubbed for link).
#pragma once
#ifdef __SWITCH__
#include <sys/types.h>
#define Q_SYNC     0x800001
#define Q_QUOTAON  0x800002
#define Q_QUOTAOFF 0x800003
#define Q_GETQUOTA 0x800007
#define Q_SETQUOTA 0x800008
int quotactl(int cmd, const char *special, int id, char *addr);
#endif // __SWITCH__
