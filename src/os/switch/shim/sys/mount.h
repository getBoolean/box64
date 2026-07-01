// box64-nx shim — <sys/mount.h> (Linux mount; stubbed for link).
#pragma once
#ifdef __SWITCH__
#define MS_RDONLY      1
#define MS_NOSUID      2
#define MS_NODEV       4
#define MS_NOEXEC      8
#define MS_REMOUNT     32
#define MS_BIND        4096
#define MS_MOVE        8192
#define MS_REC         16384
#define MNT_FORCE      1
#define MNT_DETACH     2
#define MNT_EXPIRE     4
#define UMOUNT_NOFOLLOW 8

int mount(const char *source, const char *target, const char *filesystemtype, unsigned long mountflags, const void *data);
int umount(const char *target);
int umount2(const char *target, int flags);
#endif // __SWITCH__
