// KurokoNX shim — <sys/vfs.h> (statfs). Linux struct layout; stubbed in kuro_posix.c.
#pragma once
#ifdef __SWITCH__
#include <sys/types.h>

typedef struct { int __val[2]; } fsid_t;

struct statfs {
    unsigned long f_type;
    unsigned long f_bsize;
    unsigned long f_blocks;
    unsigned long f_bfree;
    unsigned long f_bavail;
    unsigned long f_files;
    unsigned long f_ffree;
    fsid_t        f_fsid;
    unsigned long f_namelen;
    unsigned long f_frsize;
    unsigned long f_flags;
    unsigned long f_spare[4];
};

int statfs(const char *path, struct statfs *buf);
int fstatfs(int fd, struct statfs *buf);

#endif // __SWITCH__
