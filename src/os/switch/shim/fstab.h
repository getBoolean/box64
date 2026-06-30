// KurokoNX shim — <fstab.h> (glibc fstab; stubbed for link).
#pragma once
#ifdef __SWITCH__
struct fstab {
    char *fs_spec;
    char *fs_file;
    char *fs_vfstype;
    char *fs_mntops;
    const char *fs_type;
    int   fs_freq;
    int   fs_passno;
};
int   setfsent(void);
void  endfsent(void);
struct fstab *getfsent(void);
struct fstab *getfsspec(const char *name);
struct fstab *getfsfile(const char *name);
#endif // __SWITCH__
