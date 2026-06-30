// KurokoNX shim — glibc large-file (*64) types/functions as REAL symbols.
// Macro-aliasing (#define stat64 stat) corrupts box64's wrapper tables (which have
// both `stat` and `stat64` members), so these are real declarations; the bodies in
// kuro_posix.c forward to the plain newlib calls (newlib's off_t is already 64-bit).
#pragma once
#ifdef __SWITCH__
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <stdio.h>

// Byte-identical to newlib's aarch64 struct stat (so a cast in the wrappers is valid,
// and newlib's st_atime/st_mtime/st_ctime compat macros apply to it too).
struct stat64 {
    dev_t           st_dev;
    ino_t           st_ino;
    mode_t          st_mode;
    nlink_t         st_nlink;
    uid_t           st_uid;
    gid_t           st_gid;
    dev_t           st_rdev;
    off_t           st_size;
    struct timespec st_atim;
    struct timespec st_mtim;
    struct timespec st_ctim;
    blksize_t       st_blksize;
    blkcnt_t        st_blocks;
    long            st_spare4[2];
};

// glibc dirent64 (box64's scandir64 filter/compare are typed on it). Horizon's scandir64
// is stubbed, so the extra fields are never populated/read at runtime.
struct dirent64 {
    ino_t          d_ino;
    off_t          d_off;
    unsigned short d_reclen;
    unsigned char  d_type;
    char           d_name[256];
};

int   stat64(const char *path, struct stat64 *buf);
int   fstat64(int fd, struct stat64 *buf);
int   lstat64(const char *path, struct stat64 *buf);
int   fstatat64(int dirfd, const char *path, struct stat64 *buf, int flags);
int   open64(const char *path, int flags, ...);
int   openat64(int dirfd, const char *path, int flags, ...);
int   creat64(const char *path, mode_t mode);
FILE *fopen64(const char *path, const char *mode);
FILE *freopen64(const char *path, const char *mode, FILE *stream);
FILE *tmpfile64(void);
struct dirent64 *readdir64(DIR *dirp);
int   scandir64(const char *dirp, struct dirent64 ***namelist,
                int (*filter)(const struct dirent64 *),
                int (*compar)(const struct dirent64 **, const struct dirent64 **));
int   scandirat64(int dirfd, const char *dirp, struct dirent64 ***namelist,
                  int (*filter)(const struct dirent64 *),
                  int (*compar)(const struct dirent64 **, const struct dirent64 **));

#include <glob.h>
#include <ftw.h>
typedef glob_t glob64_t;
int  glob64(const char *pattern, int flags, int (*errfunc)(const char *, int), glob64_t *pglob);
void globfree64(glob64_t *pglob);
int  ftw64(const char *dirpath, int (*fn)(const char *, const struct stat64 *, int), int nopenfd);
int  nftw64(const char *dirpath, int (*fn)(const char *, const struct stat64 *, int, struct FTW *), int nopenfd, int flags);

// glibc ctype table accessors (newlib uses __ctype_ptr__); impl in kuro_posix.c.
const unsigned short **__ctype_b_loc(void);
const int **__ctype_toupper_loc(void);
const int **__ctype_tolower_loc(void);

// mknod exists in newlib <sys/stat.h> but is visibility-gated; redeclare.
int mknod(const char *pathname, mode_t mode, dev_t dev);

#endif // __SWITCH__
