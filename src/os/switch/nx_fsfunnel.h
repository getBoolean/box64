// nx_fsfunnel.h — SD I/O funnel API (box64-nx). See nx_fsfunnel.c.
//
// Guest file I/O ANTI-scales on the Switch: 1 thread ~160 file-ops/s, but 12 concurrent threads
// aggregate only ~126/s — concurrency makes it WORSE. fsdev is lock-free, but every op multiplexes
// over libnx's 3-session fsp-srv pool onto ONE sdmc: IFileSystem -> ONE FS sysmodule -> ONE serial
// SD device; 12 threads interleaving onto that serial device destroys sequential locality and
// oversubscribes the pool. The funnel routes real fsdev ops through a small dedicated worker pool
// (default N=1): guest threads enqueue + block, the worker drains a FIFO. Submission becomes ordered
// and de-oversubscribed, which removes the anti-scale penalty (the serial ~160 ops/s ceiling is
// unchanged — this stops threading from HURTING, it doesn't make it help).
//
// v1 = metadata only (resolve/open/stat/mkdir/unlink/rmdir/rename/getdents/ftruncate/close) — exactly
// the op class the measured anti-scale is made of. v2 (later) adds the data path.
#pragma once
#ifdef __SWITCH__

#include <stddef.h>
#include <sys/types.h>   // mode_t, off_t

struct stat;

// One directory entry captured at opendir time (moved here from nx_vfd.c so nx_fs_getdents can hand
// back the snapshot). A VK_DIR vfd reads the whole dir once and holds NO persistent fsdev handle.
typedef struct { char name[256]; unsigned char type; } nx_dent_t;

#ifdef __cplusplus
extern "C" {
#endif

// Wrappers = the only v1 API. Each takes a HOST (already-translated) path/fd and performs ONLY the raw
// newlib fsdev call on the worker; resolution, IPC counters and cache invalidation stay on the CALLER
// thread. errno is the HOST (newlib) value the syscall-return seam later translates to Linux. When the
// funnel is off (KX_NO_FSFUNNEL) or the caller is itself a worker, every wrapper degrades to a direct
// call on the calling thread — byte-for-byte identical to the pre-funnel code.
int  nx_fs_resolve(const char* guest, char* out, size_t outn, int* exists, int* isdir, struct stat* st);
int  nx_fs_open(const char* host, int flags, mode_t mode);
int  nx_fs_stat(const char* host, struct stat* st);
int  nx_fs_mkdir(const char* host, mode_t mode);
int  nx_fs_unlink(const char* host);
int  nx_fs_rmdir(const char* host);
int  nx_fs_rename(const char* host_a, const char* host_b);
long nx_fs_getdents(const char* host, nx_dent_t** dents, int* n, int* cap);
int  nx_fs_ftruncate(int fd, off_t len);
int  nx_fs_close(int fd);
int  nx_fs_in_worker(void);   // 1 iff called on a funnel worker (a nested FS op then runs direct)

// Op "direct" bodies that need caller-module state (rootfs macros / IPC counters); the worker calls
// these instead of re-implementing them. Defined where their dependencies live.
int  nx_fs_resolve_direct(const char* guest, char* out, size_t outn,
                          int* exists, int* isdir, struct stat* st);   // nx_posix.c
int  nx_fs_rename_direct(const char* host_a, const char* host_b);      // nx_vfd.c

#ifdef __cplusplus
}
#endif

#endif // __SWITCH__
