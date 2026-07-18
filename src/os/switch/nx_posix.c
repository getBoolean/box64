// box64-nx — "kuro-posix" implementation (libnx). See nx_posix.h.
#ifdef __SWITCH__

#include "nx_posix.h"

#include <switch.h>
#include <stdlib.h>
#include <malloc.h>     // memalign
#include <string.h>
#include <errno.h>
#include <stdio.h>      // vsnprintf
#include <stdarg.h>
#include <sys/mman.h>   // PROT_*/MAP_* (box64-nx shim)
#include <fcntl.h>      // open/O_RDONLY (M2.1 rootfs shim)
#include <unistd.h>     // read/close/lseek
#include <pthread.h>    // guest threads (clone) run on host pthreads
#include <stdatomic.h>  // per-thread tid counter
#include <limits.h>     // INT_MAX (futex wake-all)

// box64-internal (src/libtools/threads.c): drop this thread's emu from the pthread key so the key
// destructor can't double-free the emu clone_fn_syscall already released (see clone() below).
extern void thread_forget_emu(void);
extern void thread_free_forgotten_emu(void);   // M2.6: same, plus free the ~64B wrapper (fixes the leak)
void nx_guest_output(int fd, const void *buf, size_t len);   // nx_main.c — debug log + result-file tee

#define NX_PAGE 0x1000UL

// Loud one-line warning to the Horizon debug log (svcOutputDebugString, which Ryujinx surfaces).
// Used to make still-faked host primitives announce themselves, so a guest that trips one produces
// a self-explaining log line instead of failing silently. Deliberately dependency-free (no box64
// debug.h) so it is safe to call from the lowest-level POSIX shims.
static void nx_warnf(const char *fmt, ...) {
    char b[160];
    va_list ap; va_start(ap, fmt);
    int n = vsnprintf(b, sizeof b, fmt, ap);
    va_end(ap);
    if (n < 0) return;
    if (n > (int)sizeof b - 1) n = (int)sizeof b - 1;
    svcOutputDebugString(b, (size_t)n);
}

// nx_mmap / nx_munmap moved to nx_virtmem.c (phase 1): a real page-granular allocator over the
// Alias region (svcMapPhysicalMemory) with reclaiming munmap, falling back to the heap path if the
// arena can't init. See nx_virtmem.c.

// --- Guest threads (M2.2) -----------------------------------------------------------------------
// The guest's real glibc creates threads with a raw x86-64 clone syscall; box64 (x64syscall.c case 56)
// builds a child x64emu_t and calls the host clone() below. We run box64's clone_fn_syscall on a
// DETACHED host pthread (so its pthread-key emu lookup + per-thread errno/_reent work). A per-thread
// record carries the tid + the CLONE_CHILD_CLEARTID address so nx_gettid() and thread-exit find them.
typedef struct nx_clone_s {
    int  (*fn)(void*);   // == clone_fn_syscall
    void*  arg;          // == clone_t* (opaque — never dereference)
    int    flags;
    int*   ctid;         // CLONE_CHILD_CLEARTID target, or NULL
    int    tid;          // our positive, unique tid (== the value written to *ptid)
    int    gpid;         // creator's guest-instance pid (M2.5) — the child inherits it
} nx_clone_t;

static _Atomic int          g_nx_next_tid = 2;     // 1 is the main thread
static __thread nx_clone_t* g_nx_self     = NULL;  // this thread's record; NULL on the main thread

int nx_gettid(void) {
    // Per-thread tid assigned by clone() (main thread -> 1). Must equal the value glibc caches as
    // pd->tid (we wrote it to *ptid in clone), so pthread_join's futex + robust-mutex owner words agree.
    return g_nx_self ? g_nx_self->tid : 1;
}

int nx_sched_yield(void) {
    svcSleepThread(0);
    return 0;
}

// Probe real Horizon system info via libnx (used by src/os/sysinfo.c, which has no libnx).
// Core count from the process core mask (svcGetInfo), CPU clock from the clkrst service (may
// be stubbed under emulation -> fallback), and the hardware model from set:sys.
void nx_sysinfo(uint64_t *ncpu, uint64_t *freq_hz, char *name, unsigned long namelen) {
    u64 mask = 0;
    if (R_SUCCEEDED(svcGetInfo(&mask, InfoType_CoreMask, CUR_PROCESS_HANDLE, 0)) && mask)
        *ncpu = (uint64_t)__builtin_popcountll(mask);
    else
        *ncpu = 3;   // a homebrew applet is normally granted 3 of the 4 A57 cores

    *freq_hz = 0;
    if (R_SUCCEEDED(clkrstInitialize())) {
        ClkrstSession s;
        if (R_SUCCEEDED(clkrstOpenSession(&s, PcvModuleId_CpuBus, 3))) {
            u32 hz = 0;
            if (R_SUCCEEDED(clkrstGetClockRate(&s, &hz)) && hz) *freq_hz = hz;
            clkrstCloseSession(&s);
        }
        clkrstExit();
    }
    if (!*freq_hz) *freq_hz = 1020000000ULL;   // ~1.02 GHz (docked) fallback

    // NOTE: the exact model (Erista/Mariko/Lite/OLED) is available via setsysGetProductModel
    // (set:sys cmd 79), but Ryujinx *throws* on that unimplemented command and takes the whole
    // emulator down (it doesn't return a catchable error), so we keep a generic name. All models
    // are a Tegra X1/X1+ with a 4x Cortex-A57 cluster, which is what matters for box64.
    const char *model = "Nintendo Switch (Tegra)";
    if (namelen) {
        strncpy(name, model, namelen - 1);
        name[namelen - 1] = '\0';
    }
}

// --- POSIX system-name wrappers (box64 calls these directly in places) -----------------------
#include <dlfcn.h>

// NOTE: mmap/mmap64/munmap are provided by box64's src/custommmap.c, which delegates to
// InternalMmap (os_switch.c -> nx_mmap). We only supply the rest of the mman surface here.
// No real page-permission changes for the interpreter (heap-backed mmap); revisited in M1.2.
int mprotect(void *addr, size_t len, int prot) { return nx_vm_protect(addr, len, prot); }
void *mremap(void *old_addr, size_t old_size, size_t new_size, int flags, ...) {
    // Previously returned a *fresh zeroed* block, silently dropping old_addr's contents — a
    // data-loss trap (glibc malloc arenas / large realloc got zeroed garbage with no error). Fail
    // loudly instead until phase 1 provides a real remap; callers then fall back to malloc+copy+free.
    (void)flags;
    nx_warnf("nx_stub: mremap(old=%p 0x%zx->0x%zx) unsupported -> MAP_FAILED\n", old_addr, old_size, new_size);
    errno = ENOMEM;
    return MAP_FAILED;
}
int madvise(void *a, size_t l, int adv) { (void)a; (void)l; (void)adv; return 0; }
int msync(void *a, size_t l, int f) { (void)a; (void)l; (void)f; return 0; }
int mlock(const void *a, size_t l) { (void)a; (void)l; return 0; }
int munlock(const void *a, size_t l) { (void)a; (void)l; return 0; }
// POSIX shared memory — no cross-process shm on Horizon (single process).
int shm_open(const char *name, int oflag, mode_t mode) { (void)name; (void)oflag; (void)mode; errno = ENOSYS; return -1; }
int shm_unlink(const char *name) { (void)name; errno = ENOSYS; return -1; }

// --- Signal-set builders (newlib leaves these to the port) ------------------------------------
// Real bitmask ops. Signal *delivery* stays stubbed until phase 4, but code must still be able to
// *build* a sigset (glibc/pthread setup does). These were aliased to the -ENOSYS stub, so even
// sigemptyset() failed — a correctness bug that would break the first threaded/libc guest.
// NB: newlib defines sig*set as function-like MACROS in <sys/signal.h>; box64's wrapper tables
// take these by address, so we need real function symbols. #undef the macros, then define them
// (matching newlib's own macro semantics: signals are 1-based, stored in a single unsigned long).
#include <signal.h>
#undef sigemptyset
#undef sigfillset
#undef sigaddset
#undef sigdelset
#undef sigismember
int sigemptyset(sigset_t *set) { if (!set) { errno = EINVAL; return -1; } *set = 0UL;  return 0; }
int sigfillset(sigset_t *set)  { if (!set) { errno = EINVAL; return -1; } *set = ~0UL; return 0; }
int sigaddset(sigset_t *set, int signo) {
    if (!set || signo < 1 || signo > (int)(8 * sizeof(*set))) { errno = EINVAL; return -1; }
    *set |= (1UL << (signo - 1)); return 0;
}
int sigdelset(sigset_t *set, int signo) {
    if (!set || signo < 1 || signo > (int)(8 * sizeof(*set))) { errno = EINVAL; return -1; }
    *set &= ~(1UL << (signo - 1)); return 0;
}
int sigismember(const sigset_t *set, int signo) {
    if (!set || signo < 1 || signo > (int)(8 * sizeof(*set))) { errno = EINVAL; return -1; }
    return (*set & (1UL << (signo - 1))) ? 1 : 0;
}

// --- prctl: Horizon has none; satisfy the PR_SET_NAME box64 calls at startup (was -ENOSYS noise) --
#include <sys/prctl.h>
int prctl(int option, ...) {
    if (option == PR_SET_NAME || option == PR_GET_NAME) return 0;   // thread name: accept + ignore
    errno = ENOSYS; return -1;
}

// --- dlopen stubs (Horizon has no dynamic loading; STATICBUILD never calls these at runtime) --
void *dlopen(const char *f, int fl) { (void)f; (void)fl; return NULL; }
int   dlclose(void *h) { (void)h; return 0; }
void *dlsym(void *h, const char *s) { (void)h; (void)s; return NULL; }
void *dlvsym(void *h, const char *s, const char *v) { (void)h; (void)s; (void)v; return NULL; }
char *dlerror(void) { return (char *)"dlfcn unsupported on Horizon"; }
int   dladdr(const void *addr, Dl_info *info) { (void)addr; if (info) memset(info, 0, sizeof(*info)); return 0; }
int   dlinfo(void *h, int request, void *info) { (void)h; (void)request; (void)info; return -1; }

// box64's --test self-test harness (test.c) is excluded from the Switch build; stub its entry so
// core.c still links (it's only reached in --test mode, which Horizon never enters).
int unittest(int argc, const char **argv) { (void)argc; (void)argv; return 0; }

// --- GNU libm extensions newlib lacks (declared in shim/static_compat.h) ----------------------
#include <math.h>
void sincos(double x, double *s, double *c)  { *s = sin(x);  *c = cos(x);  }
void sincosf(float x, float *s, float *c)    { *s = sinf(x); *c = cosf(x); }
double      exp10(double x)      { return pow(10.0, x); }
float       exp10f(float x)      { return powf(10.0f, x); }
long double exp10l(long double x){ return powl(10.0L, x); }
double      pow10(double x)      { return pow(10.0, x); }
float       pow10f(float x)      { return powf(10.0f, x); }
long double pow10l(long double x){ return powl(10.0L, x); }

// --- Linux syscall functions newlib lacks ----------------------------------------------------
// Reached only via box64's guest x86-64 syscall table for fd-multiplexing / eventing syscalls,
// which a static single-threaded guest never invokes. Stubbed to -ENOSYS so box64 links and so a
// guest that probes them gets a clean error rather than a crash. Fleshed out as guests demand.
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/utsname.h>
#include <sys/signalfd.h>
#include <sys/eventfd.h>
#include <sys/epoll.h>

// poll() and ioctl() are provided by libnx (BSD sockets); we only declare them.
int signalfd(int fd, const sigset_t *mask, int flags) { (void)fd;(void)mask;(void)flags; errno=ENOSYS; return -1; }
int eventfd(unsigned int initval, int flags) { (void)initval;(void)flags; errno=ENOSYS; return -1; }
int eventfd_read(int fd, eventfd_t *value) { (void)fd;(void)value; errno=ENOSYS; return -1; }
int eventfd_write(int fd, eventfd_t value) { (void)fd;(void)value; errno=ENOSYS; return -1; }
int epoll_create(int size) { (void)size; errno=ENOSYS; return -1; }
int epoll_create1(int flags) { (void)flags; errno=ENOSYS; return -1; }
int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event) { (void)epfd;(void)op;(void)fd;(void)event; errno=ENOSYS; return -1; }
int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout) { (void)epfd;(void)events;(void)maxevents;(void)timeout; errno=ENOSYS; return -1; }
int epoll_pwait(int epfd, struct epoll_event *events, int maxevents, int timeout, const sigset_t *sigmask) { (void)epfd;(void)events;(void)maxevents;(void)timeout;(void)sigmask; errno=ENOSYS; return -1; }

// --- BSD err/warn family (err.h) --------------------------------------------------------------
#include <err.h>
#include <stdarg.h>
void vwarnx(const char *fmt, va_list ap) {
    fputs("box64: ", stderr);
    if (fmt) vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
}
void vwarn(const char *fmt, va_list ap) {
    int e = errno;
    fputs("box64: ", stderr);
    if (fmt) { vfprintf(stderr, fmt, ap); fputs(": ", stderr); }
    fprintf(stderr, "%s\n", strerror(e));
}
void verrx(int eval, const char *fmt, va_list ap) { vwarnx(fmt, ap); exit(eval); }
void verr(int eval, const char *fmt, va_list ap) { vwarn(fmt, ap); exit(eval); }
void warnx(const char *fmt, ...) { va_list ap; va_start(ap, fmt); vwarnx(fmt, ap); va_end(ap); }
void warn(const char *fmt, ...)  { va_list ap; va_start(ap, fmt); vwarn(fmt, ap); va_end(ap); }
void errx(int eval, const char *fmt, ...) { va_list ap; va_start(ap, fmt); verrx(eval, fmt, ap); va_end(ap); }
void err(int eval, const char *fmt, ...)  { va_list ap; va_start(ap, fmt); verr(eval, fmt, ap); va_end(ap); }

// GNU backtrace (execinfo.h) — no host unwinder on Horizon.
int    backtrace(void **buffer, int size) { (void)buffer; (void)size; return 0; }
char **backtrace_symbols(void *const *buffer, int size) { (void)buffer; (void)size; return NULL; }
void   backtrace_symbols_fd(void *const *buffer, int size, int fd) { (void)buffer; (void)size; (void)fd; }

// --- statfs / process_vm / ptrace / syslog / error (wrappedlibc forwards to these) ------------
#include <sys/vfs.h>
#include <sys/uio.h>
#include <sys/ptrace.h>
#include <syslog.h>
#include <error.h>
#include <stdio.h>

char *program_invocation_name = (char *)"box64";
char *program_invocation_short_name = (char *)"box64";

int statfs(const char *path, struct statfs *buf) { (void)path; if (buf) memset(buf, 0, sizeof(*buf)); errno = ENOSYS; return -1; }
int fstatfs(int fd, struct statfs *buf) { (void)fd; if (buf) memset(buf, 0, sizeof(*buf)); errno = ENOSYS; return -1; }
ssize_t process_vm_readv(int pid, const struct iovec *l, unsigned long lc, const struct iovec *r, unsigned long rc, unsigned long f) { (void)pid;(void)l;(void)lc;(void)r;(void)rc;(void)f; errno = ENOSYS; return -1; }
ssize_t process_vm_writev(int pid, const struct iovec *l, unsigned long lc, const struct iovec *r, unsigned long rc, unsigned long f) { (void)pid;(void)l;(void)lc;(void)r;(void)rc;(void)f; errno = ENOSYS; return -1; }
long ptrace(int request, ...) { (void)request; errno = ENOSYS; return -1; }

void openlog(const char *ident, int option, int facility) { (void)ident; (void)option; (void)facility; }
void closelog(void) {}
int  setlogmask(int mask) { (void)mask; return 0; }
void vsyslog(int priority, const char *format, va_list ap) { (void)priority; if (format) vfprintf(stderr, format, ap); }
void syslog(int priority, const char *format, ...) { va_list ap; va_start(ap, format); vsyslog(priority, format, ap); va_end(ap); }

void error(int status, int errnum, const char *format, ...) {
    va_list ap; va_start(ap, format);
    fputs("box64: ", stderr);
    if (format) vfprintf(stderr, format, ap);
    va_end(ap);
    if (errnum) fprintf(stderr, ": %s", strerror(errnum));
    fputc('\n', stderr);
    if (status) exit(status);
}
void error_at_line(int status, int errnum, const char *filename, unsigned int linenum, const char *format, ...) {
    va_list ap; va_start(ap, format);
    fprintf(stderr, "box64:%s:%u: ", filename ? filename : "?", linenum);
    if (format) vfprintf(stderr, format, ap);
    va_end(ap);
    if (errnum) fprintf(stderr, ": %s", strerror(errnum));
    fputc('\n', stderr);
    if (status) exit(status);
}

// --- glibc large-file (*64) wrappers (declared in shim/largefile64.h) -------------------------
#include <largefile64.h>
#include <stdarg.h>
#include <ctype.h>
int stat64(const char *p, struct stat64 *b)  { return stat(p, (struct stat *)b); }
int fstat64(int fd, struct stat64 *b)         { return fstat(fd, (struct stat *)b); }
int lstat64(const char *p, struct stat64 *b)  { return lstat(p, (struct stat *)b); }
// M2.1: real fstatat (was an -ENOSYS link stub). The guest's ld.so stats libc via
// newfstatat(fd, "", &st, AT_EMPTY_PATH) — box64's my_fstatat forwards here. Handle the fd form
// (AT_EMPTY_PATH / empty path) via fstat; translate a path form to the staged SD lib dir by basename.
#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH 0x1000
#endif
// M2.7: should this fd's stat report a REGULAR FILE (S_IFREG)? True for std out/err (0/1/2) AND their
// SCM_RIGHTS-passed dups — the in-process wineserver fstat's the dup of client fd 1 to classify the fd
// type (server/file.c file_get_fd_type). A regular file -> Wine picks FD_TYPE_FILE -> NtWriteFile does
// a SYNCHRONOUS in-process write() (no server round-trip, no async, no APC). A char/fifo -> FD_TYPE_CHAR
// -> async write -> an alertable SELECT_NONE APC wait that never completes on fork/exec-less Horizon
// (no conhost, no async-I/O loop) — THE `cmd /c echo` hang. Key on the tee origin, not the fd number:
// the wineserver's copy of fd 1 is a high-numbered dup with nx_tee_origin()==1 (shared g_tee[]).
int nx_stdfd_regularize(int fd, unsigned mode) {
    extern int nx_tee_origin(int fd);
    extern int nx_guest_pid(void);
    if (fd < 0) return 0;
    int tee = nx_tee_origin(fd);
    int is = (fd <= 2 || tee);
    // DIAG (KX_STATLOG): log std/tee fds AND any raw char-device/fifo fstat (the libnx console + the
    // dups the wineserver fstat's for the passed std handle) so we can see how fd 1 gets classified.
    // Skip the S_IFREG library flood. `mode` is the RAW st_mode BEFORE this override.
    static int on = -1; if (on < 0) on = getenv("KX_STATLOG") ? 1 : 0;
    if (on && (is || (mode & S_IFMT) == S_IFCHR || (mode & S_IFMT) == S_IFIFO)) {
        char b[128]; int n = snprintf(b, sizeof b, "nx_stat: pid=%d fd=%d tee=%d rawmode=0%o is=%d\n",
                                      nx_guest_pid(), fd, tee, (unsigned)(mode & S_IFMT), is);
        svcOutputDebugString(b, (size_t)n);
    }
    return is;
}
int fstatat(int dirfd, const char *path, struct stat *b, int flags) {
    int r;
    extern int nx_vfd_is(int fd);
    extern int nx_vfd_stat(int fd, struct stat* st);
    extern const char* nx_vfd_dir_guest(int fd);
    char hp[512]; int have_hp = 0;
    if ((flags & AT_EMPTY_PATH) || !path || !path[0]) {
        r = nx_vfd_is(dirfd) ? nx_vfd_stat(dirfd, b)     // M2.5: dir/socket vfds
                             : fstat(dirfd, b);          // fstat via the open fd
        // std out/err (+ their SCM_RIGHTS-passed dups, which the in-process wineserver fstat's for the
        // passed std handle) -> a valid REGULAR-FILE stat. TWO reasons: (1) the libnx console fd's fstat
        // FAILS with ENOSYS, which fails Wine's create_file_for_fd() (server/file.c) -> NULL hStdOutput
        // -> cmd.exe's `echo` is written to a dead handle and LOST; synthesizing success makes the std
        // handle exist so WCMD's WriteFile fallback reaches fd 1 (the tee). (2) FD_TYPE_FILE makes
        // NtWriteFile a synchronous in-process write() (no async/APC). ino is set nonzero below.
        if (nx_stdfd_regularize(dirfd, r == 0 ? b->st_mode : 0)) {
            if (r != 0) { memset(b, 0, sizeof *b); b->st_nlink = 1; r = 0; }
            b->st_mode = (b->st_mode & ~S_IFMT) | S_IFREG | 0600;
        }
        if (r != 0 && !nx_vfd_is(dirfd)) {
            // A real fd newlib can't fstat (a special/char/pipe fd the in-process wineserver passes to
            // create_file_for_fd -> fstat -> file_set_error, which can't map ENOSYS -> STATUS_UNSUCCESSFUL
            // aborts the mapping op: the "file_set_error() can't map error" message). Synthesize a valid
            // regular-file stat so the op proceeds (a non-zero ino is stamped below).
            int se = errno;
            static int on = -1; if (on < 0) on = getenv("KX_STATLOG") ? 1 : 0;
            if (on) { char bb[96]; int nn = snprintf(bb, sizeof bb, "nx_stat: SYNTH fd=%d fstat_errno=%d\n", dirfd, se);
                      svcOutputDebugString(bb, (size_t)nn); }
            memset(b, 0, sizeof *b); b->st_mode = S_IFREG | 0600; b->st_nlink = 1; r = 0;
        }
    } else {
        char gp[512];                                    // M2.5: relative to a dir vfd
        if (path[0] != '/' && nx_vfd_is(dirfd) && nx_vfd_dir_guest(dirfd)) {
            snprintf(gp, sizeof gp, "%s/%s", nx_vfd_dir_guest(dirfd), path);
            path = gp;
        }
        // M2.5: the wineserver `socket` (a bound vfd) and lock/tmpmap (shared objects) have no fsdev
        // file, but Wine stat()s the socket before connecting — return a synthetic S_IFSOCK/regular
        // stat so it doesn't see ENOENT and give up ("cannot connect").
        { extern int nx_vfd_path_stat(const char* guestpath, struct stat* st);
          if (nx_vfd_path_stat(path, b) == 0) return 0; }
        if (nx_translate_path(path, hp, sizeof hp) != 0) { errno = ENOENT; return -1; }
        have_hp = 1;
        r = stat(hp, b);
    }
    // Every stat MUST return a non-zero st_ino: ld.so dedups loaded objects by (dev,ino), so a zero
    // ino makes libc/ntdll/... all look like the SAME already-loaded object and ld.so drops them
    // (ntdll's __wine_main then vanishes — this was THE cmd.exe bring-up bug). Two cases:
    //  - PATH stat (have_hp): FNV-1a of the CANONICAL host path — deterministic AND stable across guest
    //    instances, so wineserver's stat(server_dir) == its later stat(".") and the client + wineserver
    //    derive the SAME `server-<dev>-<ino>` socket name (M2.5).
    //  - FD stat (fstat / AT_EMPTY_PATH — no path available): a unique non-zero counter. ld.so dedups
    //    the fd form by soname anyway, so it need not match the path form; it just must be != 0.
    //    (Pre-M2.5 used the counter for BOTH branches; gating it on have_hp left fd stats at ino 0.)
    if (r == 0) {
        b->st_dev = 1;
        if (!b->st_ino) {
            if (have_hp) {
                unsigned long h = 1469598103934665603UL;     // FNV-1a 64 of the host path
                for (const char* c = hp; *c; ++c) { h ^= (unsigned char)*c; h *= 1099511628211UL; }
                b->st_ino = h ? h : 1;
            } else {
                static unsigned long g_fdino = 2;
                b->st_ino = __atomic_add_fetch(&g_fdino, 1, __ATOMIC_RELAXED);
            }
        }
        // Everything runs as root (uid/gid 0). Clear group/other perm bits so Wine's wineserver
        // security check passes: it fatals unless its runtime dir (/run/user/0/wine) is owned by
        // getuid() with (st_mode & 077)==0. fsdev reports 0777 for everything, so strip 077.
        b->st_uid = 0; b->st_gid = 0; b->st_mode &= ~(mode_t)077;
    }
    return r;
}
int fstatat64(int d, const char *p, struct stat64 *b, int f) { return fstatat(d, p, (struct stat *)b, f); }
int open64(const char *p, int fl, ...) { va_list a; va_start(a, fl); mode_t m = (mode_t)va_arg(a, int); va_end(a); return open(p, fl, m); }
int openat64(int d, const char *p, int fl, ...) { va_list a; va_start(a, fl); mode_t m = (mode_t)va_arg(a, int); va_end(a); return openat(d, p, fl, m); }
int creat64(const char *p, mode_t m) { return creat(p, m); }
FILE *fopen64(const char *p, const char *m) { return fopen(p, m); }
FILE *freopen64(const char *p, const char *m, FILE *s) { return freopen(p, m, s); }
FILE *tmpfile64(void) { return tmpfile(); }
int mknod(const char *p, mode_t m, dev_t d) { (void)p;(void)m;(void)d; errno = ENOSYS; return -1; }
// Directory/glob/tree *64 variants — stubbed (a static guest never enumerates host dirs).
struct dirent64 *readdir64(DIR *d) { (void)d; return NULL; }
int scandir64(const char *d, struct dirent64 ***n, int (*f)(const struct dirent64 *), int (*c)(const struct dirent64 **, const struct dirent64 **)) { (void)d;(void)n;(void)f;(void)c; errno = ENOSYS; return -1; }
int scandirat64(int fd, const char *d, struct dirent64 ***n, int (*f)(const struct dirent64 *), int (*c)(const struct dirent64 **, const struct dirent64 **)) { (void)fd;(void)d;(void)n;(void)f;(void)c; errno = ENOSYS; return -1; }
int glob64(const char *pat, int fl, int (*ef)(const char *, int), glob64_t *pg) { return glob(pat, fl, ef, pg); }
void globfree64(glob64_t *pg) { globfree(pg); }
int ftw64(const char *d, int (*fn)(const char *, const struct stat64 *, int), int n) { (void)d;(void)fn;(void)n; errno = ENOSYS; return -1; }
int nftw64(const char *d, int (*fn)(const char *, const struct stat64 *, int, struct FTW *), int n, int fl) { (void)d;(void)fn;(void)n;(void)fl; errno = ENOSYS; return -1; }

// glibc ctype accessors over newlib's tables. Approximate: return pointers into a static
// table built from newlib's ctype macros (offset by 128 for EOF, as glibc does).
const unsigned short **__ctype_b_loc(void) {
    static unsigned short tbl[384];
    static const unsigned short *p;
    if (!p) {
        for (int i = -128; i < 256; i++) {
            unsigned short f = 0; int c = i & 0xff;
            if (i >= 0) {
                if (isupper(c)) f |= 0x0100; if (islower(c)) f |= 0x0200;
                if (isalpha(c)) f |= 0x0400; if (isdigit(c)) f |= 0x0800;
                if (isxdigit(c)) f |= 0x1000; if (isspace(c)) f |= 0x2000;
                if (isprint(c)) f |= 0x4000; if (isgraph(c)) f |= 0x8000;
                if (isblank(c)) f |= 0x0001; if (iscntrl(c)) f |= 0x0002;
                if (ispunct(c)) f |= 0x0004; if (isalnum(c)) f |= 0x0008;
            }
            tbl[i + 128] = f;
        }
        p = &tbl[128];
    }
    return &p;
}
const int **__ctype_toupper_loc(void) {
    static int tbl[384];
    static const int *p;
    if (!p) { for (int i = -128; i < 256; i++) tbl[i + 128] = (i >= 0) ? toupper(i & 0xff) : (i & 0xff); p = &tbl[128]; }
    return &p;
}
const int **__ctype_tolower_loc(void) {
    static int tbl[384];
    static const int *p;
    if (!p) { for (int i = -128; i < 256; i++) tbl[i + 128] = (i >= 0) ? tolower(i & 0xff) : (i & 0xff); p = &tbl[128]; }
    return &p;
}

// --- linear search (search.h omits these on newlib) -------------------------------------------
void *lfind(const void *key, const void *base, size_t *nelp, size_t width, int (*cmp)(const void *, const void *)) {
    const char *p = (const char *)base;
    for (size_t i = 0; i < *nelp; i++, p += width)
        if (cmp(key, p) == 0) return (void *)p;
    return NULL;
}
void *lsearch(const void *key, void *base, size_t *nelp, size_t width, int (*cmp)(const void *, const void *)) {
    void *r = lfind(key, base, nelp, width, cmp);
    if (r) return r;
    char *dst = (char *)base + (*nelp) * width;   // append
    memcpy(dst, key, width);
    (*nelp)++;
    return dst;
}

// --- fts (filesystem-tree walk) — unsupported on Horizon; box64 only forwards these -----------
#include <fts.h>
FTS    *fts_open(char *const *p, int o, int (*c)(const FTSENT **, const FTSENT **)) { (void)p;(void)o;(void)c; errno = ENOSYS; return NULL; }
FTSENT *fts_read(FTS *f) { (void)f; return NULL; }
FTSENT *fts_children(FTS *f, int o) { (void)f;(void)o; return NULL; }
int     fts_set(FTS *f, FTSENT *e, int o) { (void)f;(void)e;(void)o; return 0; }
int     fts_close(FTS *f) { (void)f; return 0; }

// --- rlimit / SysV sem / libc-version (wrappedlibc forwards to these) --------------------------
#include <sys/sem.h>
#include <gnu/libc-version.h>
int getrlimit(int r, struct rlimit *l) { (void)r; if (l) { l->rlim_cur = RLIM_INFINITY; l->rlim_max = RLIM_INFINITY; } return 0; }
int setrlimit(int r, const struct rlimit *l) { (void)r; (void)l; return 0; }
int prlimit(pid_t p, int r, const struct rlimit *nl, struct rlimit *ol) { (void)p;(void)r;(void)nl; if (ol) { ol->rlim_cur = RLIM_INFINITY; ol->rlim_max = RLIM_INFINITY; } return 0; }
int semget(key_t k, int n, int f) { (void)k;(void)n;(void)f; errno = ENOSYS; return -1; }
int semop(int id, struct sembuf *s, size_t n) { (void)id;(void)s;(void)n; errno = ENOSYS; return -1; }
int semctl(int id, int num, int cmd, ...) { (void)id;(void)num;(void)cmd; errno = ENOSYS; return -1; }
int semtimedop(int id, struct sembuf *s, size_t n, const struct timespec *t) { (void)id;(void)s;(void)n;(void)t; errno = ENOSYS; return -1; }
const char *gnu_get_libc_version(void) { return "2.39"; }      // box64 presents a glibc identity
const char *gnu_get_libc_release(void) { return "stable"; }

// pty (pty.h) — no PTYs on Horizon.
int openpty(int *am, int *as, char *n, const struct termios *t, const struct winsize *w) { (void)am;(void)as;(void)n;(void)t;(void)w; errno = ENOSYS; return -1; }
int forkpty(int *am, char *n, const struct termios *t, const struct winsize *w) { (void)am;(void)n;(void)t;(void)w; errno = ENOSYS; return -1; }

// libutil login records (utmp.h) — no utmp database on Horizon.
#include <sys/utmp.h>
void login(const struct utmp *ut) { (void)ut; }
int  logout(const char *line) { (void)line; return 0; }
void logwtmp(const char *line, const char *name, const char *host) { (void)line; (void)name; (void)host; }

// readlink/readlinkat — newlib returns -ENOSYS, which makes glibc realpath() and Wine's path
// resolution HARD-FAIL ("cannot get path to ntdll.so"). box64's my_readlink handles /proc/self/exe
// before reaching us; for everything else, a rootfs entry is not a symlink, so report EINVAL — the
// POSIX "not a symbolic link" errno, which realpath()/Wine treat as "use the path verbatim". Also
// answer /proc/self/exe with the Wine loader path (in case box64's isProcSelf didn't match the form).
static ssize_t nx_readlink_common(const char* path, char* buf, size_t bufsz) {
    if (!path || !buf) { errno = EFAULT; return -1; }
    if (!strcmp(path, "/proc/self/exe") || !strcmp(path, "/proc/curproc/file")) {
        const char* exe = "/usr/lib/wine/wine64";     // a plausible loader path for Wine's bindir logic
        size_t n = strlen(exe); if (n > bufsz) n = bufsz;
        memcpy(buf, exe, n);
        return (ssize_t)n;
    }
    // M2.5: Wine maps DOS drives by readlink()ing $WINEPREFIX/dosdevices/<x>: to a unix path. fsdev has
    // no symlinks, so synthesize the standard targets — Z: -> / (unix root) and C: -> the prefix drive_c
    // — so `cmd /c ... > C:\file` / `Z:\file` resolves and Wine's file I/O reaches fsdev (bypassing the
    // Wine console entirely, which needs a console host we can't spawn).
    { const char* d = strstr(path, "/dosdevices/");
      if (d) { d += 12; const char* tgt = NULL;
        if ((d[0]=='z'||d[0]=='Z') && d[1]==':' && !d[2]) tgt = "/";
        else if ((d[0]=='c'||d[0]=='C') && d[1]==':' && !d[2]) tgt = "../drive_c";
        if (tgt) { size_t n = strlen(tgt); if (n > bufsz) n = bufsz; memcpy(buf, tgt, n); return (ssize_t)n; }
      }
    }
    errno = EINVAL;                                    // not a symlink -> caller uses the path as-is
    return -1;
}
ssize_t readlink(const char* path, char* buf, size_t bufsz) { return nx_readlink_common(path, buf, bufsz); }
ssize_t readlinkat(int dirfd, const char* path, char* buf, size_t bufsz) { (void)dirfd; return nx_readlink_common(path, buf, bufsz); }

// sysconf/getpagesize — newlib's return -ENOSYS via our stubs, but box64 needs a real page
// size (box64_pagesize = sysconf(_SC_PAGESIZE); a -1 poisons all its alignment/mmap math).
#include <unistd.h>
long sysconf(int name) {
    switch (name) {
        case _SC_PAGESIZE:          return 4096;
        case _SC_NPROCESSORS_CONF:
        case _SC_NPROCESSORS_ONLN: {
            u64 mask = 0;                                       // real core count from the process mask
            if (R_SUCCEEDED(svcGetInfo(&mask, InfoType_CoreMask, CUR_PROCESS_HANDLE, 0)) && mask)
                return (long)__builtin_popcountll(mask);
            return 3;
        }
        case _SC_CLK_TCK:           return 100;
        case _SC_OPEN_MAX:          return 1024;
        case _SC_PHYS_PAGES: {
            u64 total = 0;                                      // real per-process memory budget
            if (R_SUCCEEDED(svcGetInfo(&total, InfoType_TotalMemorySize, CUR_PROCESS_HANDLE, 0)) && total)
                return (long)(total / 4096);
            return (long)((256UL * 1024 * 1024) / 4096);
        }
        case _SC_AVPHYS_PAGES: {
            u64 total = 0, used = 0;
            if (R_SUCCEEDED(svcGetInfo(&total, InfoType_TotalMemorySize, CUR_PROCESS_HANDLE, 0)) &&
                R_SUCCEEDED(svcGetInfo(&used,  InfoType_UsedMemorySize,  CUR_PROCESS_HANDLE, 0)) && total >= used)
                return (long)((total - used) / 4096);
            return (long)((128UL * 1024 * 1024) / 4096);
        }
        default:                    errno = EINVAL; return -1;
    }
}
int getpagesize(void) { return 4096; }

// futex(uaddr, op, val, timeout, uaddr2, val3) over the Horizon address arbiter (svcWaitForAddress /
// svcSignalToAddress — the kernel's futex). glibc low-level locks use WAIT/WAKE; the 2.25+ condvar uses
// WAIT_BITSET (absolute timeout, match-any) + WAKE, no requeue — so this op set is complete. PI and
// requeue ops -> ENOSYS (glibc falls back / doesn't need them for the M2.2 gate).
#ifndef FUTEX_WAIT
#define FUTEX_WAIT            0
#define FUTEX_WAKE            1
#define FUTEX_WAIT_BITSET     9
#define FUTEX_WAKE_BITSET     10
#define FUTEX_PRIVATE_FLAG    128
#define FUTEX_CLOCK_REALTIME  256
#endif
#define FUTEX_CMD_MASK (~(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME))

static long nx_futex(int* uaddr, int op, unsigned val, const void* timeout,
                     int* uaddr2, unsigned val3) {
    (void)uaddr2; (void)val3;
    struct nx_ts { long tv_sec, tv_nsec; };                       // x86-64 kernel timespec (both 64-bit)
    if (((uintptr_t)uaddr) & 3u) { errno = EINVAL; return -1; }   // kernel requires a 4-byte-aligned addr
    int cmd = op & FUTEX_CMD_MASK;
    switch (cmd) {
        case FUTEX_WAIT:
        case FUTEX_WAIT_BITSET: {
            s64 timeout_ns = -1;                                  // NULL timeout -> wait forever
            if (timeout) {
                const struct nx_ts* to = (const struct nx_ts*)timeout;
                if (cmd == FUTEX_WAIT) {                          // relative
                    timeout_ns = (s64)to->tv_sec * 1000000000LL + to->tv_nsec;
                } else {                                          // WAIT_BITSET: absolute -> relative
                    u64 now = armTicksToNs(armGetSystemTick());   // CLOCK_MONOTONIC epoch
                    s64 abs = (s64)to->tv_sec * 1000000000LL + to->tv_nsec;
                    timeout_ns = abs - (s64)now;
                    if (timeout_ns < 0) timeout_ns = 0;
                }
            }
            { static int on = -1; if (on < 0) on = getenv("KX_REQLOG") ? 1 : 0;
              if (on) { char b[112]; extern int nx_guest_pid(void); int n = snprintf(b, sizeof b,
                  "nx: FUTEXW pid=%d uaddr=%p val=%u *u=%d to=%lld\n", nx_guest_pid(), (void*)uaddr,
                  val, uaddr ? *(volatile int*)uaddr : 0, (long long)timeout_ns); svcOutputDebugString(b, n); } }
            Result rc = svcWaitForAddress(uaddr, ArbitrationType_WaitIfEqual, (s64)(s32)val, timeout_ns);
            if (R_SUCCEEDED(rc)) return 0;
            switch (R_DESCRIPTION(rc)) {
                case 117: errno = ETIMEDOUT; return -1;           // KernelError_TimedOut
                case 118: errno = EINTR;     return -1;           // KernelError_Cancelled
                default:  errno = EAGAIN;    return -1;           // 125 InvalidState = *uaddr != val
            }
        }
        case FUTEX_WAKE:
        case FUTEX_WAKE_BITSET: {
            s32 count = (val > (unsigned)INT_MAX) ? INT_MAX : (s32)val;
            svcSignalToAddress(uaddr, SignalType_Signal, 0, count);
            return 0;                                             // NPTL ignores the woken count
        }
        default:
            nx_warnf("nx: futex op=%d (cmd=%d) unimplemented -> ENOSYS\n", op, cmd);
            errno = ENOSYS; return -1;
    }
}

// --- M2.3: host (newlib) errno -> Linux errno ---------------------------------------------------
// box64 upstream runs ON Linux, where host errno == guest errno, so every syscall site returns
// S_RAX = -errno verbatim. On Horizon the host C library is newlib, whose errno numbers diverge from
// Linux above ~34 (newlib ETIMEDOUT=116 vs Linux 110, ENOSYS=88 vs 38, ENAMETOOLONG=91 vs 36, ...).
// The guest's real glibc reads the negative RAX as a *Linux* errno, so an untranslated -errno becomes
// a wrong error (a condvar timeout would surface as ~EDQUOT instead of ETIMEDOUT; clone3's ENOSYS
// fallback already had to be special-cased for exactly this reason). x64Syscall_linux() calls this at
// its return seam. The table holds only the entries where newlib != Linux (1-34 are identical and hit
// the identity fallback); it was generated by joining <errno.h> against the asm-generic Linux values.
int nx_errno_h2l(int e) {
    // { newlib_host, linux_guest }. Numeric (not macro) because newlib gates the extended errnos behind
    // __LINUX_ERRNO_EXTENSIONS__; the host column is newlib's <sys/errno.h> value, the guest column the
    // asm-generic Linux value. Generated by joining the two tables; only the divergent entries appear.
    static const struct { short host, lin; } tbl[] = {
        {  35, 42 },  // ENOMSG
        {  36, 43 },  // EIDRM
        {  37, 44 },  // ECHRNG
        {  38, 45 },  // EL2NSYNC
        {  39, 46 },  // EL3HLT
        {  40, 47 },  // EL3RST
        {  41, 48 },  // ELNRNG
        {  42, 49 },  // EUNATCH
        {  43, 50 },  // ENOCSI
        {  44, 51 },  // EL2HLT
        {  45, 35 },  // EDEADLK
        {  46, 37 },  // ENOLCK
        {  50, 52 },  // EBADE
        {  51, 53 },  // EBADR
        {  52, 54 },  // EXFULL
        {  53, 55 },  // ENOANO
        {  54, 56 },  // EBADRQC
        {  55, 57 },  // EBADSLT
        {  56, 35 },  // EDEADLOCK
        {  57, 59 },  // EBFONT
        {  74, 72 },  // EMULTIHOP
        {  76, 73 },  // EDOTDOT
        {  77, 74 },  // EBADMSG
        {  80, 76 },  // ENOTUNIQ
        {  81, 77 },  // EBADFD
        {  82, 78 },  // EREMCHG
        {  83, 79 },  // ELIBACC
        {  84, 80 },  // ELIBBAD
        {  85, 81 },  // ELIBSCN
        {  86, 82 },  // ELIBMAX
        {  87, 83 },  // ELIBEXEC
        {  88, 38 },  // ENOSYS
        {  90, 39 },  // ENOTEMPTY
        {  91, 36 },  // ENAMETOOLONG
        {  92, 40 },  // ELOOP
        { 106, 97 },  // EAFNOSUPPORT
        { 107, 91 },  // EPROTOTYPE
        { 108, 88 },  // ENOTSOCK
        { 109, 92 },  // ENOPROTOOPT
        { 110,108 },  // ESHUTDOWN
        { 112, 98 },  // EADDRINUSE
        { 113,103 },  // ECONNABORTED
        { 114,101 },  // ENETUNREACH
        { 115,100 },  // ENETDOWN
        { 116,110 },  // ETIMEDOUT
        { 117,112 },  // EHOSTDOWN
        { 118,113 },  // EHOSTUNREACH
        { 119,115 },  // EINPROGRESS
        { 120,114 },  // EALREADY
        { 121, 89 },  // EDESTADDRREQ
        { 122, 90 },  // EMSGSIZE
        { 123, 93 },  // EPROTONOSUPPORT
        { 124, 94 },  // ESOCKTNOSUPPORT
        { 125, 99 },  // EADDRNOTAVAIL
        { 126,102 },  // ENETRESET
        { 127,106 },  // EISCONN
        { 128,107 },  // ENOTCONN
        { 129,109 },  // ETOOMANYREFS
        { 131, 87 },  // EUSERS
        { 132,122 },  // EDQUOT
        { 133,116 },  // ESTALE
        { 134, 95 },  // ENOTSUP
        { 135,123 },  // ENOMEDIUM
        { 138, 84 },  // EILSEQ
        { 139, 75 },  // EOVERFLOW
        { 140,125 },  // ECANCELED
        { 141,131 },  // ENOTRECOVERABLE
        { 142,130 },  // EOWNERDEAD
        { 143, 86 },  // ESTRPIPE
    };
    if (e <= 0) return e;                                       // 0 / sentinels pass through unchanged
    for (unsigned i = 0; i < sizeof(tbl) / sizeof(tbl[0]); ++i)
        if (tbl[i].host == e) return tbl[i].lin;
    return e;                                                   // names identical to Linux (or unknown)
}

// --- M2.4: rootfs path translation + synthetic /proc,/dev pseudo-files -------------------------
// The guest (real ld.so/glibc, and later Wine) issues Linux absolute paths (/lib/..., /usr/..., the
// WINEPREFIX, /proc, /dev). None exist on Horizon. Root the guest FS at sdmc:/box64/rootfs/ and
// materialize a few pseudo-files to a temp file so the ordinary open/read/lseek path serves them.
// A flat sdmc:/box64/lib/<basename> fallback keeps the M2.1/M2.2 tests (which stage libc.so.6 there)
// working. Every file syscall (openat/stat/...) funnels through nx_translate_path for one policy.
#include <sys/stat.h>   // mkdir

#define NX_ROOTFS "sdmc:/box64/rootfs"
#define NX_LIBDIR "sdmc:/box64/lib"
#define NX_TMPDIR "sdmc:/box64/tmp"

// Linux open() flags (guest) -> newlib/host <fcntl.h> flags. Low 2 bits (RD/WR/RDWR) match; the rest
// differ (Linux O_CREAT=0100, newlib O_CREAT=0x200, etc.). Left = Linux octal, right = host macro.
int nx_oflags_l2h(int lf) {
    int hf = lf & 3;
    if (lf & 000100) hf |= O_CREAT;
    if (lf & 000200) hf |= O_EXCL;
    if (lf & 000400) hf |= O_NOCTTY;
    if (lf & 001000) hf |= O_TRUNC;
    if (lf & 002000) hf |= O_APPEND;
    if (lf & 004000) hf |= O_NONBLOCK;
#ifdef O_DIRECTORY
    if (lf & 0200000) hf |= O_DIRECTORY;
#endif
#ifdef O_CLOEXEC
    if (lf & 02000000) hf |= O_CLOEXEC;
#endif
    return hf;
}

// Write a pseudo-file's bytes to sdmc:/box64/tmp/<slug> and return that path, so a real seekable SD
// file backs /proc + /dev entries (the plain open/read/lseek path then serves them unchanged).
static int nx_materialize(const char* slug, const void* content, size_t len, char* out, size_t outn) {
    mkdir(NX_TMPDIR, 0777);                                       // no-op if it already exists
    snprintf(out, outn, "%s/%s", NX_TMPDIR, slug);
    int fd = open(out, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return -1;
    const char* c = (const char*)content; size_t w = 0;
    while (w < len) { ssize_t r = write(fd, c + w, len - w); if (r <= 0) break; w += (size_t)r; }
    close(fd);
    return (w == len) ? 0 : -1;
}

static const char kx_cpuinfo[] =
    "processor\t: 0\nvendor_id\t: GenuineIntel\ncpu family\t: 6\nmodel\t\t: 60\n"
    "model name\t: box64-nx on Tegra X1 (Cortex-A57)\nstepping\t: 3\ncpu MHz\t\t: 1020.000\n"
    "cache size\t: 256 KB\nphysical id\t: 0\nsiblings\t: 3\ncore id\t\t: 0\ncpu cores\t: 3\n"
    "flags\t\t: fpu vme de pse tsc msr pae cx8 apic sep mtrr pge cmov pat pse36 clflush mmx fxsr "
    "sse sse2 ht syscall nx lm constant_tsc rep_good nopl cpuid pni ssse3 cx16 sse4_1 sse4_2 "
    "popcnt aes xsave avx\nbogomips\t: 2040.00\n\n";

// Normalize a guest path: resolve a relative path against the guest CWD (nx_cwd, set by
// chdir/fchdir) and collapse "." / ".." / duplicate slashes, so "sdmc:..." never sees them
// (fsdev chokes on "/dir/." forms). Output is an absolute guest path.
char* nx_cwd_buf(void);        // per-instance cwd accessor (defined below)
int   nx_guest_pid(void);      // per-instance guest pid (defined below)
static void nx_normalize_guest(const char* p, char* out, size_t outn) {
    char joined[1024];
    const char* cwd = nx_cwd_buf();
    if (p[0] == '/') snprintf(joined, sizeof joined, "%s", p);
    else snprintf(joined, sizeof joined, "%s/%s", (cwd[0] == '/') ? cwd : "/", p);
    // segment-wise collapse
    char* segs[64]; int n = 0;
    char work[1024]; snprintf(work, sizeof work, "%s", joined);
    for (char* t = strtok(work, "/"); t; t = strtok(NULL, "/")) {
        if (!strcmp(t, ".") || !t[0]) continue;
        if (!strcmp(t, "..")) { if (n) n--; continue; }
        if (n < 64) segs[n++] = t;
    }
    size_t o = 0;
    for (int i = 0; i < n && o + 1 < outn; i++) {
        int w = snprintf(out + o, outn - o, "/%s", segs[i]);
        if (w < 0) break; o += (size_t)w;
    }
    if (!n) snprintf(out, outn, "/");
    // Wine DOS-drive symlinks: fsdev/NTFS cannot hold a "c:"-named file, so the dosdevices/<x>:
    // links exist only synthetically (readlink/getdents). A path THROUGH the link component
    // (".../.wine/dosdevices/c:/windows/...") must be resolved here, in normalization, or every
    // \??\C:\ lookup fails EINVAL on the colon: z: -> "/", <x>: -> "<prefix>/drive_<x>".
    char* dd = strstr(out, "/dosdevices/");
    if (dd) {
        char l = dd[12];
        if (l >= 'a' && l <= 'z' && dd[13] == ':' && (dd[14] == '/' || dd[14] == 0)) {
            char rest[512]; snprintf(rest, sizeof rest, "%s", dd + 14);       // "/rest" or ""
            if (l == 'z') {
                char tmp[512]; snprintf(tmp, sizeof tmp, "%s", rest[0] ? rest : "/");
                snprintf(out, outn, "%s", tmp);
            } else {
                char tmp[512]; snprintf(tmp, sizeof tmp, "drive_%c%s", l, rest);
                snprintf(dd + 1, outn - (size_t)(dd + 1 - out), "%s", tmp);
            }
        }
    }
}

int nx_translate_path(const char* p, char* out, size_t outn) {
    if (!p || !p[0]) { errno = ENOENT; return -1; }
    if (!strncmp(p, "sdmc:", 5)) { snprintf(out, outn, "%s", p); return 0; }   // already Horizon
    char norm[512];
    nx_normalize_guest(p, norm, sizeof norm);
    p = norm;
    // Synthetic pseudo-files, backed by a materialized SD temp file.
    if (!strcmp(p, "/proc/cpuinfo"))
        return nx_materialize("proc-cpuinfo", kx_cpuinfo, sizeof kx_cpuinfo - 1, out, outn);
    if (!strcmp(p, "/dev/urandom") || !strcmp(p, "/dev/random") || !strcmp(p, "/dev/hwrng")) {
        unsigned char rb[4096]; randomGet(rb, sizeof rb);
        return nx_materialize("dev-urandom", rb, sizeof rb, out, outn);
    }
    if (!strcmp(p, "/dev/null"))
        return nx_materialize("dev-null", "", 0, out, outn);
    // glibc-hwcaps: box64 advertises AVX2 (x86-64-v3) via CPUID/HWCAP, so the guest's ld.so probes
    // .../glibc-hwcaps/x86-64-v3/libc.so.6 FIRST. If our flat-lib fallback answered that with the base
    // libc, ld.so would load libc TWICE under two host paths (base + hwcaps) -> two inodes -> a split
    // symbol scope (ntdll's __wine_main becomes unresolvable). Force ENOENT for hwcaps variant paths so
    // ld.so falls back to the single base libc. (Must precede the flat-basename fallback below.)
    if (strstr(p, "/glibc-hwcaps/")) { errno = ENOENT; return -1; }
    // Rootfs tree first, then the flat lib/<basename> fallback, else the rootfs path
    // (so an O_CREAT of a new file still lands somewhere sane under the rootfs).
    {
        struct stat st;
        snprintf(out, outn, "%s%s", NX_ROOTFS, p);
        if (stat(out, &st) == 0) return 0;
        const char* b = strrchr(p, '/'); b = b ? b + 1 : p;
        char lib[512]; snprintf(lib, sizeof lib, "%s/%s", NX_LIBDIR, b);
        if (stat(lib, &st) == 0) { snprintf(out, outn, "%s", lib); return 0; }
        snprintf(out, outn, "%s%s", NX_ROOTFS, p);
        return 0;
    }
}

// M2.1 libos: the guest's real ld.so/glibc issue raw Linux syscalls; box64 translates the x86-64 number
// to the aarch64 NR and routes the tail (whatever it does NOT hand-case in emu/x64syscall.c) through
// here. Implement the milestone-1 set over Horizon SVCs; log the rest so the bring-up loop sees the next
// gap. NUMBERS ARE aarch64/generic-Linux NRs (box64 already translated from x86-64).
// M2.7/M2.5: guest CWD — PER guest INSTANCE (the wine client and the in-process wineserver each have
// their own cwd; a shared one would cross-contaminate relative-path resolution). nx_cwd_buf() returns
// the calling instance's 512-byte cwd, keyed by nx_guest_pid(). Threads within one instance share it.
static char nx_cwd_main[512] = "/";
char* nx_cwd_buf(void) {
    int pid = nx_guest_pid();
    if (pid == 100) return nx_cwd_main;                       // the primary guest (fast path)
    static struct { int pid; char cwd[512]; } t[8];
    static pthread_mutex_t mx = PTHREAD_MUTEX_INITIALIZER;
    pthread_mutex_lock(&mx);
    for (int i = 0; i < 8; i++) if (t[i].pid == pid) { pthread_mutex_unlock(&mx); return t[i].cwd; }
    for (int i = 0; i < 8; i++) if (!t[i].pid) { t[i].pid = pid; t[i].cwd[0] = '/'; t[i].cwd[1] = 0;
                                                 pthread_mutex_unlock(&mx); return t[i].cwd; }
    pthread_mutex_unlock(&mx);
    return nx_cwd_main;
}

// M2.5: per-"process" guest pid. One Horizon process hosts multiple guest INSTANCES (the wine client
// + the wineserver thread), which must see different getpid()s — wineserver keys its process table on
// the client pid (SO_PEERCRED + the init_first_thread handshake). Thread-local, inherited via clone().
static pthread_key_t g_pidkey;
static pthread_once_t g_pidonce = PTHREAD_ONCE_INIT;
static void nx_pidkey_init(void) { pthread_key_create(&g_pidkey, NULL); }
int nx_guest_pid(void) {
    pthread_once(&g_pidonce, nx_pidkey_init);
    void* v = pthread_getspecific(g_pidkey);
    return v ? (int)(uintptr_t)v : 100;                 // main guest instance = pid 100
}
void nx_set_guest_pid(int pid) {
    pthread_once(&g_pidonce, nx_pidkey_init);
    pthread_setspecific(g_pidkey, (void*)(uintptr_t)pid);
}

// nx_vfd.c (M2.5): virtual fds — dirs, pipes, in-process AF_UNIX sockets
int  nx_vfd_is(int fd);
int  nx_vfd_open_dir(const char* guest, const char* host);
const char* nx_vfd_dir_host(int fd);
const char* nx_vfd_dir_guest(int fd);
int  nx_vfd_close(int fd);
long nx_vfd_read(int fd, void* buf, size_t n);
long nx_vfd_write(int fd, const void* buf, size_t n);
int  nx_vfd_stat(int fd, struct stat* st);
long nx_vfd_getdents64(int fd, void* buf, size_t count);
int  nx_vfd_fchdir(int fd);
int  nx_pipe2(int fds[2], int linux_flags);
int  nx_socket(int domain, int type, int protocol);
int  nx_socketpair(int domain, int type, int protocol, int sv[2]);
int  nx_shutdown(int fd, int how);
int  nx_bind(int fd, const void* addr, unsigned alen);
int  nx_listen(int fd, int backlog);
int  nx_connect(int fd, const void* addr, unsigned alen);
int  nx_accept4(int fd, void* addr, unsigned* alen, int flags);
long nx_sendmsg(int fd, const void* msg, int flags);
long nx_recvmsg(int fd, void* msg, int flags);
int  nx_getsockopt(int fd, int level, int opt, void* val, unsigned* len);
int  nx_setsockopt(int fd, int level, int opt, const void* val, unsigned len);
int  nx_getsockname(int fd, void* addr, unsigned* alen);
int  nx_poll(void* pfds, unsigned long n, int timeout_ms);
int  nx_vfd_open_shared(const char* guestpath, int is_lock);   // wineserver lock/tmpmap (M2.5)
int  nx_vfd_flock(int fd, int op);
int  nx_vfd_ftruncate(int fd, off_t len);
long nx_vfd_lseek(int fd, off_t off, int whence);
long syscall(long number, ...) {
    va_list ap; va_start(ap, number);
    unsigned long a0 = va_arg(ap, unsigned long);
    unsigned long a1 = va_arg(ap, unsigned long);
    unsigned long a2 = va_arg(ap, unsigned long);
    unsigned long a3 = va_arg(ap, unsigned long);
    unsigned long a4 = va_arg(ap, unsigned long);   // futex uaddr2
    unsigned long a5 = va_arg(ap, unsigned long);   // futex val3
    va_end(ap);
    switch (number) {
        case 214: {   // brk(addr): glibc/ld.so bump allocator. Linux returns the resulting break.
            // M2.5: brk is PER guest INSTANCE — the client (pid 100) and the in-process wineserver
            // (pid 2) each have their own glibc that assumes it owns the break, so a single shared
            // arena would corrupt both heaps. Keep a tiny per-pid arena table.
            struct kx_brk { int pid; uint8_t *base, *cur, *end; };
            static struct kx_brk g_brks[8];
            static pthread_mutex_t g_brkmx = PTHREAD_MUTEX_INITIALIZER;
            int pid = nx_guest_pid();
            pthread_mutex_lock(&g_brkmx);
            struct kx_brk* b = NULL;
            for (int i = 0; i < 8; i++) if (g_brks[i].pid == pid) { b = &g_brks[i]; break; }
            if (!b) for (int i = 0; i < 8; i++) if (!g_brks[i].pid) { b = &g_brks[i]; b->pid = pid; break; }
            if (!b) { pthread_mutex_unlock(&g_brkmx); errno = ENOMEM; return -1; }
            if (!b->base) {
                size_t sz = 64UL * 1024 * 1024;     // 64 MiB per instance
                void* p = mmap(NULL, sz, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
                if (p == MAP_FAILED) { pthread_mutex_unlock(&g_brkmx); nx_warnf("nx: brk arena mmap failed\n"); errno = ENOMEM; return -1; }
                b->base = b->cur = (uint8_t*)p; b->end = b->base + sz;
            }
            uint8_t* req = (uint8_t*)a0;
            long ret;
            if (!req) ret = (long)(uintptr_t)b->cur;                          // query current break
            else { if (req >= b->base && req <= b->end) b->cur = req; ret = (long)(uintptr_t)b->cur; }
            pthread_mutex_unlock(&g_brkmx);
            return ret;
        }
        case 96:  return nx_gettid();                // set_tid_address -> this thread's tid
        case 99:  return 0;                          // set_robust_list -> accept
        case 293: errno = ENOSYS; return -1;         // rseq -> glibc tolerates ENOSYS (benign probe)
        case 233: return 0;                          // madvise -> advisory; no-op success (glibc malloc + thread-stack mgmt spam it per thread)
        case 261: errno = ENOSYS; return -1;         // prlimit64 -> glibc falls back to getrlimit/defaults (sane-limits TODO after arena root-cause)
        case 278:                                    // getrandom(buf, len, flags)
            if (a0 && a1) { randomGet((void*)a0, a1); return (long)a1; }
            return 0;
        case 56: {  // openat(dirfd, path, flags, mode)
            const char* p = (const char*)a1;
            if (!p) { errno = EFAULT; return -1; }
            // M2.4 rootfs VFS: map the guest Linux path to a Horizon path (rootfs tree, flat-lib
            // fallback, or a synthetic /proc,/dev file). FLAGS ARRIVE HOST-CONVERTED: box64's
            // openat case (x64syscall.c) applies of_convert() before this host syscall, so a2 is
            // already newlib bits — do NOT re-convert (double conversion silently drops O_CREAT;
            // cost a bring-up cycle). Keep open()'s errno for the Linux-errno return seam.
            // M2.5: a relative path with a dir vfd resolves against that dir; opening a DIRECTORY
            // returns a dir vfd (newlib open() can't open dirs — glibc opendir needs this).
            char gp[512];
            if (p[0] != '/' && nx_vfd_is((int)a0) && nx_vfd_dir_guest((int)a0)) {
                snprintf(gp, sizeof gp, "%s/%s", nx_vfd_dir_guest((int)a0), p);
                p = gp;
            }
            // Canonicalize to an absolute guest path (resolves a relative "lock"/"tmpmap-*" against the
            // per-instance cwd) so the wineserver-runtime detection below and the shared-object key are
            // stable across the client and wineserver instances.
            char np[512]; nx_normalize_guest(p, np, sizeof np); p = np;
            // Diagnostic (KX_SCTRACE, off by default — it floods): arm the per-syscall trace
            // (x64syscall.c) at the drive_c/windows DLL-search to see the client's last syscalls.
            { extern volatile int kx_sctrace; if (!kx_sctrace && strstr(p, "drive_c/windows") && getenv("KX_SCTRACE")) kx_sctrace = 1; }
            // M2.5: the wineserver runtime files (its `lock` + `tmpmap-*` shared memory) are shared
            // between the in-process client and wineserver. fsdev can't open the same file from both
            // instances and file-backed mmap copies per instance, so back them with in-process shared
            // state (nx_vfd_open_shared): a pid-owned lock, and a single shared buffer both mmaps see.
            { const char* base = strrchr(p, '/'); base = base ? base + 1 : p;
              if (strstr(p, "/wine/server-")) {
                  if (!strcmp(base, "lock"))            return nx_vfd_open_shared(p, 1);
                  if (!strncmp(base, "tmpmap", 6))      return nx_vfd_open_shared(p, 0);
              }
            }
            char hp[512];
            if (nx_translate_path(p, hp, sizeof hp) != 0) return -1;
            struct stat st;
            if (stat(hp, &st) == 0 && S_ISDIR(st.st_mode)) {
                if ((a2 & 3) != 0) { errno = EISDIR; return -1; }        // write access on a dir
                int dfd = nx_vfd_open_dir(p, hp);
                nx_warnf("nx: openat dir '%s' -> vfd=%d\n", p, dfd);
                return dfd;
            }
#ifdef O_DIRECTORY
            if (a2 & O_DIRECTORY) { errno = ENOTDIR; return -1; }        // O_DIRECTORY on a non-dir
#endif
            int fd = open(hp, (int)a2, (mode_t)a3);
            // Robust registry save: if a reg<pid>.tmp open FAILS (the raw fsdev open can transiently
            // return ENOSYS under shared-fd-table pressure — e.g. during a big dir enumeration), fall
            // back to a write-discard SINK vfd so the wineserver's periodic flush COMPLETES instead of
            // looping forever (the mark-after-open nerf never engaging -> registry-save livelock;
            // `directory` hung ~1/6). Only on FAILURE — a successful open keeps the real-fd path (+ its
            // existing write-discard nerf) unchanged, so cmd.exe's save is untouched. The reg*.tmp->*.reg
            // rename is already short-circuited (nx_rename_guest); registry persistence is irrelevant here.
            if (fd < 0) { extern int nx_regtmp_name(const char*); extern int nx_vfd_open_sink(void);
                          if (nx_regtmp_name(p)) return nx_vfd_open_sink(); }
            // HW-visible diagnostic (KX_STATLOG): temp-file opens (the file test's GetTempFileName
            // create + FILE_APPEND_DATA reopen). rlog goes to box64-result.txt, which real HW captures
            // (svcOutputDebugString / nx_warnf do NOT). Bounded to temp paths so it can't flood.
            { static int on = -1; if (on < 0) on = getenv("KX_STATLOG") ? 1 : 0;
              if (on && (strstr(p, "foo") || strstr(p, ".tmp") || strstr(p, "Temp") || strstr(p, "/tmp/"))) {
                  extern void nx_result_log(const char*);
                  char lb[240]; snprintf(lb, sizeof lb, "nx_open: pid=%d '%s' flags=0x%lx mode=0%o -> fd=%d errno=%d",
                      nx_guest_pid(), p, (unsigned long)a2, (unsigned)a3, fd, fd < 0 ? errno : 0);
                  nx_result_log(lb);
              } }
            if (fd < 0) { nx_warnf("nx: openat '%s' -> '%s' FAIL e=%d\n", p, hp, errno); return -1; }
            nx_warnf("nx: openat '%s' -> '%s' fd=%d\n", p, hp, fd);
            // Fast registry save: mark a wineserver reg*.tmp fd so its writes are discarded (the file
            // stays empty and its save rename is short-circuited) — else a slow fsdev save-all starves
            // the wine client. See nx_vfd.c nx_regtmp_*.
            { extern int nx_regtmp_name(const char*); extern void nx_regtmp_mark(int);
              if (nx_regtmp_name(p)) nx_regtmp_mark(fd); }
            return fd;
        }
        case 57:                                                 // close
            if (nx_vfd_is((int)a0)) return nx_vfd_close((int)a0);
            { extern void nx_tee_forget(int fd); nx_tee_forget((int)a0); }  // drop stale stdout/err dup flag
            { extern void nx_regtmp_forget(int fd); nx_regtmp_forget((int)a0); }  // drop reg*.tmp sink flag
            return close((int)a0);
        case 63:                                                 // read
            if (nx_vfd_is((int)a0)) return nx_vfd_read((int)a0, (void*)a1, (size_t)a2);
            return read((int)a0, (void*)a1, (size_t)a2);
        case 64:                                                 // write (vfd; real fds hand-cased in x64syscall)
            if (nx_vfd_is((int)a0)) return nx_vfd_write((int)a0, (const void*)a1, (size_t)a2);
            { extern int nx_regtmp_is(int); if (nx_regtmp_is((int)a0)) return (long)a2; }  // fast registry save
            return write((int)a0, (void*)a1, (size_t)a2);
        case 50: return nx_vfd_fchdir((int)a0);                  // fchdir
        case 61: return nx_vfd_getdents64((int)a0, (void*)a1, (size_t)a2);   // getdents64
        case 46:                                                 // ftruncate (wineserver shmem sizing)
            if (nx_vfd_is((int)a0)) return nx_vfd_ftruncate((int)a0, (off_t)a1);
            return ftruncate((int)a0, (off_t)a1);
        case 32:                                                 // flock -> VK_LOCK owner protocol, else accept
            if (nx_vfd_is((int)a0)) return nx_vfd_flock((int)a0, (int)a1);
            return 0;
        case 59: return nx_pipe2((int*)a0, (int)a1);             // pipe2
        case 73: {  // ppoll(fds, n, timespec*, sigmask) -> nx_poll
            struct kx_ts { long s, ns; } *ts = (struct kx_ts*)a2;
            int ms = ts ? (int)(ts->s * 1000 + ts->ns / 1000000) : -1;
            return nx_poll((void*)a0, (unsigned long)a1, ms);
        }
        // ---- M2.5 in-process AF_UNIX sockets (aarch64 NRs; box64 scwrap routes here) ----
        case 198: return nx_socket((int)a0, (int)a1, (int)a2);
        case 199: return nx_socketpair((int)a0, (int)a1, (int)a2, (int*)a3);
        case 200: return nx_bind((int)a0, (const void*)a1, (unsigned)a2);
        case 201: return nx_listen((int)a0, (int)a1);
        case 202: return nx_accept4((int)a0, (void*)a1, (unsigned*)a2, 0);
        case 242: return nx_accept4((int)a0, (void*)a1, (unsigned*)a2, (int)a3);   // accept4
        case 203: return nx_connect((int)a0, (const void*)a1, (unsigned)a2);
        case 204: return nx_getsockname((int)a0, (void*)a1, (unsigned*)a2);
        case 205: return nx_getsockname((int)a0, (void*)a1, (unsigned*)a2);        // getpeername
        case 206:   // sendto (unix stream: addr ignored)
            if (nx_vfd_is((int)a0)) return nx_vfd_write((int)a0, (const void*)a1, (size_t)a2);
            errno = EBADF; return -1;
        case 207:   // recvfrom
            if (nx_vfd_is((int)a0)) return nx_vfd_read((int)a0, (void*)a1, (size_t)a2);
            errno = EBADF; return -1;
        case 208: return nx_setsockopt((int)a0, (int)a1, (int)a2, (const void*)a3, (unsigned)a4);
        case 209: return nx_getsockopt((int)a0, (int)a1, (int)a2, (void*)a3, (unsigned*)a4);
        case 210: return nx_shutdown((int)a0, (int)a1);          // shutdown (SHUT_WR -> peer EOF)
        case 211: return nx_sendmsg((int)a0, (const void*)a1, (int)a2);
        case 212: return nx_recvmsg((int)a0, (void*)a1, (int)a2);
        case 62:                                                 // lseek
            if (nx_vfd_is((int)a0)) return nx_vfd_lseek((int)a0, (off_t)a1, (int)a2);
            return (long)lseek((int)a0, (off_t)a1, (int)a2);
        case 67: {  // pread64(fd, buf, count, offset) — ld.so reads ELF headers at offsets
            // Emulated via lseek+read (newlib lacks pread). A NON-SEEKABLE fd (pipe/socket/vfd) makes
            // lseek fail; newlib reports that as ENOSYS(88), which box64 would forward to the guest as
            // Linux ENOSYS(38). But real Linux pread64 on a non-seekable fd returns ESPIPE(29), and Wine
            // (e.g. NtReadFile's positioned-read path around get_token_sid) branches on ESPIPE to fall
            // back to a plain read — on the unexpected ENOSYS it left its buffer unfilled and then
            // dereferenced garbage (InvalidMemoryRegion fault). Map any lseek failure to ESPIPE.
            if (nx_vfd_is((int)a0)) { errno = ESPIPE; return -1; }  // vfd pipes/sockets aren't seekable
            off_t cur = lseek((int)a0, 0, SEEK_CUR);
            if (cur < 0)                     { errno = ESPIPE; return -1; }
            if (lseek((int)a0, (off_t)a3, SEEK_SET) < 0) { errno = ESPIPE; return -1; }
            ssize_t r = read((int)a0, (void*)a1, (size_t)a2);
            int e = errno;
            lseek((int)a0, cur, SEEK_SET);                       // restore
            errno = e;
            return (long)r;
        }
        case 68: {  // pwrite64(fd, buf, count, offset)
            int wfd = (int)a0;
            extern int nx_tee_origin(int fd);
            int to = nx_tee_origin(wfd);
            if (to) {  // std out/err (now a "regular file" to Wine): the tee IS the console channel.
                // NEVER seek the libnx console fd (lseek would fail -> lost write). Capture + succeed.
                if (a2) nx_guest_output(to, (const void*)a1, (size_t)a2);
                return (long)a2;
            }
            // wineserver sizes/inits its shared-mem file via positioned writes
            off_t cur = lseek(wfd, 0, SEEK_CUR);
            if (lseek(wfd, (off_t)a3, SEEK_SET) < 0) return -1;
            ssize_t r = write(wfd, (const void*)a1, (size_t)a2);
            lseek(wfd, cur, SEEK_SET);
            return (long)r;
        }
        case 66: {  // writev(fd, iov, iovcnt) — REAL scatter write. fds 1/2 tee to the debug log +
            // result file (that tee IS the guest-console channel); a vfd routes to the vfd layer —
            // Wine's wine_server_call sends every payload-carrying request via writev(request_fd),
            // so swallowing those here silently ate server requests and deadlocked the client;
            // anything else hits the host fd.
            struct kx_iovec { const char* base; size_t len; };
            const struct kx_iovec* v = (const struct kx_iovec*)a1;
            extern int nx_tee_origin(int fd);            // nx_vfd.c — 1/2 or a dup chained from them
            extern long nx_vfd_writev(int fd, const void* iov, int iovcnt);  // atomic vfd scatter-write
            int wfd = (int)a0;
            // A vfd (wineserver request/reply pipe) MUST land the whole writev atomically — the server
            // reads a request's fixed header then its variable data in a blocking loop and relies on the
            // full request arriving as one unit. Route vfds through the atomic writev.
            if (nx_vfd_is(wfd)) return nx_vfd_writev(wfd, (const void*)a1, (int)a2);
            int to  = nx_tee_origin(wfd);
            long total = 0;
            for (unsigned i = 0; i < (unsigned)a2 && v; ++i) {
                if (!v[i].base || !v[i].len) continue;
                long r;
                if (to) nx_guest_output(to, v[i].base, v[i].len);
                if (wfd == 1 || wfd == 2) r = (long)v[i].len;   // the tee IS the console channel
                else                      r = write(wfd, v[i].base, v[i].len);
                if (r < 0) return total ? total : -1;
                total += r;
                if ((size_t)r < v[i].len) break;
            }
            return total;
        }
        case 135: return 0;                          // rt_sigprocmask -> accept (no signals yet)
        case 178: return nx_gettid();                // gettid
        case 172: return nx_guest_pid();             // getpid (per guest INSTANCE — M2.5)
        case 124: svcSleepThread(0); return 0;       // sched_yield
        case 98:  return nx_futex((int*)a0, (int)a1, (unsigned)a2, (const void*)a3, (int*)a4, (unsigned)a5);
        // M2.7 (Wine): the WINEPREFIX. box64-nx's VFS resolves paths against the rootfs (not a real CWD),
        // so accept chdir + report the requested dir back via getcwd. Wine chdir()s into /root/.wine.
        case 49: {   // chdir(path) -> accept + remember the CANONICAL absolute cwd (resolve relative
                     // against the current cwd + collapse ./.. ), so getcwd + a later stat(".") agree
                     // with an absolute stat of the same dir (wineserver's post-chdir identity check).
            const char* p = (const char*)a0;
            if (p) { char norm[512]; nx_normalize_guest(p, norm, sizeof norm);
                     snprintf(nx_cwd_buf(), 512, "%s", norm); }
            return 0;
        }
        case 17: {   // getcwd(buf, size) -> the remembered CWD (Linux returns length incl NUL)
            char* buf = (char*)a0; size_t sz = (size_t)a1;
            const char* nc = nx_cwd_buf(); const char* c = nc[0] ? nc : "/";
            size_t n = strlen(c) + 1;
            if (!buf || n > sz) { errno = ERANGE; return -1; }
            memcpy(buf, c, n); return (long)n;
        }
        case 174: return 0;                          // getuid  -> root
        case 175: return 0;                          // geteuid -> root
        case 176: return 0;                          // getgid  -> root
        case 177: return 0;                          // getegid -> root
        case 113: {  // clock_gettime(clockid, timespec*) — Horizon monotonic tick
            struct kx_ts { long tv_sec, tv_nsec; } *ts = (struct kx_ts*)a1;
            if (!ts) { errno = EFAULT; return -1; }
            u64 ns = armTicksToNs(armGetSystemTick());
            ts->tv_sec = (long)(ns / 1000000000ULL); ts->tv_nsec = (long)(ns % 1000000000ULL);
            return 0;
        }
        case 169: {  // gettimeofday(tv, tz) — wineserver + the client poll loop use it for timing
            struct kx_tv { long tv_sec, tv_usec; } *tv = (struct kx_tv*)a0;
            if (tv) { u64 ns = armTicksToNs(armGetSystemTick());
                      tv->tv_sec = (long)(ns / 1000000000ULL); tv->tv_usec = (long)((ns / 1000ULL) % 1000000ULL); }
            return 0;
        }
        case 34: {   // mkdirat(dirfd, path, mode) — create a dir in the rootfs (Wine: server tmpdir)
            extern int nx_mkdir_guest(const char* p, unsigned mode);
            return nx_mkdir_guest((const char*)a1, (unsigned)a2);
        }
        // No-op-and-succeed file ops that fsdev has no semantics for. As ENOSYS they made the
        // wineserver's file_set_error() choke (ENOSYS has no NT mapping) and stall its service loop,
        // starving the wine client mid-startup. Accept them: perms/times/flush are irrelevant to us.
        case 82:  return 0;   // fsync
        case 83:  return 0;   // fdatasync
        case 52:  return 0;   // fchmod
        case 53:  return 0;   // fchmodat
        case 88:  return 0;   // utimensat / futimens
        case 55:  return 0;   // fchown
        case 54:  return 0;   // fchownat
        case 44: {   // fstatfs(fd, buf) / statfs — Wine + the wineserver query the FS; ENOSYS made the
                     // wineserver's file_set_error() choke (can't map ENOSYS to an NT status) and stall a
                     // client request. Report a plausible ext-like filesystem so the mapping proceeds.
                     // Linux struct statfs (x86-64): f_type,f_bsize,f_blocks,f_bfree,f_bavail,f_files,
                     // f_ffree,f_fsid[2],f_namelen,f_frsize,f_flags,f_spare[4] — all 8-byte on x86-64.
            struct kx_statfs { long type, bsize, blocks, bfree, bavail, files, ffree;
                               int fsid[2]; long namelen, frsize, flags, spare[4]; } *sf =
                (struct kx_statfs*)a1;   // fstatfs: buf=a1; statfs: buf=a1 too (path=a0)
            if (sf) { memset(sf, 0, sizeof *sf);
                      sf->type = 0xEF53; sf->bsize = 4096; sf->frsize = 4096;
                      sf->blocks = 0x100000; sf->bfree = 0x80000; sf->bavail = 0x80000;
                      sf->files = 0x10000; sf->ffree = 0x8000; sf->namelen = 255; }
            return 0;
        }
        case 269: case 439: {   // faccessat(dirfd,path,mode[,flags]) / faccessat2 — glibc access() tries
                                // faccessat2 first; ENOSYS there stalled the wineserver's access check.
                                // Route to an existence check against the rootfs (fsdev has no perms).
            extern int nx_access_guest(const char* p, int mode);
            const char* p = (const char*)a1;   // dirfd=a0, path=a1
            if (p && p[0] != '/' && nx_vfd_is((int)a0) && nx_vfd_dir_guest((int)a0)) {
                char full[1024]; snprintf(full, sizeof full, "%s/%s", nx_vfd_dir_guest((int)a0), p);
                return nx_access_guest(full, (int)a2);
            }
            return nx_access_guest(p, (int)a2);
        }
        // Non-file syscalls glibc/Wine touch during cmd.exe startup. As ENOSYS they spammed nx_stub
        // and left a sticky guest errno; give each a benign, plausible result instead.
        case 114: {  // clock_getres(clockid, timespec*) — report 1ns resolution
            struct kx_ts { long tv_sec, tv_nsec; } *ts = (struct kx_ts*)a1;
            if (ts) { ts->tv_sec = 0; ts->tv_nsec = 1; }
            return 0;
        }
        case 123: {  // sched_getaffinity(pid, cpusetsize, mask) — report online CPUs so glibc's
                     // nproc/arena sizing is sane. Return the bytes filled (glibc zeroes the rest).
            unsigned long sz = (unsigned long)a1; unsigned char* mask = (unsigned char*)a2;
            if (!mask || sz < 8) { errno = EINVAL; return -1; }
            memset(mask, 0, sz);
            mask[0] = 0x0f;                          // 4 CPUs online (Horizon exposes cores 0-3)
            return 8;                                // bytes of cpumask copied
        }
        case 167: return 0;                          // prctl(option, ...) -> accept (PR_SET_NAME etc.)
        case 179: {  // sysinfo(struct sysinfo*) — zero-fill + a plausible RAM figure (mem_unit=1)
            // Layout MUST match the kernel uapi struct exactly: the tail is
            // char _f[20 - 2*sizeof(long) - sizeof(int)] = ZERO bytes on 64-bit (total 112 bytes).
            // A hand-inlined `_f[20]` made sizeof 128 and the memset overflowed 16 bytes past the
            // guest's on-stack struct — glibc get_phys_pages() has ONLY the canary above it, so every
            // sysconf(_SC_PHYS_PAGES) died "*** stack smashing detected ***" (the ntdll:directory
            // deterministic smash, 2026-07-18; deterministic + engine-independent = this libos bug).
            struct kx_sysinfo { long uptime; unsigned long loads[3];
                unsigned long totalram, freeram, sharedram, bufferram, totalswap, freeswap;
                unsigned short procs, pad; unsigned long totalhigh, freehigh;
                unsigned int mem_unit;
                char _f[20 - 2 * sizeof(unsigned long) - sizeof(unsigned int)]; }
                *si = (struct kx_sysinfo*)a0;
            _Static_assert(sizeof(struct kx_sysinfo) == 112, "kernel sysinfo is 112 bytes on 64-bit");
            if (si) { memset(si, 0, sizeof *si);
                      si->mem_unit = 1; si->totalram = 0x40000000UL; si->freeram = 0x20000000UL;
                      si->procs = 1; }
            return 0;
        }
        default:
            nx_warnf("nx_stub: syscall(%ld) unimplemented -> -ENOSYS\n", number);
            errno = ENOSYS; return -1;
    }
}
#ifndef CLONE_PARENT_SETTID
#define CLONE_PARENT_SETTID  0x00100000
#endif
#ifndef CLONE_CHILD_CLEARTID
#define CLONE_CHILD_CLEARTID 0x00200000
#endif

// ---- host-thread reaper (M2.6) ---------------------------------------------------------------
// A DETACHED host thread leaks its Horizon thread-ResourceLimit slot (only threadClose, reached via
// pthread_join, frees it) -> svcCreateThread LimitReached after ~600 lifecycles -> pthread_create
// EPERM. So we run guest threads JOINABLE and reap them with a plain pthread_join at the next clone().
// This is safe as long as guest threads get their OWN glibc TLS: CLONE_SETTLS must reach the child emu
// (x64syscall.c case 56), else all threads share the parent's tcache/thread_arena and the shared-arena
// race corrupts the guest heap (it looked like a join-reaper bug because joining is what let arena.c
// run long enough — 4800 lifecycles — to expose it). Clean on real HW (arena 4800 lifecycles + stress
// x32 green). Reaper is ON by default; set KX_NO_REAP to opt out (restores the leak for A/B).
#define NX_TPOOL_MAX  640            // > the ~600 thread ceiling -> the reap queue never overflows
static pthread_t g_reap[NX_TPOOL_MAX];
static int       g_reap_n = 0;
static pthread_mutex_t g_tpool_mx = PTHREAD_MUTEX_INITIALIZER;

static int reap_enabled(void) {
    static int e = -1;
    if (e < 0) e = getenv("KX_NO_REAP") ? 0 : 1;   // ON by default
    return e;
}
static void nx_reap_enqueue(pthread_t th) {
    pthread_mutex_lock(&g_tpool_mx);
    if (g_reap_n < NX_TPOOL_MAX) g_reap[g_reap_n++] = th;
    pthread_mutex_unlock(&g_tpool_mx);
}
static void nx_reap_drain(void) {
    pthread_t batch[NX_TPOOL_MAX]; int n;
    pthread_mutex_lock(&g_tpool_mx);
    n = g_reap_n; g_reap_n = 0;                              // take the pending batch under lock,
    for (int i = 0; i < n; i++) batch[i] = g_reap[i];
    pthread_mutex_unlock(&g_tpool_mx);
    for (int i = 0; i < n; i++) pthread_join(batch[i], NULL);   // join OUTSIDE the lock: frees the slot
}

static void* nx_clone_trampoline(void* p) {
    nx_clone_t* c = (nx_clone_t*)p;
    g_nx_self = c;                          // publish tid/ctid before running the guest
    { extern void nx_set_guest_pid(int); nx_set_guest_pid(c->gpid); }   // same guest "process"
    c->fn(c->arg);                          // clone_fn_syscall: DynaRun the guest, FreeX64Emu, then return
                                            // here (on __SWITCH__ it returns instead of _exit; x64syscall.c)
    if (c->ctid) {                          // CLONE_CHILD_CLEARTID: zero the tid + wake pthread_join
        __atomic_store_n(c->ctid, 0, __ATOMIC_SEQ_CST);
        svcSignalToAddress(c->ctid, SignalType_Signal, 0, 1);
    }
    thread_free_forgotten_emu();            // NULL the pthread key + FREE the ~64B wrapper. The emu was
                                            // already freed (destructor would double-free it), so we free the
                                            // orphaned emuthread_t here instead of leaking it every thread (M2.6).
    { extern void nx_exc_thread_exit(void); nx_exc_thread_exit(); }   // release any exception slots this
                                            // thread still holds (M2.6 pool, release site 3 — safe here: the
                                            // exiting thread is off every slot stack once c->fn returned)
    free(c);
    g_nx_self = NULL;
    if (reap_enabled()) nx_reap_enqueue(pthread_self());   // JOINABLE: a later clone() joins us -> frees the slot
    return NULL;
}

// Host clone() — the seam box64's raw-clone THREAD branch (x64syscall.c case 56) calls. box64's `stack`
// is a 1MB host scratch stack we ignore (we only receive its top); pthread allocates the host/JIT stack.
// The guest owns join via the CLONE_CHILD_CLEARTID futex, so box64 never host-joins for synchronization;
// the reaper's pthread_join (above) only frees the Horizon thread slot.
int clone(int (*fn)(void *), void *stack, int flags, void *arg, ...) {
    (void)stack;
    va_list ap; va_start(ap, arg);
    int*  ptid   = va_arg(ap, int*);          // R_RDX (parent_tid)
    void* newtls = va_arg(ap, void*); (void)newtls;   // R_R8 — CLONE_SETTLS applied by box64 to the child emu's FS (x64syscall.c)
    int*  ctid   = va_arg(ap, int*);          // R_R10 (child_tid)
    va_end(ap);

    int reap = reap_enabled();
    if (reap) nx_reap_drain();   // reclaim Horizon thread slots from host threads that exited since last clone() (M2.6)

    nx_clone_t* c = (nx_clone_t*)malloc(sizeof(*c));
    if (!c) { errno = ENOMEM; return -1; }
    c->fn    = fn;
    c->arg   = arg;
    c->flags = flags;
    c->ctid  = (flags & CLONE_CHILD_CLEARTID) ? ctid : NULL;
    c->tid   = atomic_fetch_add_explicit(&g_nx_next_tid, 1, memory_order_relaxed);
    { extern int nx_guest_pid(void); c->gpid = nx_guest_pid(); }   // child stays in this guest "process"
    if ((flags & CLONE_PARENT_SETTID) && ptid) *ptid = c->tid;   // == the value glibc caches as pd->tid

    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, 1u << 20);                  // >=1MB host/JIT stack; libnx owns it
    pthread_attr_setdetachstate(&attr, reap ? PTHREAD_CREATE_JOINABLE : PTHREAD_CREATE_DETACHED);
    pthread_t th;
    int rc = pthread_create(&th, &attr, nx_clone_trampoline, c);
    pthread_attr_destroy(&attr);
    if (rc) { free(c); errno = rc; return -1; }
    return c->tid;                                                // child tid to the guest parent
}

// --- Advanced pthread APIs libnx lacks (declared in shim/static_compat.h) ---------------------
// Single-threaded static guests never reach these; -ENOSYS keeps box64 linking.
#include <pthread.h>
#include <sched.h>
int pthread_attr_getinheritsched(const pthread_attr_t *a, int *v) { (void)a;(void)v; return ENOSYS; }
int pthread_attr_getschedpolicy(const pthread_attr_t *a, int *v) { (void)a;(void)v; return ENOSYS; }
int pthread_attr_getscope(const pthread_attr_t *a, int *v) { (void)a;(void)v; return ENOSYS; }
int pthread_attr_setinheritsched(pthread_attr_t *a, int v) { (void)a;(void)v; return ENOSYS; }
int pthread_attr_setschedpolicy(pthread_attr_t *a, int v) { (void)a;(void)v; return ENOSYS; }
int pthread_attr_setscope(pthread_attr_t *a, int v) { (void)a;(void)v; return ENOSYS; }
int pthread_attr_setaffinity_np(pthread_attr_t *a, size_t n, const cpu_set_t *c) { (void)a;(void)n;(void)c; return ENOSYS; }
int pthread_getattr_np(pthread_t t, pthread_attr_t *a) { (void)t;(void)a; return ENOSYS; }
int pthread_getattr_default_np(pthread_attr_t *a) { (void)a; return ENOSYS; }
int pthread_setattr_default_np(const pthread_attr_t *a) { (void)a; return ENOSYS; }
int pthread_getaffinity_np(pthread_t t, size_t n, cpu_set_t *c) { (void)t;(void)n;(void)c; return ENOSYS; }
int pthread_setaffinity_np(pthread_t t, size_t n, const cpu_set_t *c) { (void)t;(void)n;(void)c; return ENOSYS; }
int pthread_mutexattr_getprotocol(const pthread_mutexattr_t *a, int *v) { (void)a;(void)v; return ENOSYS; }
int pthread_mutexattr_getrobust(const pthread_mutexattr_t *a, int *v) { (void)a;(void)v; return ENOSYS; }
int pthread_mutexattr_setprioceiling(pthread_mutexattr_t *a, int v) { (void)a;(void)v; return ENOSYS; }
int pthread_mutexattr_setprotocol(pthread_mutexattr_t *a, int v) { (void)a;(void)v; return ENOSYS; }
int pthread_mutexattr_setrobust(pthread_mutexattr_t *a, int v) { (void)a;(void)v; return ENOSYS; }

int uname(struct utsname *buf) {
    if (!buf) { errno = EFAULT; return -1; }
    memset(buf, 0, sizeof(*buf));
    strcpy(buf->sysname, "Linux");          // box64 presents a Linux personality to the guest
    strcpy(buf->nodename, "switch");
    strcpy(buf->release, "6.1.0-kurokonx");
    strcpy(buf->version, "#1 box64-nx Horizon");
    strcpy(buf->machine, "x86_64");         // the *guest* ABI box64 emulates
    return 0;
}

#endif // __SWITCH__
