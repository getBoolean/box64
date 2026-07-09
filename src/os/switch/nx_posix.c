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
int fstatat(int dirfd, const char *path, struct stat *b, int flags) {
    int r;
    extern int nx_vfd_is(int fd);
    extern int nx_vfd_stat(int fd, struct stat* st);
    extern const char* nx_vfd_dir_guest(int fd);
    if ((flags & AT_EMPTY_PATH) || !path || !path[0])
        r = nx_vfd_is(dirfd) ? nx_vfd_stat(dirfd, b)     // M2.5: dir/socket vfds
                             : fstat(dirfd, b);          // fstat via the open fd
    else {
        char gp[512];                                    // M2.5: relative to a dir vfd
        if (path[0] != '/' && nx_vfd_is(dirfd) && nx_vfd_dir_guest(dirfd)) {
            snprintf(gp, sizeof gp, "%s/%s", nx_vfd_dir_guest(dirfd), path);
            path = gp;
        }
        char hp[512];                                    // M2.4: rootfs VFS (was flat-lib basename)
        if (nx_translate_path(path, hp, sizeof hp) != 0) { errno = ENOENT; return -1; }
        r = stat(hp, b);
    }
    // fsdev/newlib returns st_dev=st_ino=0 for every file. ld.so dedups loaded objects by (dev,ino),
    // so 0/0 makes libc.so.6 look "already loaded" (same 0/0 as ld.so/the main exe), ld.so skips
    // mapping it, and __libc_start_main is then undefined. Give each stat a unique non-zero identity.
    if (r == 0) { static unsigned long g_ino = 2; b->st_dev = 1; if (!b->st_ino) b->st_ino = __atomic_add_fetch(&g_ino, 1, __ATOMIC_RELAXED); }
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
extern char nx_cwd[512];
static void nx_normalize_guest(const char* p, char* out, size_t outn) {
    char joined[1024];
    if (p[0] == '/') snprintf(joined, sizeof joined, "%s", p);
    else snprintf(joined, sizeof joined, "%s/%s", (nx_cwd[0] == '/') ? nx_cwd : "/", p);
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
static uint8_t *g_brk_base = NULL, *g_brk_cur = NULL, *g_brk_end = NULL;   // simple bump arena for brk()
char nx_cwd[512] = "/";   // M2.7: guest CWD (VFS resolves against the rootfs; this is just for getcwd)

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
            if (!g_brk_base) {
                size_t sz = 64UL * 1024 * 1024;     // 64 MiB arena is ample for ld.so + a hello's heap
                void* p = mmap(NULL, sz, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
                if (p == MAP_FAILED) { nx_warnf("nx: brk arena mmap failed\n"); errno = ENOMEM; return -1; }
                g_brk_base = g_brk_cur = (uint8_t*)p; g_brk_end = g_brk_base + sz;
            }
            uint8_t* req = (uint8_t*)a0;
            if (!req) return (long)(uintptr_t)g_brk_cur;                     // query current break
            if (req >= g_brk_base && req <= g_brk_end) g_brk_cur = req;       // grow/shrink within the arena
            return (long)(uintptr_t)g_brk_cur;                               // else unchanged (grow failed)
        }
        case 96:  return nx_gettid();                // set_tid_address -> this thread's tid
        case 99:  return 0;                          // set_robust_list -> accept
        case 293: errno = ENOSYS; return -1;         // rseq -> glibc tolerates ENOSYS
        case 261: errno = ENOSYS; return -1;         // prlimit64 -> glibc falls back to getrlimit/defaults
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
            if (fd < 0) { nx_warnf("nx: openat '%s' -> '%s' FAIL e=%d\n", p, hp, errno); return -1; }
            nx_warnf("nx: openat '%s' -> '%s' fd=%d\n", p, hp, fd);
            return fd;
        }
        case 57: return nx_vfd_is((int)a0) ? nx_vfd_close((int)a0) : close((int)a0);   // close
        case 63:                                                 // read
            if (nx_vfd_is((int)a0)) return nx_vfd_read((int)a0, (void*)a1, (size_t)a2);
            return read((int)a0, (void*)a1, (size_t)a2);
        case 64:                                                 // write (vfd; real fds hand-cased in x64syscall)
            if (nx_vfd_is((int)a0)) return nx_vfd_write((int)a0, (const void*)a1, (size_t)a2);
            return write((int)a0, (void*)a1, (size_t)a2);
        case 50: return nx_vfd_fchdir((int)a0);                  // fchdir
        case 61: return nx_vfd_getdents64((int)a0, (void*)a1, (size_t)a2);   // getdents64
        case 32: return 0;                                       // flock -> single fs user, accept
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
        case 210: return 0;                                      // shutdown -> accept
        case 211: return nx_sendmsg((int)a0, (const void*)a1, (int)a2);
        case 212: return nx_recvmsg((int)a0, (void*)a1, (int)a2);
        case 62: return (long)lseek((int)a0, (off_t)a1, (int)a2);// lseek
        case 67: {  // pread64(fd, buf, count, offset) — ld.so reads ELF headers at offsets
            off_t cur = lseek((int)a0, 0, SEEK_CUR);             // save position (newlib may lack pread)
            if (lseek((int)a0, (off_t)a3, SEEK_SET) < 0) return -1;
            ssize_t r = read((int)a0, (void*)a1, (size_t)a2);
            lseek((int)a0, cur, SEEK_SET);                       // restore
            return (long)r;
        }
        case 66: {  // writev(fd, iov, iovcnt) — surface guest stderr/stdout (glibc/ld.so error text)
            struct kx_iovec { const char* base; size_t len; };
            const struct kx_iovec* v = (const struct kx_iovec*)a1;
            long total = 0;
            for (unsigned i = 0; i < (unsigned)a2 && v; ++i) {
                if (v[i].base && v[i].len) {
                    nx_guest_output((int)a0, v[i].base, v[i].len);  // Ryujinx log + result-file tee
                    total += (long)v[i].len;
                }
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
        case 49: {   // chdir(path) -> accept + remember
            const char* p = (const char*)a0;
            if (p) snprintf(nx_cwd, sizeof nx_cwd, "%s", p);
            return 0;
        }
        case 17: {   // getcwd(buf, size) -> the remembered CWD (Linux returns length incl NUL)
            char* buf = (char*)a0; size_t sz = (size_t)a1;
            const char* c = nx_cwd[0] ? nx_cwd : "/";
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
        case 34: {   // mkdirat(dirfd, path, mode) — create a dir in the rootfs (Wine: server tmpdir)
            extern int nx_mkdir_guest(const char* p, unsigned mode);
            return nx_mkdir_guest((const char*)a1, (unsigned)a2);
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
    thread_forget_emu();                    // NULL the pthread key: the emu was already freed, so its
                                            // destructor must not run (would double-free). The ~64B et leaks.
    free(c);
    g_nx_self = NULL;
    return NULL;                            // detached: pthread/libnx reclaim the host stack
}

// Host clone() — the seam box64's raw-clone THREAD branch (x64syscall.c case 56) calls. box64's `stack`
// is a 1MB host scratch stack we ignore (we only receive its top); pthread allocates the host/JIT stack.
// The guest owns join via the CLONE_CHILD_CLEARTID futex, so the pthread is detached (never host-joined).
int clone(int (*fn)(void *), void *stack, int flags, void *arg, ...) {
    (void)stack;
    va_list ap; va_start(ap, arg);
    int*  ptid   = va_arg(ap, int*);          // R_RDX (parent_tid)
    void* newtls = va_arg(ap, void*); (void)newtls;   // R_R8 — CLONE_SETTLS already stripped by box64
    int*  ctid   = va_arg(ap, int*);          // R_R10 (child_tid)
    va_end(ap);

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
    pthread_attr_setstacksize(&attr, 1u << 20);                  // >=1MB host/JIT stack
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
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
