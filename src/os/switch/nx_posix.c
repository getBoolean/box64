// box64-nx — "kuro-posix" implementation (libnx). See nx_posix.h.
#ifdef __SWITCH__

#include "nx_posix.h"

#include <switch.h>
#include <stdlib.h>
#include <malloc.h>     // memalign
#include <string.h>
#include <errno.h>
#include <sys/mman.h>   // PROT_*/MAP_* (box64-nx shim)

#define NX_PAGE 0x1000UL

// M1.1: back mappings with the newlib heap (page-aligned). box64's ELF loader first reserves a
// whole-image block with a plain (non-FIXED) anonymous mmap, then places each PT_LOAD segment at a
// fixed offset *inside* that block with MAP_FIXED. Since the heap block is already RW, we honor an
// anonymous MAP_FIXED by returning the requested address (zeroing it — that covers .bss); box64
// then fread()s the file contents over the file-backed part. A *file*-backed MAP_FIXED can't be
// satisfied by a heap allocator, so we fail it, which makes box64 fall back to its anon-map+fread
// path. Real virtmem-backed placement + a W^X dynarec arena arrive in M1.2/M1.3.
void *nx_mmap(void *addr, unsigned long length, int prot, int flags, int fd, ssize_t offset) {
    (void)prot; (void)fd; (void)offset;
#ifdef NX_MMAP_TRACE
    { char b[128]; int n = snprintf(b, sizeof b, "nx_mmap(addr=%p len=0x%lx fl=0x%x fd=%d)\n", addr, length, (unsigned)flags, fd); svcOutputDebugString(b, n); }
#endif
    if (!length) return MAP_FAILED;
    size_t rounded = (length + NX_PAGE - 1) & ~(NX_PAGE - 1);

    if (flags & MAP_FIXED) {
        if (!(flags & MAP_ANONYMOUS) || !addr) {
            // File-backed (or NULL) fixed mapping — force box64's anon-map + fread fallback.
            errno = ENODEV;
            return MAP_FAILED;
        }
        memset(addr, 0, rounded);   // target is inside an already-reserved heap block
        return addr;
    }

    void *p = memalign(NX_PAGE, rounded);
    if (!p) { errno = ENOMEM; return MAP_FAILED; }
    if (flags & MAP_ANONYMOUS) memset(p, 0, rounded);
    return p;
}

int nx_munmap(void *addr, unsigned long length) {
    (void)addr; (void)length;
    // NOTE: addr may be a MAP_FIXED sub-range *inside* a larger reserved block (not its own
    // allocation), so free()ing it here would corrupt the heap. Leak for now — a static M1 guest
    // maps once and runs; a real allocator (tracking reserved blocks) lands with virtmem in M1.3.
    return 0;
}

int nx_gettid(void) {
    // Single-threaded for now (M1 static guests). Real per-thread ids arrive with thread support.
    return 1;
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
int mprotect(void *addr, size_t len, int prot) { (void)addr; (void)len; (void)prot; return 0; }
void *mremap(void *old_addr, size_t old_size, size_t new_size, int flags, ...) {
    (void)old_size; (void)flags; return nx_mmap(old_addr, new_size, 0, MAP_ANONYMOUS, -1, 0);
}
int madvise(void *a, size_t l, int adv) { (void)a; (void)l; (void)adv; return 0; }
int msync(void *a, size_t l, int f) { (void)a; (void)l; (void)f; return 0; }
int mlock(const void *a, size_t l) { (void)a; (void)l; return 0; }
int munlock(const void *a, size_t l) { (void)a; (void)l; return 0; }
// POSIX shared memory — no cross-process shm on Horizon (single process).
int shm_open(const char *name, int oflag, mode_t mode) { (void)name; (void)oflag; (void)mode; errno = ENOSYS; return -1; }
int shm_unlink(const char *name) { (void)name; errno = ENOSYS; return -1; }

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

// sysconf/getpagesize — newlib's return -ENOSYS via our stubs, but box64 needs a real page
// size (box64_pagesize = sysconf(_SC_PAGESIZE); a -1 poisons all its alignment/mmap math).
#include <unistd.h>
long sysconf(int name) {
    switch (name) {
        case _SC_PAGESIZE:          return 4096;
        case _SC_NPROCESSORS_CONF:
        case _SC_NPROCESSORS_ONLN:  return 3;      // homebrew applet cores
        case _SC_CLK_TCK:           return 100;
        case _SC_OPEN_MAX:          return 1024;
        case _SC_PHYS_PAGES:        return (long)((256UL * 1024 * 1024) / 4096);
        case _SC_AVPHYS_PAGES:      return (long)((128UL * 1024 * 1024) / 4096);
        default:                    errno = EINVAL; return -1;
    }
}
int getpagesize(void) { return 4096; }

long syscall(long number, ...) { (void)number; errno = ENOSYS; return -1; }
int  clone(int (*fn)(void *), void *stack, int flags, void *arg, ...) {
    (void)fn; (void)stack; (void)flags; (void)arg; errno = ENOSYS; return -1;
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
