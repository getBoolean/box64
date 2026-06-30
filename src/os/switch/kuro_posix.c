// KurokoNX — "kuro-posix" implementation (libnx). See kuro_posix.h.
#ifdef __SWITCH__

#include "kuro_posix.h"

#include <switch.h>
#include <stdlib.h>
#include <malloc.h>     // memalign
#include <string.h>
#include <errno.h>
#include <sys/mman.h>   // PROT_*/MAP_* (KurokoNX shim)

#define KURO_PAGE 0x1000UL

// M1.0/M1.1: back anonymous RW mappings with the newlib heap (aligned). This does NOT honor
// MAP_FIXED at guest-chosen x86 addresses yet — box64's address-space placement + executable
// (dynarec) arenas come in M1.1/M1.2 (libnx virtmem + jit dual-alias). For now this is enough to
// link and to run a simple static interpreter guest.
void *kuro_mmap(void *addr, unsigned long length, int prot, int flags, int fd, ssize_t offset) {
    (void)addr; (void)prot; (void)fd; (void)offset; (void)flags;
    if (!length) return MAP_FAILED;
    size_t rounded = (length + KURO_PAGE - 1) & ~(KURO_PAGE - 1);
    void *p = memalign(KURO_PAGE, rounded);
    if (!p) { errno = ENOMEM; return MAP_FAILED; }
    if (flags & MAP_ANONYMOUS) memset(p, 0, rounded);
    return p;
}

int kuro_munmap(void *addr, unsigned long length) {
    (void)length;
    free(addr);   // pairs with memalign above; refined when virtmem-backed mmap lands
    return 0;
}

int kuro_gettid(void) {
    // Single-threaded for now (M1 static guests). Real per-thread ids arrive with thread support.
    return 1;
}

int kuro_sched_yield(void) {
    svcSleepThread(0);
    return 0;
}

// --- POSIX system-name wrappers (box64 calls these directly in places) -----------------------
#include <dlfcn.h>

// NOTE: mmap/mmap64/munmap are provided by box64's src/custommmap.c, which delegates to
// InternalMmap (os_switch.c -> kuro_mmap). We only supply the rest of the mman surface here.
// No real page-permission changes for the interpreter (heap-backed mmap); revisited in M1.2.
int mprotect(void *addr, size_t len, int prot) { (void)addr; (void)len; (void)prot; return 0; }
void *mremap(void *old_addr, size_t old_size, size_t new_size, int flags, ...) {
    (void)old_size; (void)flags; return kuro_mmap(old_addr, new_size, 0, MAP_ANONYMOUS, -1, 0);
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

int poll(struct pollfd *fds, nfds_t nfds, int timeout) { (void)fds;(void)nfds;(void)timeout; errno=ENOSYS; return -1; }
int ioctl(int fd, unsigned long request, ...) { (void)fd;(void)request; errno=ENOSYS; return -1; }
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
    strcpy(buf->version, "#1 KurokoNX Horizon");
    strcpy(buf->machine, "x86_64");         // the *guest* ABI box64 emulates
    return 0;
}

#endif // __SWITCH__
