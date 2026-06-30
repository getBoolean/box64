// KurokoNX shim — newlib libc compatibility for box64's glibc-isms.
// Force-included on the Switch target (see CMakeLists.txt NintendoSwitch branch)
// so these aliases are visible in every translation unit.
#pragma once
#ifdef __SWITCH__

// Many box64 TUs assume GNU libc visibility (pthread _np APIs, CLOCK_*_COARSE,
// CPU_SET, etc.). newlib gates those behind _GNU_SOURCE; set it globally for the
// Switch build (this header is force-included before any system header).
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <stdio.h>

// box64's ELF parser uses the glibc large-file aliases; newlib's off_t is
// already 64-bit, so the plain POSIX names are equivalent.
#ifndef fseeko64
#define fseeko64 fseeko
#endif
#ifndef ftello64
#define ftello64 ftello
#endif

// GNU libm extensions newlib lacks; real symbols live in kuro_posix.c so the
// libm wrapper table (&sincos) also resolves at link time.
void sincos(double x, double *s, double *c);
void sincosf(float x, float *s, float *c);

// Linux waitid()/waitpid() option flags newlib's <sys/wait.h> omits (Linux values).
// Only reached on the guest fork/vfork path, which Horizon never executes.
#include <sys/wait.h>
#ifndef WNOHANG
#define WNOHANG    1
#endif
#ifndef WUNTRACED
#define WUNTRACED  2
#endif
#ifndef WEXITED
#define WEXITED    4
#endif
#ifndef WCONTINUED
#define WCONTINUED 8
#endif
#ifndef WSTOPPED
#define WSTOPPED   WUNTRACED
#endif
#ifndef WNOWAIT
#define WNOWAIT    0x01000000
#endif

// glibc large-file dirent types newlib spells differently.
typedef unsigned long long ino64_t;
typedef _off64_t           off64_t;

// Linux clone() flags (from <linux/sched.h>); box64's guest clone/thread path
// references these. Never executed by a single-threaded static guest.
#ifndef CLONE_VM
#define CLONE_VM             0x00000100
#define CLONE_FS             0x00000200
#define CLONE_FILES          0x00000400
#define CLONE_SIGHAND        0x00000800
#define CLONE_VFORK          0x00004000
#define CLONE_PARENT         0x00008000
#define CLONE_THREAD         0x00010000
#define CLONE_SYSVSEM        0x00040000
#define CLONE_SETTLS         0x00080000
#define CLONE_PARENT_SETTID  0x00100000
#define CLONE_CHILD_CLEARTID 0x00200000
#define CLONE_DETACHED       0x00400000
#define CLONE_CHILD_SETTID   0x01000000
#endif

// box64 provides mmap64() itself (src/custommmap.c, delegating to InternalMmap);
// just declare it so callers like threads.c see a prototype.
void *mmap64(void *addr, unsigned long length, int prot, int flags, int fd, long offset);
#ifndef PTHREAD_STACK_MIN
#define PTHREAD_STACK_MIN 16384
#endif

// Raw syscall passthrough and clone(); Horizon has no host syscalls, so these are
// -ENOSYS stubs in kuro_posix.c. box64 only reaches them for un-special-cased guest
// syscalls / thread creation, which M1 static guests don't exercise.
long syscall(long number, ...);
int  clone(int (*fn)(void *), void *stack, int flags, void *arg, ...);

// fcntl flags newlib lacks (Linux aarch64 values). O_LARGEFILE is a no-op (64-bit).
#include <fcntl.h>
#ifndef O_LARGEFILE
#define O_LARGEFILE 0
#endif
#ifndef O_NOATIME
#define O_NOATIME 01000000
#endif
#ifndef O_PATH
#define O_PATH 010000000
#endif
#ifndef O_TMPFILE
#define O_TMPFILE 020200000
#endif
#ifndef O_DIRECT
#define O_DIRECT 0200000
#endif

// NOTE: glibc large-file *64 aliases (stat64/open64/...) are intentionally NOT
// macro-aliased here — box64's wrapper tables use those names as struct members,
// so a blanket `#define name64 name` corrupts them. They belong with the wrapped-lib
// decoupling work (see docs/TODO.md), not the core build.

// glibc qsort_r comparator type (newlib has __compar_fn_t; qsort_r itself is GNU-compatible
// under _GNU_SOURCE) + linear-search funcs newlib's <search.h> omits (impl in kuro_posix.c).
#ifndef __compar_d_fn_t_defined
#define __compar_d_fn_t_defined
typedef int (*__compar_d_fn_t)(const void *, const void *, void *);
#endif
void *lsearch(const void *key, void *base, size_t *nelp, size_t width, int (*compar)(const void *, const void *));
void *lfind(const void *key, const void *base, size_t *nelp, size_t width, int (*compar)(const void *, const void *));

// glibc obstack <-> stdio extensions (implemented in kuro_obstack.c).
#include <stdarg.h>
struct obstack;
int obstack_printf(struct obstack *obstack, const char *fmt, ...);
int obstack_vprintf(struct obstack *obstack, const char *fmt, va_list ap);

// Advanced GNU/POSIX pthread APIs that libnx's pthread doesn't implement. box64's
// my_pthread_* wrappers call these; stubbed to -ENOSYS in kuro_posix.c (never reached
// by a single-threaded static guest). Declared after <pthread.h>/<sched.h> for the types.
#include <pthread.h>
#include <sched.h>
// This target ships no <sys/cpuset.h>, so cpu_set_t is undefined; provide the Linux layout.
#ifndef CPU_SETSIZE
#define CPU_SETSIZE 1024
typedef struct { unsigned long __bits[CPU_SETSIZE / (8 * sizeof(unsigned long))]; } cpu_set_t;
#endif
int pthread_attr_getinheritsched(const pthread_attr_t *attr, int *inheritsched);
int pthread_attr_getschedpolicy(const pthread_attr_t *attr, int *policy);
int pthread_attr_getscope(const pthread_attr_t *attr, int *scope);
int pthread_attr_setinheritsched(pthread_attr_t *attr, int inheritsched);
int pthread_attr_setschedpolicy(pthread_attr_t *attr, int policy);
int pthread_attr_setscope(pthread_attr_t *attr, int scope);
int pthread_attr_setaffinity_np(pthread_attr_t *attr, size_t cpusetsize, const cpu_set_t *cpuset);
int pthread_getattr_np(pthread_t thread, pthread_attr_t *attr);
int pthread_getattr_default_np(pthread_attr_t *attr);
int pthread_setattr_default_np(const pthread_attr_t *attr);
int pthread_getaffinity_np(pthread_t thread, size_t cpusetsize, cpu_set_t *cpuset);
int pthread_setaffinity_np(pthread_t thread, size_t cpusetsize, const cpu_set_t *cpuset);
int pthread_mutexattr_getprotocol(const pthread_mutexattr_t *attr, int *protocol);
int pthread_mutexattr_getrobust(const pthread_mutexattr_t *attr, int *robustness);
int pthread_mutexattr_setprioceiling(pthread_mutexattr_t *attr, int prioceiling);
int pthread_mutexattr_setprotocol(pthread_mutexattr_t *attr, int protocol);
int pthread_mutexattr_setrobust(pthread_mutexattr_t *attr, int robustness);

#endif // __SWITCH__
