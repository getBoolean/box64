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

void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
    return kuro_mmap(addr, length, prot, flags, fd, (ssize_t)offset);
}
int munmap(void *addr, size_t length) { return kuro_munmap(addr, length); }
// No real page-permission changes for the interpreter (heap-backed mmap); revisited in M1.2.
int mprotect(void *addr, size_t len, int prot) { (void)addr; (void)len; (void)prot; return 0; }
void *mremap(void *old_addr, size_t old_size, size_t new_size, int flags, ...) {
    (void)old_size; (void)flags; return kuro_mmap(old_addr, new_size, 0, MAP_ANONYMOUS, -1, 0);
}
int madvise(void *a, size_t l, int adv) { (void)a; (void)l; (void)adv; return 0; }
int msync(void *a, size_t l, int f) { (void)a; (void)l; (void)f; return 0; }
int mlock(const void *a, size_t l) { (void)a; (void)l; return 0; }
int munlock(const void *a, size_t l) { (void)a; (void)l; return 0; }

// --- dlopen stubs (Horizon has no dynamic loading; STATICBUILD never calls these at runtime) --
void *dlopen(const char *f, int fl) { (void)f; (void)fl; return NULL; }
int   dlclose(void *h) { (void)h; return 0; }
void *dlsym(void *h, const char *s) { (void)h; (void)s; return NULL; }
char *dlerror(void) { return (char *)"dlfcn unsupported on Horizon"; }
int   dladdr(const void *addr, Dl_info *info) { (void)addr; if (info) memset(info, 0, sizeof(*info)); return 0; }

// box64's --test self-test harness (test.c) is excluded from the Switch build; stub its entry so
// core.c still links (it's only reached in --test mode, which Horizon never enters).
int unittest(int argc, const char **argv) { (void)argc; (void)argv; return 0; }

#endif // __SWITCH__
