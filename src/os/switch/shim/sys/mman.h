// KurokoNX shim — <sys/mman.h> for the box64 Horizon port (newlib/devkitA64 has none).
// Provides the PROT_*/MAP_* constants and mmap-family declarations box64 references. Linux
// aarch64 values, so box64's flag handling stays consistent. Implementations live in kuro-posix.
#pragma once
#ifdef __SWITCH__

#include <stddef.h>
#include <sys/types.h>

#define PROT_NONE  0x0
#define PROT_READ  0x1
#define PROT_WRITE 0x2
#define PROT_EXEC  0x4

#define MAP_SHARED    0x01
#define MAP_PRIVATE   0x02
#define MAP_FIXED     0x10
#define MAP_ANONYMOUS 0x20
#define MAP_ANON      MAP_ANONYMOUS
#define MAP_32BIT     0x40
#define MAP_GROWSDOWN 0x0100
#define MAP_NORESERVE 0x4000
#define MAP_HUGETLB   0x40000
#define MAP_STACK     0x20000
#define MAP_FAILED    ((void*)-1)

// madvise / msync advice + flags (values box64 may pass; behavior is best-effort)
#define MADV_NORMAL     0
#define MADV_DONTNEED   4
#define MADV_FREE       8
#define MS_ASYNC        1
#define MS_SYNC         4
#define MS_INVALIDATE   2

#ifdef __cplusplus
extern "C" {
#endif

void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
int   munmap(void *addr, size_t length);
int   mprotect(void *addr, size_t len, int prot);
void *mremap(void *old_addr, size_t old_size, size_t new_size, int flags, ...);
int   madvise(void *addr, size_t length, int advice);
int   msync(void *addr, size_t length, int flags);
int   mlock(const void *addr, size_t len);
int   munlock(const void *addr, size_t len);

#ifdef __cplusplus
}
#endif

#endif // __SWITCH__
