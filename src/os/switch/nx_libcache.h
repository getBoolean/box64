// nx_libcache.h — RAM content cache for read-only libs/DLLs (Part 2 / Phase B). See nx_libcache.c.
//
// A single cold DLL/section read is SD-bandwidth-bound (~21 MB/s on real HW — Part-0 measurement), so the
// only way to beat it for REPEATED / CONCURRENT / SHARED loads (many threads or the client+wineserver both
// loading the same libc/ntdll) is to keep the content in RAM: read each eligible file from the SD ONCE,
// then serve every later mmap-section / positioned read as a pure memcpy. Offset-based paths only
// (mmap-fill + pread) — both are self-contained, so there is no per-fd cursor to keep in sync (libs are
// loaded via mmap+pread, never sequential read()). Gate KX_NO_LIBCACHE; cap KX_LIBCACHE_CAP_MB.
#pragma once
#ifdef __SWITCH__

#include <stddef.h>
#include <sys/types.h>
struct stat;

#ifdef __cplusplus
extern "C" {
#endif

// Associate an eligible read-only lib fd with a cache entry (lazy — the blob fills on first access, not
// here, so Wine's open+stat+close DLL-search probes cost nothing). `host` = resolved sdmc: path, `st` =
// its stat (size/mtime key), `flags` = host open flags. No-op if the cache is off or the file ineligible.
void nx_libcache_open(int fd, const char* host, const struct stat* st, int flags);
// Serve a positioned read from the blob if fd is cached (filling it on first touch). 1 = served (*served
// = bytes copied), 0 = not cached (caller does the SD read).
int  nx_libcache_pread(int fd, void* buf, size_t n, off_t off, long* served);
// Fill a MAP_PRIVATE mapping region from the blob if fd is cached: memcpy blob[off..) into dst, zero the
// tail past EOF (bss). 1 = filled (no SD), 0 = not cached (caller does the SD read loop).
int  nx_libcache_mmap_fill(int fd, void* dst, size_t len, off_t off);
void nx_libcache_forget(int fd);                 // drop the (pid,fd) association (on close)
void nx_libcache_invalidate(const char* host);   // drop the entry for host (on unlink/rename/writable open)

#ifdef __cplusplus
}
#endif

#endif // __SWITCH__
