// nx_libcache.c — RAM content cache for read-only libs/DLLs (Part 2 / Phase B). See nx_libcache.h.
//
// Cold DLL reads are SD-bandwidth-bound (~21 MB/s, Part-0 HW measurement); this makes repeated/concurrent/
// shared loads hit RAM. An eligible read-only file is read from the SD ONCE into an immutable heap blob
// keyed by (canonical host path, size, mtime); every later mmap-section / pread of it is a memcpy. Reads
// are lock-free after the map lookup (blob immutable once filled; an open fd pins its entry vs eviction).
// Serves only the offset-based paths (mmap-fill, pread) — libs are loaded that way, and offset-based
// serving needs no per-fd cursor (so no divergence risk vs the real fd position). Gate KX_NO_LIBCACHE.

#ifdef __SWITCH__

#include <switch.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/stat.h>

#include "nx_libcache.h"

extern int  nx_guest_pid(void);        // nx_posix.c — client vs in-process wineserver have separate fd tables
extern void nx_result_log(const char* msg);

#define NX_LIBCACHE_MAX 64             // distinct cached files
#define NX_LCFD_MAX     256            // live (pid,fd) associations

typedef struct {
    int           used, filling;
    int           refs;                // open fds referencing this entry (pins it vs eviction)
    char          host[512]; off_t size; long mtime;   // key
    uint8_t*      blob;                // immutable once filled (filling->0); NULL while filling / on failure
    unsigned long gen;                 // LRU: bumped on each use
} libc_ent;
static libc_ent g_lc[NX_LIBCACHE_MAX];
static struct { int pid, fd, ent; } g_lcfd[NX_LCFD_MAX];
static pthread_mutex_t g_lc_mx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  g_lc_cv = PTHREAD_COND_INITIALIZER;
static size_t g_lc_bytes = 0, g_lc_cap = 0;
static unsigned long g_lc_gen = 0;
static unsigned long g_lc_hits = 0, g_lc_misses = 0, g_lc_evict = 0;   // KX_REQLOG stats

static int nx_libcache_on(void) { static int on = -1; if (on < 0) on = getenv("KX_NO_LIBCACHE") ? 0 : 1; return on; }
static size_t nx_libcache_cap(void) {
    if (!g_lc_cap) { const char* c = getenv("KX_LIBCACHE_CAP_MB"); int mb = c ? atoi(c) : 128;
                     if (mb < 1) mb = 1; g_lc_cap = (size_t)mb * 1024 * 1024; }
    return g_lc_cap;
}
static off_t nx_libcache_perfile(void) {
    const char* c = getenv("KX_LIBCACHE_MAXFILE_MB"); int mb = c ? atoi(c) : 32;
    if (mb < 1) mb = 1; return (off_t)mb * 1024 * 1024;
}

// Eligible = a read-only regular staged file that stays constant during the run. Excludes writable opens,
// the runtime-rewritten registry, and materialized /proc,/dev pseudo-files (those live under sdmc:/box64/tmp,
// NOT rootfs/lib). /tmp never reaches here — it is the RAM tmpfs, intercepted before nx_translate_path.
static int lc_eligible(const char* host, int flags, const struct stat* st) {
    if (!host || !st) return 0;
    if ((flags & O_ACCMODE) != O_RDONLY) return 0;
    if (flags & (O_CREAT | O_TRUNC | O_APPEND)) return 0;
    if (!S_ISREG(st->st_mode)) return 0;
    if (st->st_size <= 0 || st->st_size > nx_libcache_perfile()) return 0;   // skip empty + oversized
    // Staged tree only (mirrors NX_ROOTFS/NX_LIBDIR in nx_posix.c). NB "sdmc:/box64/tmp" (materialized
    // /dev,/proc) is NOT under either prefix, so it is correctly excluded.
    if (strncmp(host, "sdmc:/box64/rootfs", 18) != 0 && strncmp(host, "sdmc:/box64/lib", 15) != 0) return 0;
    size_t hl = strlen(host);
    if (hl >= 4 && !strcmp(host + hl - 4, ".reg")) return 0;                 // registry is rewritten at runtime
    return 1;
}

// ---- entry table (g_lc_mx held) ------------------------------------------------------------------
static int lc_find(const char* host, off_t size, long mtime) {
    for (int i = 0; i < NX_LIBCACHE_MAX; i++)
        if (g_lc[i].used && g_lc[i].size == size && g_lc[i].mtime == mtime && !strcmp(g_lc[i].host, host))
            return i;
    return -1;
}
static void lc_drop(int e) {   // free the blob + slot
    if (g_lc[e].blob) { g_lc_bytes = (g_lc_bytes >= (size_t)g_lc[e].size) ? g_lc_bytes - (size_t)g_lc[e].size : 0;
                        free(g_lc[e].blob); }
    memset(&g_lc[e], 0, sizeof g_lc[e]);
}
// Make room for `need` bytes by LRU-evicting unreferenced, filled entries. Returns 1 if it now fits.
static int lc_evict_to_fit(size_t need) {
    if (need > nx_libcache_cap()) return 0;
    while (g_lc_bytes + need > nx_libcache_cap()) {
        int victim = -1; unsigned long lo = ~0UL;
        for (int i = 0; i < NX_LIBCACHE_MAX; i++)
            if (g_lc[i].used && !g_lc[i].filling && g_lc[i].refs == 0 && g_lc[i].blob && g_lc[i].gen < lo)
                { lo = g_lc[i].gen; victim = i; }
        if (victim < 0) return 0;               // everything is pinned/filling — can't fit
        lc_drop(victim); g_lc_evict++;
    }
    return 1;
}
static int lc_alloc(void) {   // a free slot (or LRU-evict one)
    for (int i = 0; i < NX_LIBCACHE_MAX; i++) if (!g_lc[i].used) return i;
    int victim = -1; unsigned long lo = ~0UL;
    for (int i = 0; i < NX_LIBCACHE_MAX; i++)
        if (!g_lc[i].filling && g_lc[i].refs == 0 && g_lc[i].gen < lo) { lo = g_lc[i].gen; victim = i; }
    if (victim >= 0) { lc_drop(victim); g_lc_evict++; return victim; }
    return -1;
}

// ---- (pid,fd) association (g_lc_mx held) ----------------------------------------------------------
static int lc_assoc_find(int pid, int fd) {
    for (int i = 0; i < NX_LCFD_MAX; i++) if (g_lcfd[i].ent >= 0 && g_lcfd[i].pid == pid && g_lcfd[i].fd == fd)
        return i;
    return -1;
}
static void lc_assoc_add(int pid, int fd, int ent) {   // g_lc_mx held; g_lcfd initialized (ent<0 = empty)
    int i = lc_assoc_find(pid, fd);            // overwrite a stale assoc (a missed close on a reused fd)
    if (i >= 0) { int old = g_lcfd[i].ent; if (old >= 0 && g_lc[old].refs > 0) g_lc[old].refs--;
                  g_lcfd[i].ent = ent; g_lc[ent].refs++; return; }
    for (i = 0; i < NX_LCFD_MAX; i++) if (g_lcfd[i].ent < 0) {
        g_lcfd[i].pid = pid; g_lcfd[i].fd = fd; g_lcfd[i].ent = ent; g_lc[ent].refs++; return;
    }
    // table full: leave this fd uncached (correct — it just won't be cache-served)
}

// g_lcfd uses "ent < 0 = empty"; initialize lazily (under g_lc_mx, so the one-shot is race-free).
static void lc_init(void) {
    static int done = 0;
    if (done) return;
    for (int i = 0; i < NX_LCFD_MAX; i++) g_lcfd[i].ent = -1;
    done = 1;
}

// Ensure entry `e`'s blob is filled (g_lc_mx held; releases the lock during the SD read). 1 = ready.
static int lc_fill_blob(const char* host, uint8_t* blob, size_t sz) {   // lock NOT held
    int fd = open(host, O_RDONLY);
    if (fd < 0) return 0;
    extern uint64_t nx_bench_tick(void); extern uint64_t g_t_sdread, g_n_sdread_bytes, g_n_sdread_ops;
    uint64_t _t = nx_bench_tick();
    size_t done = 0;
    while (done < sz) { ssize_t r = read(fd, blob + done, sz - done); if (r <= 0) break; done += (size_t)r; }
    g_t_sdread += nx_bench_tick() - _t; g_n_sdread_ops++; g_n_sdread_bytes += (uint64_t)done;
    close(fd);
    return done == sz;
}
static int lc_ensure_filled(int e) {   // g_lc_mx held
    if (g_lc[e].blob) return 1;
    if (g_lc[e].filling) { while (g_lc[e].filling) pthread_cond_wait(&g_lc_cv, &g_lc_mx); return g_lc[e].blob != NULL; }
    size_t sz = (size_t)g_lc[e].size;
    if (!lc_evict_to_fit(sz)) { g_lc_misses++; return 0; }     // over cap and can't evict — leave uncached
    g_lc[e].filling = 1;
    char host[512]; snprintf(host, sizeof host, "%s", g_lc[e].host);
    pthread_mutex_unlock(&g_lc_mx);
    uint8_t* blob = (uint8_t*)malloc(sz);
    int ok = blob && lc_fill_blob(host, blob, sz);
    pthread_mutex_lock(&g_lc_mx);
    if (ok) { g_lc[e].blob = blob; g_lc_bytes += sz; g_lc_misses++; }   // this cold fill counts as the miss
    else if (blob) free(blob);
    g_lc[e].filling = 0;
    pthread_cond_broadcast(&g_lc_cv);
    return g_lc[e].blob != NULL;
}

// ---- public API ----------------------------------------------------------------------------------
void nx_libcache_open(int fd, const char* host, const struct stat* st, int flags) {
    if (!nx_libcache_on() || fd < 0 || !lc_eligible(host, flags, st)) return;
    int pid = nx_guest_pid();
    pthread_mutex_lock(&g_lc_mx);
    lc_init();
    int e = lc_find(host, st->st_size, st->st_mtime);
    if (e < 0) {
        e = lc_alloc();
        if (e < 0) { pthread_mutex_unlock(&g_lc_mx); return; }   // no slot — uncached
        memset(&g_lc[e], 0, sizeof g_lc[e]);
        g_lc[e].used = 1;
        snprintf(g_lc[e].host, sizeof g_lc[e].host, "%s", host);
        g_lc[e].size = st->st_size; g_lc[e].mtime = st->st_mtime;
    }
    g_lc[e].gen = ++g_lc_gen;
    lc_assoc_add(pid, fd, e);                 // refs++ (pins the entry while this fd is open); lazy fill later
    pthread_mutex_unlock(&g_lc_mx);
}

// Shared serve helper: look up (pid,fd)->entry, ensure filled, hand back the immutable blob + size.
static const uint8_t* lc_lookup_blob(int fd, off_t* out_sz) {
    if (!nx_libcache_on()) return NULL;
    int pid = nx_guest_pid();
    pthread_mutex_lock(&g_lc_mx);
    lc_init();
    int a = lc_assoc_find(pid, fd);
    if (a < 0) { pthread_mutex_unlock(&g_lc_mx); return NULL; }
    int e = g_lcfd[a].ent;
    if (!lc_ensure_filled(e)) { pthread_mutex_unlock(&g_lc_mx); return NULL; }
    g_lc[e].gen = ++g_lc_gen; g_lc_hits++;
    const uint8_t* blob = g_lc[e].blob; *out_sz = g_lc[e].size;   // immutable + pinned (refs>0) => safe after unlock
    pthread_mutex_unlock(&g_lc_mx);
    return blob;
}

int nx_libcache_mmap_fill(int fd, void* dst, size_t len, off_t off) {
    off_t sz;
    const uint8_t* blob = lc_lookup_blob(fd, &sz);
    if (!blob) return 0;
    size_t avail = (off >= 0 && off < sz) ? (size_t)(sz - off) : 0;
    size_t k = len < avail ? len : avail;
    if (k) memcpy(dst, blob + off, k);
    if (k < len) memset((char*)dst + k, 0, len - k);   // tail past EOF = bss (zero), matching the SD path
    return 1;
}

int nx_libcache_pread(int fd, void* buf, size_t n, off_t off, long* served) {
    off_t sz;
    const uint8_t* blob = lc_lookup_blob(fd, &sz);
    if (!blob) return 0;
    size_t avail = (off >= 0 && off < sz) ? (size_t)(sz - off) : 0;
    size_t k = n < avail ? n : avail;
    if (k) memcpy(buf, blob + off, k);
    *served = (long)k;
    return 1;
}

void nx_libcache_forget(int fd) {
    if (!nx_libcache_on()) return;
    int pid = nx_guest_pid();
    pthread_mutex_lock(&g_lc_mx);
    lc_init();
    int a = lc_assoc_find(pid, fd);
    if (a >= 0) { int e = g_lcfd[a].ent; if (e >= 0 && g_lc[e].refs > 0) g_lc[e].refs--;
                  g_lcfd[a].pid = 0; g_lcfd[a].fd = 0; g_lcfd[a].ent = -1; }
    pthread_mutex_unlock(&g_lc_mx);
}

void nx_libcache_invalidate(const char* host) {
    if (!nx_libcache_on() || !host) return;
    pthread_mutex_lock(&g_lc_mx);
    lc_init();
    for (int i = 0; i < NX_LIBCACHE_MAX; i++)
        if (g_lc[i].used && !g_lc[i].filling && !strcmp(g_lc[i].host, host)) lc_drop(i);
    pthread_mutex_unlock(&g_lc_mx);
}

// KX_REQLOG one-line dump at guest exit (called from nx_ipc_stats_dump).
void nx_libcache_stats_dump(void) {
    if (!getenv("KX_REQLOG")) return;
    char b[160];
    snprintf(b, sizeof b, "nx_libcache: hits=%lu misses=%lu evict=%lu bytes=%lu cap_mb=%lu",
             g_lc_hits, g_lc_misses, g_lc_evict, (unsigned long)g_lc_bytes, (unsigned long)(nx_libcache_cap() >> 20));
    nx_result_log(b);
}

#endif // __SWITCH__
