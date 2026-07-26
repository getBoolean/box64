// nx_fsfunnel.c — SD I/O funnel (box64-nx). See nx_fsfunnel.h for the WHY.
//
// A bounded FIFO drained by a small dedicated worker-thread pool (default N=1). A guest thread that
// needs a real fsdev metadata op builds a stack request, enqueues it, and blocks on a per-request
// futex word; the worker pops the queue, runs ONLY raw newlib (its errno/_reent are per-pthread,
// fsdev is process-global — proven by nx_main.c's guest-log writer), records the result, and wakes
// the one owner. Submission thus becomes ORDERED and DE-OVERSUBSCRIBED (one thread touches the SD),
// which removes the anti-scale penalty (goal: T=12 ~ T=1 instead of worse).
//
// House style mirrors nx_vfd.c: static state + pthread mutex/cond for the queue, and the exact
// svcWaitForAddress/svcSignalToAddress address-arbiter idiom nx_posix.c uses for the futex (NR 98)
// and the CLONE_CHILD_CLEARTID handshake, here as the completion signal.
//
// Gate: KX_NO_FSFUNNEL (default ON; set => byte-for-byte direct A/B). Tunables: KX_FSFUNNEL_WORKERS
// (default 1), KX_FSFUNNEL_QDEPTH (default 64).

#ifdef __SWITCH__

#include <switch.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <pthread.h>
#include <sys/stat.h>

#include "nx_fsfunnel.h"

// From the caller modules — the worker calls these for ops that need box64 state (rootfs macros /
// IPC counters / the metadata governor). nx_result_log writes one heap-free line to box64-result.txt
// (survives on real HW — the funnel's "active" proof channel, like the nx_vm backend banner).
extern void nx_meta_governor(void);
extern void nx_result_log(const char* msg);

// ---- request -------------------------------------------------------------------------------------

typedef enum {
    FSOP_RESOLVE, FSOP_OPEN, FSOP_STAT, FSOP_MKDIR, FSOP_UNLINK,
    FSOP_RMDIR, FSOP_RENAME, FSOP_GETDENTS, FSOP_FTRUNCATE, FSOP_CLOSE
} fsop_t;

// Stack-allocated by the producer; its lifetime spans the blocking call (the producer does not return
// until `done`), so no field ever outlives its owner and nothing is heap-allocated for the request.
typedef struct {
    fsop_t       op;
    const char*  path;                                  // primary host/guest path
    const char*  path2;                                 // FSOP_RENAME target
    int          fd;
    int          flags;
    mode_t       mode;
    off_t        off;                                   // FSOP_FTRUNCATE length
    char*        host;   size_t hostn;                  // FSOP_RESOLVE: host-path out buffer
    int*         p_exists; int* p_isdir; struct stat* p_st;  // FSOP_RESOLVE outputs
    struct stat* stbuf;                                 // FSOP_STAT out
    nx_dent_t**  p_dents; int* p_dn; int* p_dcap;       // FSOP_GETDENTS outputs
    long         ret;                                   // op result (worker -> producer)
    int          err;                                   // captured host errno (worker -> producer)
    int          done;                                  // completion futex word (0 -> 1); 4-byte aligned
} fsreq_t;

// ---- config / lazy init --------------------------------------------------------------------------

#define NX_FSQ_DEPTH_MAX   256
#define NX_FSQ_WORKERS_MAX 8

static int      g_nworkers = 1;
static unsigned g_qdepth   = 64;

static int fsfunnel_enabled(void) {           // KX_NO_FSFUNNEL: default ON (matches the governors/cache)
    static int on = -1;
    if (on < 0) on = getenv("KX_NO_FSFUNNEL") ? 0 : 1;
    return on;
}

// ---- queue: bounded ring, producer/consumer with backpressure ------------------------------------

static fsreq_t*       g_ring[NX_FSQ_DEPTH_MAX];
static unsigned       g_head = 0, g_tail = 0, g_count = 0;   // indices always in [0, g_qdepth)
static pthread_mutex_t g_fsq_mx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  g_fsq_ne = PTHREAD_COND_INITIALIZER;  // "not empty" — workers wait
static pthread_cond_t  g_fsq_nf = PTHREAD_COND_INITIALIZER;  // "not full"  — producers wait (backpressure)

static __thread int g_in_worker = 0;
int nx_fs_in_worker(void) { return g_in_worker; }

static void fsq_submit(fsreq_t* r) {
    pthread_mutex_lock(&g_fsq_mx);
    while (g_count == g_qdepth) pthread_cond_wait(&g_fsq_nf, &g_fsq_mx);   // full: backpressure
    g_ring[g_tail] = r;
    g_tail = (g_tail + 1) % g_qdepth;
    g_count++;
    pthread_cond_signal(&g_fsq_ne);
    pthread_mutex_unlock(&g_fsq_mx);
}

// ---- op bodies (run on the worker, or inline on the direct path) ---------------------------------

// The opendir->readdir*->closedir enumeration MUST be one job: a DIR* handle can't cross threads
// mid-iteration. Byte-for-byte the old nx_vfd_getdents64 snapshot loop, plus its metadata governor.
// Hands back a malloc'd nx_dent_t[] + count + capacity; the dosdevices synth stays on the vfd thread.
static long fs_getdents_body(const char* host, nx_dent_t** out_dents, int* out_n, int* out_cap) {
    nx_meta_governor();
    DIR* d = opendir(host);
    if (!d) { errno = ENOENT; return -1; }
    int cap = 64, n = 0;
    nx_dent_t* dents = (nx_dent_t*)malloc((size_t)cap * sizeof(nx_dent_t));
    if (!dents) { closedir(d); errno = ENOMEM; return -1; }
    struct dirent* e;
    while ((e = readdir(d))) {
        if (n == cap) {
            int nc = cap * 2;
            nx_dent_t* nn = (nx_dent_t*)realloc(dents, (size_t)nc * sizeof(nx_dent_t));
            if (!nn) break;                  // OOM: serve what we captured
            dents = nn; cap = nc;
        }
        snprintf(dents[n].name, sizeof dents[0].name, "%s", e->d_name);
        unsigned char t = 0;                 // DT_UNKNOWN
#ifdef DT_DIR
        if (e->d_type == DT_DIR) t = 4; else if (e->d_type == DT_REG) t = 8;
#endif
        dents[n].type = t;
        n++;
    }
    closedir(d);                             // release the fsdev handle NOW
    *out_dents = dents; *out_n = n; *out_cap = cap;
    return 0;
}

static void fsreq_run(fsreq_t* r) {
    switch (r->op) {
        case FSOP_RESOLVE:   r->ret = nx_fs_resolve_direct(r->path, r->host, r->hostn,
                                                           r->p_exists, r->p_isdir, r->p_st); break;
        case FSOP_OPEN:      r->ret = open(r->path, r->flags, r->mode);        break;
        case FSOP_STAT:      r->ret = stat(r->path, r->stbuf);                 break;
        case FSOP_MKDIR:     r->ret = mkdir(r->path, r->mode);                 break;
        case FSOP_UNLINK:    r->ret = unlink(r->path);                         break;
        case FSOP_RMDIR:     r->ret = rmdir(r->path);                          break;
        case FSOP_RENAME:    r->ret = nx_fs_rename_direct(r->path, r->path2);  break;
        case FSOP_GETDENTS:  r->ret = fs_getdents_body(r->path, r->p_dents, r->p_dn, r->p_dcap); break;
        case FSOP_FTRUNCATE: r->ret = ftruncate(r->fd, r->off);               break;
        case FSOP_CLOSE:     r->ret = close(r->fd);                            break;
        default:             r->ret = -1; errno = ENOSYS;                      break;
    }
    r->err = errno;   // captured on the worker's per-pthread errno; the producer copies it back on failure
}

static void* fs_worker(void* arg) {
    (void)arg;
    g_in_worker = 1;                          // a nested nx_fs_* from a job body then bypasses to direct
    for (;;) {
        pthread_mutex_lock(&g_fsq_mx);
        while (g_count == 0) pthread_cond_wait(&g_fsq_ne, &g_fsq_mx);
        fsreq_t* r = g_ring[g_head];
        g_head = (g_head + 1) % g_qdepth;
        g_count--;
        pthread_cond_signal(&g_fsq_nf);
        pthread_mutex_unlock(&g_fsq_mx);

        fsreq_run(r);

        // Publish result then wake exactly the one owner (no broadcast thundering-herd). The RELEASE
        // store pairs with the producer's ACQUIRE load so ret/err/out-params are visible after the wait.
        __atomic_store_n(&r->done, 1, __ATOMIC_RELEASE);
        svcSignalToAddress(&r->done, SignalType_Signal, 0, 1);
    }
    return NULL;
}

// ---- lazy init -----------------------------------------------------------------------------------

static pthread_mutex_t g_init_mx = PTHREAD_MUTEX_INITIALIZER;
static int g_ready = 0, g_broken = 0;

static void fsfunnel_read_tunables(void) {
    const char* w = getenv("KX_FSFUNNEL_WORKERS");
    int nw = w ? atoi(w) : 1;
    if (nw < 1) nw = 1;
    if (nw > NX_FSQ_WORKERS_MAX) nw = NX_FSQ_WORKERS_MAX;
    g_nworkers = nw;

    const char* q = getenv("KX_FSFUNNEL_QDEPTH");
    int qd = q ? atoi(q) : 64;
    if (qd < 1) qd = 1;
    if (qd > NX_FSQ_DEPTH_MAX) qd = NX_FSQ_DEPTH_MAX;
    g_qdepth = (unsigned)qd;
}

// Spawn N detached workers with a >=1 MiB host stack (nx_spawn.c / clone() use the same). Returns the
// number actually created; 0 => the caller latches g_broken and every wrapper degrades to direct.
static int fsfunnel_spawn(void) {
    fsfunnel_read_tunables();
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, 1u << 20);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    int made = 0;
    for (int i = 0; i < g_nworkers; i++) {
        pthread_t th;
        if (pthread_create(&th, &attr, fs_worker, NULL) != 0) break;   // thread-slot pressure -> degrade
        made++;
    }
    pthread_attr_destroy(&attr);
    return made;
}

static int fsfunnel_ensure(void) {
    if (__atomic_load_n(&g_ready,  __ATOMIC_ACQUIRE)) return 1;
    if (__atomic_load_n(&g_broken, __ATOMIC_ACQUIRE)) return 0;
    int became = 0;   // 1 = ready, 2 = broken (log after unlock — nx_result_log does file I/O)
    pthread_mutex_lock(&g_init_mx);
    if (!g_ready && !g_broken) {
        int made = fsfunnel_spawn();
        if (made > 0) { g_nworkers = made; __atomic_store_n(&g_ready,  1, __ATOMIC_RELEASE); became = 1; }
        else          {                    __atomic_store_n(&g_broken, 1, __ATOMIC_RELEASE); became = 2; }
    }
    int ready = g_ready;
    pthread_mutex_unlock(&g_init_mx);
    if (became == 1) { char b[96]; snprintf(b, sizeof b, "nx_fsfunnel: %d worker(s) qdepth=%u ready",
                                            g_nworkers, g_qdepth); nx_result_log(b); }
    else if (became == 2) nx_result_log("nx_fsfunnel: init FAILED -> direct calls");
    return ready;
}

static int fsfunnel_on(void) {
    if (!fsfunnel_enabled()) return 0;   // short-circuits BEFORE init on the KX_NO_FSFUNNEL A/B path
    return fsfunnel_ensure();
}

// ---- dispatch + wrappers -------------------------------------------------------------------------

static long fsreq_dispatch(fsreq_t* r) {
    if (!fsfunnel_on() || g_in_worker) {
        fsreq_run(r);                        // direct: run on this thread (funnel off / already a worker)
    } else {
        r->done = 0;
        fsq_submit(r);
        // WaitIfEqual re-reads *done in-kernel, so a worker that finished before we sleep returns us
        // immediately (InvalidState) — no lost wakeup. Loop on the ACQUIRE load to pair with the store.
        while (__atomic_load_n(&r->done, __ATOMIC_ACQUIRE) == 0)
            svcWaitForAddress(&r->done, ArbitrationType_WaitIfEqual, 0, -1);
    }
    // Restore the HOST errno the op left, but only on failure — a successful op must leave the caller's
    // errno untouched (matches a direct call). ret<0 covers every failure: fd<0, -1, or getdents -1.
    if (r->ret < 0) errno = r->err;
    return r->ret;
}

int nx_fs_resolve(const char* guest, char* out, size_t outn, int* exists, int* isdir, struct stat* st) {
    fsreq_t r; memset(&r, 0, sizeof r);
    r.op = FSOP_RESOLVE; r.path = guest; r.host = out; r.hostn = outn;
    r.p_exists = exists; r.p_isdir = isdir; r.p_st = st;
    return (int)fsreq_dispatch(&r);          // nx_fs_resolve_direct returns 0 on the miss path (never <0)
}
int nx_fs_open(const char* host, int flags, mode_t mode) {
    fsreq_t r; memset(&r, 0, sizeof r);
    r.op = FSOP_OPEN; r.path = host; r.flags = flags; r.mode = mode;
    return (int)fsreq_dispatch(&r);
}
int nx_fs_stat(const char* host, struct stat* st) {
    fsreq_t r; memset(&r, 0, sizeof r);
    r.op = FSOP_STAT; r.path = host; r.stbuf = st;
    return (int)fsreq_dispatch(&r);
}
int nx_fs_mkdir(const char* host, mode_t mode) {
    fsreq_t r; memset(&r, 0, sizeof r);
    r.op = FSOP_MKDIR; r.path = host; r.mode = mode;
    return (int)fsreq_dispatch(&r);
}
int nx_fs_unlink(const char* host) {
    fsreq_t r; memset(&r, 0, sizeof r);
    r.op = FSOP_UNLINK; r.path = host;
    return (int)fsreq_dispatch(&r);
}
int nx_fs_rmdir(const char* host) {
    fsreq_t r; memset(&r, 0, sizeof r);
    r.op = FSOP_RMDIR; r.path = host;
    return (int)fsreq_dispatch(&r);
}
int nx_fs_rename(const char* host_a, const char* host_b) {
    fsreq_t r; memset(&r, 0, sizeof r);
    r.op = FSOP_RENAME; r.path = host_a; r.path2 = host_b;
    return (int)fsreq_dispatch(&r);
}
long nx_fs_getdents(const char* host, nx_dent_t** dents, int* n, int* cap) {
    fsreq_t r; memset(&r, 0, sizeof r);
    r.op = FSOP_GETDENTS; r.path = host; r.p_dents = dents; r.p_dn = n; r.p_dcap = cap;
    return fsreq_dispatch(&r);
}
int nx_fs_ftruncate(int fd, off_t len) {
    fsreq_t r; memset(&r, 0, sizeof r);
    r.op = FSOP_FTRUNCATE; r.fd = fd; r.off = len;
    return (int)fsreq_dispatch(&r);
}
int nx_fs_close(int fd) {
    fsreq_t r; memset(&r, 0, sizeof r);
    r.op = FSOP_CLOSE; r.fd = fd;
    return (int)fsreq_dispatch(&r);
}

#endif // __SWITCH__
