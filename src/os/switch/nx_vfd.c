// nx_vfd.c — M2.5: virtual file descriptors for the Horizon Linux libos.
//
// Horizon/newlib cannot open() directories, has no pipes, and has no AF_UNIX sockets — but Wine's
// startup and the wineserver protocol need all three (opendir on the server dir, a signal pipe,
// and the request socket with SCM_RIGHTS fd-passing). Everything here is IN-PROCESS: box64-nx runs
// wineserver as a guest thread in the same Horizon process (M2.5 process-model decision), so a
// "unix socket" is a mutex-guarded ring buffer pair and "fd passing" hands over a number in the
// SHARED fd table (vfds are refcounted; real fds are dup'd so sender-close doesn't kill them).
//
// Virtual fds live at NX_VFD_BASE+ so they can never collide with newlib fds. Consumers:
//  - nx_posix.c syscall(): openat(dir detect), close, getdents64, fchdir, ppoll, socket family
//  - x64syscall.c: nx_x64_precase() — the x86-64 NRs that fall to box64's big switch and would
//    otherwise call newlib with raw fds/paths (read/write/close/poll/pipe/mkdir/unlink/...)
//  - wrappedlibc.c: my_fstat/my_stat/my_lstat hooks
//
// Errnos here are HOST (newlib) values — the x64Syscall return seams translate to Linux (M2.3).

#ifdef __SWITCH__

#include <switch.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/time.h>

// nx_posix.c
extern int  nx_translate_path(const char* p, char* out, size_t outn);
extern char* nx_cwd_buf(void);   // nx_posix.c — per-instance guest cwd
extern int  nx_guest_pid(void);
void nx_guest_output(int fd, const void *buf, size_t len);   // nx_main.c

static void vlog(const char* fmt, ...) {
    char b[256]; va_list ap; va_start(ap, fmt);
    int n = vsnprintf(b, sizeof b, fmt, ap); va_end(ap);
    if (n > 0) svcOutputDebugString(b, (size_t)n);
}

#define NX_VFD_BASE 0x40000000
#define NX_VFD_MAX  256
#define RING_CAP    (256*1024)
#define FDQ_MAX     32

// VK_LOCK / VK_SHMEM (M2.5): the wineserver runtime files (lock, tmpmap-*) that the client and the
// in-process wineserver share. fsdev can't open the same file from both instances (2nd open -> EIO)
// and file-backed mmap copies per instance, so back them with IN-PROCESS shared state keyed by path.
typedef enum { VK_FREE = 0, VK_DIR, VK_PIPE, VK_SOCK, VK_LISTEN, VK_LOCK, VK_SHMEM } vkind_t;

typedef struct { int fd; uint64_t at; } fdpass_t;

// A backing object shared by all vfds that opened the same wineserver runtime path.
typedef struct {
    int      refs;                // open vfds referencing it (0 = free)
    char     path[256];
    uint8_t* mem;                 // VK_SHMEM: page-aligned shared buffer (guest RAM); NULL until sized
    size_t   size;
    int      lock_owner;          // VK_LOCK: guest pid holding LOCK_EX (0 = unlocked)
} shobj_t;
#define NX_SHOBJ_MAX 48
static shobj_t g_sh[NX_SHOBJ_MAX];

typedef struct {
    vkind_t  kind;
    int      refs;
    int      nonblock;
    unsigned ino;                 // synthetic identity for fstat
    // VK_DIR
    DIR*     d;
    char     host[512];
    char     guest[512];
    // VK_PIPE / VK_SOCK: inbound ring (the PEER writes into it)
    uint8_t* buf;                 // lazy RING_CAP
    size_t   rd, wr;              // rd<=wr, used=wr-rd (absolute counters, mod on access)
    fdpass_t fdq[FDQ_MAX];        // SCM_RIGHTS queue: fd visible once rd (bytes consumed) > at
    int      fdq_n;
    int      peer;                // slot idx, -1 = closed/never
    int      pid;                 // creator's guest pid (SO_PEERCRED)
    // VK_SOCK bound / VK_LISTEN
    char     bpath[256];
    int      backlog[8];
    int      backlog_n;
    // VK_LOCK / VK_SHMEM
    int      shobj;               // index into g_sh
    size_t   fpos;                // per-fd position (shmem read/write/lseek)
} vfd_t;

static vfd_t g_v[NX_VFD_MAX];
static pthread_mutex_t g_mx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  g_cv = PTHREAD_COND_INITIALIZER;   // broadcast on ANY state change
static unsigned g_ino_next = 0x1000;

static inline int  is_vfd(int fd)  { return fd >= NX_VFD_BASE && fd < NX_VFD_BASE + NX_VFD_MAX; }
static inline vfd_t* V(int fd)     { return &g_v[fd - NX_VFD_BASE]; }
static inline size_t rused(vfd_t* v){ return v->wr - v->rd; }

int nx_vfd_is(int fd) { return is_vfd(fd) && g_v[fd - NX_VFD_BASE].kind != VK_FREE; }

static int slot_alloc(void) {          // g_mx held
    for (int i = 0; i < NX_VFD_MAX; i++)
        if (g_v[i].kind == VK_FREE) {
            memset(&g_v[i], 0, sizeof g_v[i]);
            g_v[i].refs = 1; g_v[i].peer = -1;
            g_v[i].ino  = g_ino_next++;
            return i;
        }
    return -1;
}

// ---- directories -------------------------------------------------------------------------------

int nx_vfd_open_dir(const char* guest, const char* host) {
    pthread_mutex_lock(&g_mx);
    int i = slot_alloc();
    if (i < 0) { pthread_mutex_unlock(&g_mx); errno = EMFILE; return -1; }
    vfd_t* v = &g_v[i];
    v->kind = VK_DIR;
    snprintf(v->host,  sizeof v->host,  "%s", host);
    snprintf(v->guest, sizeof v->guest, "%s", guest ? guest : host);
    pthread_mutex_unlock(&g_mx);
    return NX_VFD_BASE + i;
}

const char* nx_vfd_dir_host(int fd)  { return nx_vfd_is(fd) ? V(fd)->host  : NULL; }
const char* nx_vfd_dir_guest(int fd) { return nx_vfd_is(fd) ? V(fd)->guest : NULL; }

int nx_vfd_fchdir(int fd) {
    if (!nx_vfd_is(fd) || V(fd)->kind != VK_DIR) { errno = ENOTDIR; return -1; }
    snprintf(nx_cwd_buf(), 512, "%s", V(fd)->guest);
    return 0;
}

// Linux getdents64 layout (x86-64): d_ino u64, d_off s64, d_reclen u16, d_type u8, name...
long nx_vfd_getdents64(int fd, void* ubuf, size_t count) {
    if (!nx_vfd_is(fd)) { errno = EBADF; return -1; }
    vfd_t* v = V(fd);
    if (v->kind != VK_DIR) { errno = ENOTDIR; return -1; }
    if (!v->d) { v->d = opendir(v->host); if (!v->d) { errno = ENOENT; return -1; } }
    uint8_t* out = (uint8_t*)ubuf; size_t off = 0; long ord = 1;
    for (;;) {
        struct dirent* e = readdir(v->d);
        if (!e) break;
        size_t nl = strlen(e->d_name);
        size_t rl = (19 + nl + 1 + 7) & ~(size_t)7;
        if (off + rl > count) {
            // no space left: readdir has no pushback on fsdev, so the entry is dropped for this
            // pass (Wine/glibc read with 4KB+ buffers — a single entry always fits in practice);
            // if we couldn't fit even one, report EINVAL like Linux
            if (off == 0) { errno = EINVAL; return -1; }
            break;
        }
        *(uint64_t*)(out + off)      = v->ino + (unsigned)ord;
        *(int64_t*) (out + off + 8)  = ord++;
        *(uint16_t*)(out + off + 16) = (uint16_t)rl;
        unsigned char t = 0;                 // DT_UNKNOWN
#ifdef DT_DIR
        if (e->d_type == DT_DIR) t = 4; else if (e->d_type == DT_REG) t = 8;
#endif
        out[off + 18] = t;
        memcpy(out + off + 19, e->d_name, nl + 1);
        off += rl;
    }
    return (long)off;
}

// FNV-1a 64 of the host path — MUST match nx_posix.c fstatat's identity so a dir opened as a vfd and
// fstat'd yields the same (dev,ino) as stat(path). wineserver's post-chdir check compares them.
static unsigned long path_ino(const char* hp) {
    unsigned long h = 1469598103934665603UL;
    for (const char* c = hp; c && *c; ++c) { h ^= (unsigned char)*c; h *= 1099511628211UL; }
    return h ? h : 1;
}

// host-format stat for a vfd (caller converts to guest layout via UnalignStat64)
int nx_vfd_stat(int fd, struct stat* st) {
    if (!nx_vfd_is(fd)) { errno = EBADF; return -1; }
    vfd_t* v = V(fd);
    if (v->kind == VK_DIR) {
        int r = stat(v->host, st);
        if (r == 0) {
            st->st_dev = 1; st->st_ino = path_ino(v->host);   // == fstatat's hash of the same host path
            st->st_uid = 0; st->st_gid = 0; st->st_mode &= ~(mode_t)077;
        }
        return r;
    }
    memset(st, 0, sizeof *st);
    st->st_dev = 1; st->st_ino = v->ino; st->st_nlink = 1;
    st->st_blksize = 4096;
    if (v->kind == VK_SHMEM || v->kind == VK_LOCK) {
        st->st_mode = S_IFREG | 0600;
        st->st_size = (v->shobj >= 0) ? (off_t)g_sh[v->shobj].size : 0;
    } else {
        st->st_mode = (v->kind == VK_PIPE) ? (S_IFIFO | 0600) : (S_IFSOCK | 0777);
    }
    return 0;
}

// ---- VK_LOCK / VK_SHMEM: shared wineserver runtime files ---------------------------------------

// find-or-create a backing object for `path` (g_mx held); refs++
static int shobj_get(const char* path) {
    for (int i = 0; i < NX_SHOBJ_MAX; i++)
        if (g_sh[i].refs && !strcmp(g_sh[i].path, path)) { g_sh[i].refs++; return i; }
    for (int i = 0; i < NX_SHOBJ_MAX; i++)
        if (!g_sh[i].refs) { memset(&g_sh[i], 0, sizeof g_sh[i]); g_sh[i].refs = 1;
                             snprintf(g_sh[i].path, sizeof g_sh[i].path, "%s", path); return i; }
    return -1;
}

// Open a wineserver runtime file (lock or tmpmap-*) as a shared vfd. is_lock selects VK_LOCK vs SHMEM.
int nx_vfd_open_shared(const char* guestpath, int is_lock) {
    pthread_mutex_lock(&g_mx);
    int i = slot_alloc();
    if (i < 0) { pthread_mutex_unlock(&g_mx); errno = EMFILE; return -1; }
    int si = shobj_get(guestpath);
    if (si < 0) { g_v[i].kind = VK_FREE; pthread_mutex_unlock(&g_mx); errno = ENFILE; return -1; }
    g_v[i].kind  = is_lock ? VK_LOCK : VK_SHMEM;
    g_v[i].shobj = si;
    g_v[i].fpos  = 0;
    pthread_mutex_unlock(&g_mx);
    vlog("nx_vfd: open %s '%s' -> vfd=%d pid=%d\n", is_lock ? "LOCK" : "SHMEM",
         guestpath, NX_VFD_BASE + i, nx_guest_pid());
    return NX_VFD_BASE + i;
}

// flock(fd, op): LOCK_SH=1, LOCK_EX=2, LOCK_UN=8, LOCK_NB=4. Wine's server holds LOCK_EX on the lock
// file; a client's LOCK_EX|LOCK_NB then fails EWOULDBLOCK ("server is running"), which is how it
// decides to connect instead of starting a server. In-process pid-owned lock (no fsdev).
int nx_vfd_flock(int fd, int op) {
    if (!nx_vfd_is(fd) || V(fd)->kind != VK_LOCK) { errno = EBADF; return -1; }
    pthread_mutex_lock(&g_mx);
    shobj_t* o = &g_sh[V(fd)->shobj];
    int pid = nx_guest_pid();
    int r = 0;
    if (op & 8) {                                   // LOCK_UN
        if (o->lock_owner == pid) o->lock_owner = 0;
    } else if (op & 3) {                            // LOCK_SH or LOCK_EX
        if (o->lock_owner && o->lock_owner != pid) { errno = EWOULDBLOCK; r = -1; }
        else o->lock_owner = pid;
    }
    pthread_mutex_unlock(&g_mx);
    vlog("nx_vfd: flock vfd=%d op=%d pid=%d owner=%d -> %d\n", fd, op, pid, o->lock_owner, r);
    return r;
}

// Ensure a VK_SHMEM object has a page-aligned shared buffer of at least `need` bytes (guest RAM).
// The buffer is allocated ONCE at its final size (ftruncate/first mmap set it) so the pointer is
// stable — both instances' mmaps return the SAME address, giving real shared memory in the one AS.
extern void* nx_mmap(void* addr, unsigned long length, int prot, int flags, int fd, ssize_t offset);
extern void  setProtection(uintptr_t addr, size_t size, uint32_t prot);
static int shmem_ensure(shobj_t* o, size_t need) {   // g_mx held
    if (o->mem && o->size >= need) return 0;
    if (o->mem) return 0;                            // already allocated (don't move — would break maps)
    size_t sz = (need + 0xffff) & ~(size_t)0xffff;   // 64KB granularity
    if (sz < 0x10000) sz = 0x10000;
    void* p = nx_mmap(NULL, sz, 3 /*RW*/, 0x22 /*MAP_ANON|PRIVATE*/, -1, 0);
    if (p == (void*)-1) { errno = ENOMEM; return -1; }
    setProtection((uintptr_t)p, sz, 3);
    o->mem = (uint8_t*)p; o->size = sz;
    return 0;
}

int nx_vfd_ftruncate(int fd, off_t len) {
    if (!nx_vfd_is(fd) || V(fd)->kind != VK_SHMEM) { errno = EINVAL; return -1; }
    pthread_mutex_lock(&g_mx);
    int r = shmem_ensure(&g_sh[V(fd)->shobj], (size_t)len);
    pthread_mutex_unlock(&g_mx);
    return r;
}

// mmap of a VK_SHMEM fd: return the shared buffer + offset (same address for every mapper).
void* nx_vfd_mmap(int fd, size_t length, off_t offset) {
    if (!nx_vfd_is(fd) || V(fd)->kind != VK_SHMEM) { errno = EACCES; return (void*)-1; }
    pthread_mutex_lock(&g_mx);
    shobj_t* o = &g_sh[V(fd)->shobj];
    if (shmem_ensure(o, (size_t)offset + length) != 0) { pthread_mutex_unlock(&g_mx); return (void*)-1; }
    void* ret = o->mem + offset;
    pthread_mutex_unlock(&g_mx);
    vlog("nx_vfd: mmap SHMEM vfd=%d off=0x%lx len=0x%lx -> %p pid=%d\n",
         fd, (unsigned long)offset, (unsigned long)length, ret, nx_guest_pid());
    return ret;
}

long nx_vfd_lseek(int fd, off_t off, int whence) {
    if (!nx_vfd_is(fd) || V(fd)->kind != VK_SHMEM) { errno = ESPIPE; return -1; }
    pthread_mutex_lock(&g_mx);
    vfd_t* v = V(fd); shobj_t* o = &g_sh[v->shobj];
    size_t np = (whence == 1) ? v->fpos + off : (whence == 2) ? o->size + off : (size_t)off;
    v->fpos = np;
    pthread_mutex_unlock(&g_mx);
    return (long)np;
}

static long shmem_rw(int fd, void* buf, size_t n, int write) {
    pthread_mutex_lock(&g_mx);
    vfd_t* v = V(fd); shobj_t* o = &g_sh[v->shobj];
    if (write && shmem_ensure(o, v->fpos + n) != 0) { pthread_mutex_unlock(&g_mx); return -1; }
    if (!o->mem) { pthread_mutex_unlock(&g_mx); return 0; }
    size_t avail = (v->fpos < o->size) ? o->size - v->fpos : 0;
    size_t k = n < avail ? n : avail;
    if (write) memcpy(o->mem + v->fpos, buf, k);
    else       memcpy(buf, o->mem + v->fpos, k);
    v->fpos += k;
    pthread_mutex_unlock(&g_mx);
    return (long)k;
}

// ---- close / read / write ----------------------------------------------------------------------

int nx_vfd_close(int fd) {
    if (!nx_vfd_is(fd)) { errno = EBADF; return -1; }
    pthread_mutex_lock(&g_mx);
    vfd_t* v = V(fd);
    if (--v->refs > 0) { pthread_mutex_unlock(&g_mx); return 0; }
    if ((v->kind == VK_LOCK || v->kind == VK_SHMEM) && v->shobj >= 0) {
        shobj_t* o = &g_sh[v->shobj];
        if (v->kind == VK_LOCK && o->lock_owner == nx_guest_pid()) o->lock_owner = 0;
        if (o->refs > 0) o->refs--;   // keep mem/lock alive while other fds reference it
    }
    if (v->kind == VK_DIR && v->d) closedir(v->d);
    if ((v->kind == VK_PIPE || v->kind == VK_SOCK) && v->peer >= 0 && g_v[v->peer].kind != VK_FREE)
        g_v[v->peer].peer = -1;              // peer sees EOF/EPIPE
    if (v->kind == VK_LISTEN)
        for (int i = 0; i < v->backlog_n; i++)
            if (g_v[v->backlog[i]].kind != VK_FREE) { g_v[v->backlog[i]].refs = 0; g_v[v->backlog[i]].kind = VK_FREE; }
    free(v->buf);
    for (int i = 0; i < v->fdq_n; i++)       // unclaimed passed fds: drop our reference
        if (nx_vfd_is(v->fdq[i].fd)) { pthread_mutex_unlock(&g_mx); nx_vfd_close(v->fdq[i].fd); pthread_mutex_lock(&g_mx); }
    memset(v, 0, sizeof *v);
    v->kind = VK_FREE;
    pthread_cond_broadcast(&g_cv);
    pthread_mutex_unlock(&g_mx);
    return 0;
}

long nx_vfd_read(int fd, void* buf, size_t n) {
    if (!nx_vfd_is(fd)) { errno = EBADF; return -1; }
    if (V(fd)->kind == VK_SHMEM) return shmem_rw(fd, buf, n, 0);
    pthread_mutex_lock(&g_mx);
    vfd_t* v = V(fd);
    if (v->kind == VK_DIR) { pthread_mutex_unlock(&g_mx); errno = EISDIR; return -1; }
    if (v->kind == VK_LISTEN) { pthread_mutex_unlock(&g_mx); errno = EINVAL; return -1; }
    for (;;) {
        size_t used = rused(v);
        if (used) {
            size_t take = used < n ? used : n;
            for (size_t i = 0; i < take; i++) ((uint8_t*)buf)[i] = v->buf[(v->rd + i) % RING_CAP];
            v->rd += take;
            pthread_cond_broadcast(&g_cv);
            pthread_mutex_unlock(&g_mx);
            return (long)take;
        }
        if (v->peer < 0) { pthread_mutex_unlock(&g_mx); return 0; }      // EOF
        if (v->nonblock) { pthread_mutex_unlock(&g_mx); errno = EAGAIN; return -1; }
        pthread_cond_wait(&g_cv, &g_mx);
    }
}

// write lands in the PEER's inbound ring
long nx_vfd_write(int fd, const void* buf, size_t n) {
    if (!nx_vfd_is(fd)) { errno = EBADF; return -1; }
    if (V(fd)->kind == VK_SHMEM) return shmem_rw(fd, (void*)buf, n, 1);
    pthread_mutex_lock(&g_mx);
    vfd_t* v = V(fd);
    if (v->kind != VK_PIPE && v->kind != VK_SOCK) { pthread_mutex_unlock(&g_mx); errno = EINVAL; return -1; }
    size_t done = 0;
    for (;;) {
        if (v->peer < 0) { pthread_mutex_unlock(&g_mx); errno = EPIPE; return done ? (long)done : -1; }
        vfd_t* p = &g_v[v->peer];
        if (!p->buf) { p->buf = (uint8_t*)malloc(RING_CAP); if (!p->buf) { pthread_mutex_unlock(&g_mx); errno = ENOMEM; return -1; } }
        size_t space = RING_CAP - rused(p);
        if (space) {
            size_t put = n - done < space ? n - done : space;
            for (size_t i = 0; i < put; i++) p->buf[(p->wr + i) % RING_CAP] = ((const uint8_t*)buf)[done + i];
            p->wr += put; done += put;
            pthread_cond_broadcast(&g_cv);
            if (done == n) { pthread_mutex_unlock(&g_mx); return (long)done; }
        }
        if (v->nonblock) { pthread_mutex_unlock(&g_mx); if (done) return (long)done; errno = EAGAIN; return -1; }
        pthread_cond_wait(&g_cv, &g_mx);
    }
}

// ---- pipes & sockets ----------------------------------------------------------------------------

static int make_pair(vkind_t kind, int fds[2], int nonblock) {
    pthread_mutex_lock(&g_mx);
    int a = slot_alloc(); int b = a >= 0 ? slot_alloc() : -1;
    if (b < 0) { if (a >= 0) g_v[a].kind = VK_FREE; pthread_mutex_unlock(&g_mx); errno = EMFILE; return -1; }
    g_v[a].kind = kind; g_v[b].kind = kind;
    g_v[a].peer = b;    g_v[b].peer = a;
    g_v[a].nonblock = g_v[b].nonblock = nonblock;
    g_v[a].pid = g_v[b].pid = nx_guest_pid();
    pthread_mutex_unlock(&g_mx);
    fds[0] = NX_VFD_BASE + a; fds[1] = NX_VFD_BASE + b;
    return 0;
}

int nx_pipe2(int fds[2], int linux_flags) {
    return make_pair(VK_PIPE, fds, (linux_flags & 0x800) ? 1 : 0);   // Linux O_NONBLOCK
}

int nx_socket(int domain, int type, int protocol) {
    (void)protocol;
    vlog("nx_vfd: socket pid=%d domain=%d type=0x%x\n", nx_guest_pid(), domain, type);
    if (domain != 1 /*AF_UNIX*/) { errno = EAFNOSUPPORT; return -1; }
    if ((type & 0xff) != 1 /*SOCK_STREAM*/) { errno = EPROTONOSUPPORT; return -1; }
    pthread_mutex_lock(&g_mx);
    int i = slot_alloc();
    if (i < 0) { pthread_mutex_unlock(&g_mx); errno = EMFILE; return -1; }
    g_v[i].kind = VK_SOCK;
    g_v[i].nonblock = (type & 0x800) ? 1 : 0;   // SOCK_NONBLOCK
    g_v[i].pid = nx_guest_pid();
    pthread_mutex_unlock(&g_mx);
    return NX_VFD_BASE + i;
}

int nx_socketpair(int domain, int type, int protocol, int sv[2]) {
    if (domain != 1) { errno = EAFNOSUPPORT; return -1; }
    (void)protocol;
    return make_pair(VK_SOCK, sv, (type & 0x800) ? 1 : 0);
}

// normalize a guest sun_path against the guest cwd so bind("socket") and a later absolute
// connect("/root/.wine/wineserver/socket") meet in the registry
static void norm_spath(const char* in, char* out, size_t outn) {
    if (in[0] == '/') snprintf(out, outn, "%s", in);
    else { const char* cwd = nx_cwd_buf();
           snprintf(out, outn, "%s/%s", (cwd[0] && strcmp(cwd, "/")) ? cwd : "", in); }
}

// stat() of a wineserver runtime path that is backed by a vfd (the bound unix `socket`, or the
// `lock`/`tmpmap-*` shared objects) — no fsdev file exists for these, but Wine stat()s the socket
// before connecting, so return a synthetic stat (S_IFSOCK for the socket) instead of ENOENT. Returns
// 0 (st filled) if the resolved path names a live vfd/shared object, else -1.
int nx_vfd_path_stat(const char* guestpath, struct stat* st) {
    char want[512]; norm_spath(guestpath, want, sizeof want);   // resolve vs the per-instance cwd
    pthread_mutex_lock(&g_mx);
    mode_t mode = 0;
    for (int i = 0; i < NX_VFD_MAX; i++) {
        vfd_t* v = &g_v[i];
        if ((v->kind == VK_LISTEN || v->kind == VK_SOCK) && v->bpath[0] && !strcmp(v->bpath, want)) {
            mode = S_IFSOCK | 0777; break;
        }
    }
    if (!mode) for (int i = 0; i < NX_SHOBJ_MAX; i++)
        if (g_sh[i].refs && !strcmp(g_sh[i].path, want)) { mode = S_IFREG | 0600; break; }
    pthread_mutex_unlock(&g_mx);
    if (!mode) return -1;
    memset(st, 0, sizeof *st);
    st->st_dev = 1; st->st_ino = path_ino(want); st->st_mode = mode; st->st_nlink = 1; st->st_blksize = 4096;
    return 0;
}

// Linux sockaddr_un: u16 family, char path[108]
int nx_bind(int fd, const void* addr, unsigned alen) {
    if (!nx_vfd_is(fd) || V(fd)->kind != VK_SOCK) { errno = EBADF; return -1; }
    if (!addr || alen < 3) { errno = EINVAL; return -1; }
    const char* path = (const char*)addr + 2;
    norm_spath(path, V(fd)->bpath, sizeof V(fd)->bpath);
    return 0;
}

void nx_spawn_note_listen(const char* bpath);   // nx_spawn.c — wineserver-ready handshake
int nx_listen(int fd, int backlog) {
    (void)backlog;
    if (!nx_vfd_is(fd) || V(fd)->kind != VK_SOCK) { errno = EBADF; return -1; }
    pthread_mutex_lock(&g_mx);
    V(fd)->kind = VK_LISTEN;
    pthread_cond_broadcast(&g_cv);
    pthread_mutex_unlock(&g_mx);
    vlog("nx_vfd: listen '%s'\n", V(fd)->bpath);
    nx_spawn_note_listen(V(fd)->bpath);
    return 0;
}

int nx_connect(int fd, const void* addr, unsigned alen) {
    if (!nx_vfd_is(fd) || V(fd)->kind != VK_SOCK) {
        vlog("nx_vfd: connect fd=%d NOT-A-SOCK-VFD (is_vfd=%d) pid=%d\n", fd, nx_vfd_is(fd), nx_guest_pid());
        errno = EBADF; return -1;
    }
    if (!addr || alen < 3) { errno = EINVAL; return -1; }
    char want[256]; norm_spath((const char*)addr + 2, want, sizeof want);
    vlog("nx_vfd: connect pid=%d raw='%s' want='%s'\n", nx_guest_pid(), (const char*)addr + 2, want);
    pthread_mutex_lock(&g_mx);
    int li = -1;
    for (int i = 0; i < NX_VFD_MAX; i++)
        if (g_v[i].kind == VK_LISTEN && !strcmp(g_v[i].bpath, want)) { li = i; break; }
    if (li < 0 || g_v[li].backlog_n >= 8) {
        pthread_mutex_unlock(&g_mx);
        vlog("nx_vfd: connect '%s' -> ECONNREFUSED\n", want);
        errno = ECONNREFUSED; return -1;
    }
    int si = slot_alloc();
    if (si < 0) { pthread_mutex_unlock(&g_mx); errno = EMFILE; return -1; }
    vfd_t* c = V(fd); vfd_t* s = &g_v[si];
    s->kind = VK_SOCK; s->pid = g_v[li].pid;
    s->peer = fd - NX_VFD_BASE; c->peer = si;
    snprintf(s->bpath, sizeof s->bpath, "%s", want);
    g_v[li].backlog[g_v[li].backlog_n++] = si;
    pthread_cond_broadcast(&g_cv);
    pthread_mutex_unlock(&g_mx);
    vlog("nx_vfd: connect '%s' OK\n", want);
    return 0;
}

int nx_accept4(int fd, void* addr, unsigned* alen, int flags) {
    if (!nx_vfd_is(fd) || V(fd)->kind != VK_LISTEN) { errno = EINVAL; return -1; }
    pthread_mutex_lock(&g_mx);
    vfd_t* l = V(fd);
    while (!l->backlog_n) {
        if (l->nonblock) { pthread_mutex_unlock(&g_mx); errno = EAGAIN; return -1; }
        pthread_cond_wait(&g_cv, &g_mx);
    }
    int si = l->backlog[0];
    memmove(l->backlog, l->backlog + 1, --l->backlog_n * sizeof(int));
    g_v[si].nonblock = (flags & 0x800) ? 1 : 0;
    pthread_mutex_unlock(&g_mx);
    if (addr && alen && *alen >= 2) { memset(addr, 0, *alen); *(uint16_t*)addr = 1; *alen = 2; }
    return NX_VFD_BASE + si;
}

// ---- sendmsg / recvmsg + SCM_RIGHTS --------------------------------------------------------------

// Linux x86-64 layouts
typedef struct { void* base; size_t len; } l_iovec;
typedef struct { void* name; unsigned namelen; l_iovec* iov; size_t iovlen;
                 void* control; size_t controllen; int flags; } l_msghdr;
typedef struct { size_t len; int level; int type; } l_cmsghdr;   // data follows, 8-aligned

long nx_sendmsg(int fd, const l_msghdr* msg, int flags) {
    (void)flags;
    if (!nx_vfd_is(fd) || V(fd)->kind != VK_SOCK) { errno = EBADF; return -1; }
    vfd_t* v = V(fd);
    // queue SCM_RIGHTS fds on the peer, stamped at the CURRENT stream position
    if (msg->control && msg->controllen >= sizeof(l_cmsghdr)) {
        pthread_mutex_lock(&g_mx);
        if (v->peer < 0) { pthread_mutex_unlock(&g_mx); errno = EPIPE; return -1; }
        vfd_t* p = &g_v[v->peer];
        const uint8_t* c = (const uint8_t*)msg->control;
        size_t rem = msg->controllen;
        while (rem >= sizeof(l_cmsghdr)) {
            const l_cmsghdr* cm = (const l_cmsghdr*)c;
            if (cm->len < sizeof(l_cmsghdr) || cm->len > rem) break;
            if (cm->level == 1 /*SOL_SOCKET*/ && cm->type == 1 /*SCM_RIGHTS*/) {
                int nfd = (int)((cm->len - sizeof(l_cmsghdr)) / sizeof(int));
                const int* fda = (const int*)(c + sizeof(l_cmsghdr));
                for (int i = 0; i < nfd && p->fdq_n < FDQ_MAX; i++) {
                    int passfd = fda[i];
                    if (nx_vfd_is(passfd)) g_v[passfd - NX_VFD_BASE].refs++;   // survive sender close
                    else { int d = dup(passfd); if (d >= 0) passfd = d; else vlog("nx_vfd: dup(%d) fail e=%d\n", passfd, errno); }
                    p->fdq[p->fdq_n].fd = passfd;
                    p->fdq[p->fdq_n].at = p->wr;
                    p->fdq_n++;
                }
            }
            size_t adv = (cm->len + 7) & ~(size_t)7;
            if (adv >= rem) break;
            c += adv; rem -= adv;
        }
        pthread_mutex_unlock(&g_mx);
    }
    long total = 0;
    for (size_t i = 0; i < msg->iovlen; i++) {
        if (!msg->iov[i].len) continue;
        long r = nx_vfd_write(fd, msg->iov[i].base, msg->iov[i].len);
        if (r < 0) return total ? total : -1;
        total += r;
        if ((size_t)r < msg->iov[i].len) break;
    }
    return total;
}

long nx_recvmsg(int fd, l_msghdr* msg, int flags) {
    (void)flags;
    if (!nx_vfd_is(fd) || V(fd)->kind != VK_SOCK) { errno = EBADF; return -1; }
    vfd_t* v = V(fd);
    long total = 0;
    for (size_t i = 0; i < msg->iovlen; i++) {
        if (!msg->iov[i].len) continue;
        long r = nx_vfd_read(fd, msg->iov[i].base, msg->iov[i].len);
        if (r < 0) { if (total) break; return -1; }
        if (r == 0) break;
        total += r;
        if ((size_t)r < msg->iov[i].len) break;
        if (i + 1 < msg->iovlen && rused(v) == 0) break;   // don't block for the next iov
    }
    // deliver queued fds that belong to the consumed range
    size_t ctl_used = 0;
    if (msg->control && msg->controllen >= sizeof(l_cmsghdr) + sizeof(int)) {
        pthread_mutex_lock(&g_mx);
        int nfit = (int)((msg->controllen - sizeof(l_cmsghdr)) / sizeof(int));
        int nout = 0;
        int* fda = (int*)((uint8_t*)msg->control + sizeof(l_cmsghdr));
        // Deliver queued SCM_RIGHTS fds whose bytes have been reached (<=, so an fd stamped at the
        // exact end of the just-consumed reply is still delivered — the client reads exactly the
        // message bytes, so `<` would strand the reply/wait channel fds and deadlock wineserver).
        while (v->fdq_n && nout < nfit && v->fdq[0].at <= v->rd) {
            fda[nout++] = v->fdq[0].fd;
            memmove(v->fdq, v->fdq + 1, --v->fdq_n * sizeof(fdpass_t));
        }
        if (nout) {
            l_cmsghdr* cm = (l_cmsghdr*)msg->control;
            cm->len = sizeof(l_cmsghdr) + nout * sizeof(int);
            cm->level = 1; cm->type = 1;
            ctl_used = (cm->len + 7) & ~(size_t)7;
            if (ctl_used > msg->controllen) ctl_used = msg->controllen;
        }
        pthread_mutex_unlock(&g_mx);
    }
    msg->controllen = ctl_used;
    msg->flags = 0;
    return total;
}

// ---- sockopt / names -----------------------------------------------------------------------------

int nx_getsockopt(int fd, int level, int opt, void* val, unsigned* len) {
    if (!nx_vfd_is(fd)) { errno = EBADF; return -1; }
    if (level == 1 && opt == 17 && val && len && *len >= 12) {   // SOL_SOCKET SO_PEERCRED
        vfd_t* v = V(fd);
        int peer_pid = (v->peer >= 0) ? g_v[v->peer].pid : v->pid;
        ((int*)val)[0] = peer_pid;   // pid
        ((int*)val)[1] = 0;          // uid root
        ((int*)val)[2] = 0;          // gid
        *len = 12;
        return 0;
    }
    if (val && len && *len >= 4) { *(int*)val = 0; *len = 4; }
    return 0;
}

int nx_setsockopt(int fd, int level, int opt, const void* val, unsigned len) {
    (void)level; (void)opt; (void)val; (void)len;
    if (!nx_vfd_is(fd)) { errno = EBADF; return -1; }
    return 0;
}

int nx_getsockname(int fd, void* addr, unsigned* alen) {
    if (!nx_vfd_is(fd)) { errno = EBADF; return -1; }
    if (addr && alen && *alen >= 2) {
        memset(addr, 0, *alen);
        *(uint16_t*)addr = 1;
        size_t pl = strlen(V(fd)->bpath);
        if (pl && *alen > 2 + pl) memcpy((char*)addr + 2, V(fd)->bpath, pl + 1);
        *alen = (unsigned)(2 + pl + (pl ? 1 : 0));
    }
    return 0;
}

// ---- poll ----------------------------------------------------------------------------------------

typedef struct { int fd; short events; short revents; } l_pollfd;

static short vfd_ready(vfd_t* v, short events) {
    short re = 0;
    if (v->kind == VK_LISTEN) {
        if (v->backlog_n) re |= 0x001;                                   // POLLIN
    } else if (v->kind == VK_SOCK || v->kind == VK_PIPE) {
        if (rused(v)) re |= 0x001;                                       // POLLIN: buffered data
        if (v->peer < 0) re |= 0x010;                                    // POLLHUP: peer closed
        else if (RING_CAP - rused(&g_v[v->peer]) > 0) re |= 0x004;       // POLLOUT
        // wineserver's sock_check_pollhup expects EXACTLY POLLHUP on a drained hung-up socket, so
        // do NOT add POLLIN on hangup — POLLHUP alone is in the always-report set below and wakes
        // readers; a hangup WITH unread data still reports POLLIN (from rused above), as Linux does.
    } else re |= 0x020;                                                  // POLLNVAL
    return re & (events | 0x010 | 0x020 | 0x008);                        // HUP/NVAL/ERR always reported
}

int nx_poll(l_pollfd* pf, unsigned long n, int timeout_ms) {
    int has_real = 0;
    for (;;) {
        pthread_mutex_lock(&g_mx);
        int ready = 0;
        for (unsigned long i = 0; i < n; i++) {
            pf[i].revents = 0;
            if (pf[i].fd < 0) continue;
            if (!nx_vfd_is(pf[i].fd)) {
                // real newlib fd: no host poll on Horizon — report it ready for whatever was
                // asked (a read on a real file won't block anyway)
                has_real = 1;
                pf[i].revents = pf[i].events & (0x001 | 0x004);
                if (pf[i].revents) ready++;
                continue;
            }
            pf[i].revents = vfd_ready(V(pf[i].fd), pf[i].events);
            if (pf[i].revents) ready++;
        }
        if (ready || timeout_ms == 0 || has_real) { pthread_mutex_unlock(&g_mx); return ready; }
        if (timeout_ms < 0) {
            pthread_cond_wait(&g_cv, &g_mx);
            pthread_mutex_unlock(&g_mx);
        } else {
            struct timeval tv; gettimeofday(&tv, NULL);
            long usec = tv.tv_usec + (timeout_ms % 1000) * 1000;
            struct timespec ts = { tv.tv_sec + timeout_ms / 1000 + usec / 1000000,
                                   (usec % 1000000) * 1000 };
            int w = pthread_cond_timedwait(&g_cv, &g_mx, &ts);
            pthread_mutex_unlock(&g_mx);
            if (w == ETIMEDOUT) {
                // one final scoreboard pass so a race right at the deadline isn't lost
                timeout_ms = 0;
            }
        }
    }
}

// ---- fcntl / ioctl (vfd subset) ------------------------------------------------------------------

// Linux x86-64 struct flock: short l_type; short l_whence; off_t l_start; off_t l_len; pid_t l_pid;
typedef struct { short l_type; short l_whence; long l_start; long l_len; int l_pid; } l_flock;

long nx_vfd_fcntl(int fd, int cmd, long arg) {
    if (!nx_vfd_is(fd)) { errno = EBADF; return -1; }
    vfd_t* v = V(fd);
    switch (cmd) {
        case 1:  return 0;                                        // F_GETFD
        case 2:  return 0;                                        // F_SETFD (CLOEXEC — no exec)
        case 3:  return 2 /*O_RDWR*/ | (v->nonblock ? 0x800 : 0); // F_GETFL (Linux bits)
        case 4:  v->nonblock = (arg & 0x800) ? 1 : 0; return 0;   // F_SETFL
        case 5: case 6: case 7: {   // F_GETLK / F_SETLK / F_SETLKW — Wine's server lock uses fcntl,
            // not flock(). The server holds a WRLCK on the lock file; a client's WRLCK then fails EAGAIN
            // ("server running") -> it connects instead of starting a server. Emulate as a pid-owned
            // exclusive lock on the shared object (VK_LOCK), so it never reports "doesn't support locks".
            if (v->kind != VK_LOCK) return 0;                     // record locks on non-lock vfds: accept
            l_flock* fl = (l_flock*)arg;
            if (!fl) { errno = EINVAL; return -1; }
            pthread_mutex_lock(&g_mx);
            shobj_t* o = &g_sh[v->shobj];
            int pid = nx_guest_pid();
            long r = 0;
            if (cmd == 5) {                                       // F_GETLK: report the holder (or unlocked)
                if (o->lock_owner && o->lock_owner != pid) { fl->l_type = 1 /*F_WRLCK*/; fl->l_pid = o->lock_owner; }
                else fl->l_type = 2 /*F_UNLCK*/;
            } else if (fl->l_type == 2 /*F_UNLCK*/) {
                if (o->lock_owner == pid) o->lock_owner = 0;
            } else {                                              // F_RDLCK/F_WRLCK acquire
                if (o->lock_owner && o->lock_owner != pid) { errno = EAGAIN; r = -1; }
                else o->lock_owner = pid;
            }
            pthread_mutex_unlock(&g_mx);
            vlog("nx_vfd: fcntl F_SETLK vfd=%d type=%d pid=%d owner=%d -> %ld\n",
                 fd, fl ? fl->l_type : -1, pid, o->lock_owner, r);
            return r;
        }
        default:
            vlog("nx_vfd: fcntl(%d, cmd=%d) unhandled\n", fd, cmd);
            errno = EINVAL; return -1;
    }
}

long nx_vfd_ioctl(int fd, unsigned long req, void* arg) {
    if (!nx_vfd_is(fd)) { errno = EBADF; return -1; }
    vfd_t* v = V(fd);
    switch (req) {
        case 0x5421: v->nonblock = arg && *(int*)arg ? 1 : 0; return 0;  // FIONBIO
        case 0x541B: if (arg) *(int*)arg = (int)rused(v); return 0;      // FIONREAD
        default: return 0;                                               // accept quietly
    }
}

// ---- guest-path helpers for the big-switch fallback cases ----------------------------------------

int nx_mkdir_guest(const char* p, unsigned mode) {
    char hp[512];
    if (!p) { errno = EFAULT; return -1; }
    if (nx_translate_path(p, hp, sizeof hp) != 0) return -1;
    int r = mkdir(hp, (mode_t)mode);
    if (r < 0 && errno == EEXIST) return 0;
    return r;
}
int nx_unlink_guest(const char* p) {
    char hp[512];
    if (!p) { errno = EFAULT; return -1; }
    if (nx_translate_path(p, hp, sizeof hp) != 0) return -1;
    return unlink(hp);
}
int nx_rmdir_guest(const char* p) {
    char hp[512];
    if (!p) { errno = EFAULT; return -1; }
    if (nx_translate_path(p, hp, sizeof hp) != 0) return -1;
    return rmdir(hp);
}
int nx_access_guest(const char* p, int mode) {
    char hp[512]; struct stat st;
    if (!p) { errno = EFAULT; return -1; }
    if (nx_translate_path(p, hp, sizeof hp) != 0) return -1;
    (void)mode;                                  // fsdev has no perms — existence check suffices
    return stat(hp, &st);
}
int nx_rename_guest(const char* a, const char* b) {
    char ha[512], hb[512];
    if (!a || !b) { errno = EFAULT; return -1; }
    if (nx_translate_path(a, ha, sizeof ha) != 0) return -1;
    if (nx_translate_path(b, hb, sizeof hb) != 0) return -1;
    return rename(ha, hb);
}

// ---- x86-64 big-switch pre-dispatch ---------------------------------------------------------------
// Handles the x86-64 NRs that box64's big switch would pass to newlib with raw fds/paths.
// Returns 1 with *ret set (result or -host_errno; the caller's seam translates errno) or 0.

int nx_x64_precase(long s, unsigned long a1, unsigned long a2, unsigned long a3,
                   unsigned long a4, unsigned long a5, unsigned long a6, long* ret) {
    (void)a4; (void)a5; (void)a6;
    long r = -1;
    switch (s) {
        case 0:   // read
            if (!nx_vfd_is((int)a1)) return 0;
            r = nx_vfd_read((int)a1, (void*)a2, (size_t)a3);
            break;
        case 1:   // write
            if (!nx_vfd_is((int)a1)) return 0;
            r = nx_vfd_write((int)a1, (const void*)a2, (size_t)a3);
            break;
        case 3:   // close
            if (!nx_vfd_is((int)a1)) return 0;
            r = nx_vfd_close((int)a1);
            break;
        case 7:   // poll
            r = nx_poll((l_pollfd*)a1, (unsigned long)a2, (int)a3);
            break;
        case 16:  // ioctl (vfd only)
            if (!nx_vfd_is((int)a1)) return 0;
            r = nx_vfd_ioctl((int)a1, (unsigned long)a2, (void*)a3);
            break;
        case 21: r = nx_access_guest((const char*)a1, (int)a2); break;
        case 22: r = nx_pipe2((int*)a1, 0); break;
        case 8:   // lseek (vfd SHMEM only; real fds fall through to box64)
            if (!nx_vfd_is((int)a1)) return 0;
            r = nx_vfd_lseek((int)a1, (off_t)a2, (int)a3);
            break;
        case 72:  // fcntl (vfd only)
            if (!nx_vfd_is((int)a1)) return 0;
            r = nx_vfd_fcntl((int)a1, (int)a2, (long)a3);
            break;
        case 73:  // flock (vfd LOCK only)
            if (!nx_vfd_is((int)a1)) return 0;
            r = nx_vfd_flock((int)a1, (int)a2);
            break;
        case 77:  // ftruncate (vfd SHMEM only)
            if (!nx_vfd_is((int)a1)) return 0;
            r = nx_vfd_ftruncate((int)a1, (off_t)a2);
            break;
        case 81:  // fchdir — wineserver saves/restores cwd around ops (open ".", fchdir back)
            if (nx_vfd_is((int)a1)) r = nx_vfd_fchdir((int)a1);
            else r = 0;                              // real fd: accept (nx_cwd is the only cwd we track)
            break;
        case 82: r = nx_rename_guest((const char*)a1, (const char*)a2); break;
        case 83: r = nx_mkdir_guest((const char*)a1, (unsigned)a2); break;
        case 84: r = nx_rmdir_guest((const char*)a1); break;
        case 87: r = nx_unlink_guest((const char*)a1); break;
        case 95: r = 022; break;             // umask
        case 112: r = nx_guest_pid(); break; // setsid
        default:
            return 0;
    }
    *ret = (r == -1) ? -(long)errno : r;
    if (r == -1 && !errno) *ret = -1;
    return 1;
}

#endif // __SWITCH__
