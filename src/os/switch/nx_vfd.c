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
#include <limits.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/iosupport.h>   // devoptab / __alloc_handle / __get_handle — real fd numbers for vfds

#include "custommem.h"   // getProtection — validate guest buffers before deref (EFAULT, not a fault)
#include "nx_fsfunnel.h" // SD I/O funnel: nx_fs_* wrappers + the nx_dent_t snapshot type
#include "nx_libcache.h" // RAM lib content cache: invalidate on unlink/rename (Part 2)
#include "nx_net.h"      // M2.8 INET sockets: keep them off the SD funnel + route the socket syscalls

// nx_posix.c
extern int  nx_translate_path(const char* p, char* out, size_t outn);
extern char* nx_cwd_buf(void);   // nx_posix.c — per-instance guest cwd
extern int  nx_guest_pid(void);
extern int  nx_gettid(void);     // nx_posix.c — guest thread id (for per-thread IPC tracing)
// nx_signals.c — directed-signal delivery. A blocking wait is the ONLY safe place to run a queued
// guest handler: the syscall boundary can have a wineserver request in flight, and a handler's own
// round-trip there desynchronises the request/reply pairing. Declared here rather than via signals.h,
// which needs x64emu_t and the emu headers this file deliberately does not pull in.
extern int  nx_signal_pending_self(void);
extern int  nx_signal_deliver_pending(void);   // 1 = a handler ran (caller should report EINTR)
void nx_guest_output(int fd, const void *buf, size_t len);   // nx_main.c

static void vlog(const char* fmt, ...) {
    char b[256]; va_list ap; va_start(ap, fmt);
    int n = vsnprintf(b, sizeof b, fmt, ap); va_end(ap);
    if (n > 0) svcOutputDebugString(b, (size_t)n);
}

// A bad guest pointer passed to write(2)/writev(2) must return -EFAULT on Linux, NEVER a SIGSEGV — but
// the vfd copy loops dereference the guest buffer directly, so a wild pointer (e.g. an om error-path
// test's 0xdeadbee0) faults INSIDE box64. The libnx exception handler then mis-delivers that as a guest
// SIGSEGV with a syscall-boundary context Wine isn't prepared for, seeding a nested-fault cascade in the
// delivery core (root-caused 2026-07-19, porting-log + [[box64-signal-delivery-notes]]). Guard the
// deref: getProtection()==0 means the page is unmapped (rb_get(memprot,·) miss) => bad. Cheap memprot
// lookup on the buffer endpoints; KX_NO_VFD_FAULTCHECK=1 restores the old raw-deref for A/B.
// Exported (as nx_guest_buf_bad) because nx_net.c needs the identical guard: libnx dereferences the
// guest's sockaddr/data buffers inside the bsd:u IPC marshalling, so a wild guest pointer would fault
// in exactly the same un-deliverable way there as it does here.
int nx_guest_buf_bad(const void* base, size_t len) {
    static int chk = -1;
    if (chk < 0) chk = getenv("KX_NO_VFD_FAULTCHECK") ? 0 : 1;
    if (!chk || !base || !len) return 0;
    uintptr_t a = (uintptr_t)base;
    if (!getProtection(a)) return 1;              // first byte's page unmapped
    if (!getProtection(a + len - 1)) return 1;    // last byte's page unmapped
    return 0;
}
static inline int nx_vfd_buf_bad(const void* base, size_t len) { return nx_guest_buf_bad(base, len); }

#define NX_VFD_BASE 0x40000000
#define NX_VFD_MAX  256
#define RING_CAP    (256*1024)
#define FDQ_MAX     256   // wine can queue many pending fds on the main socket before the client
                          // drains them via receive_fd; 32 overflowed and silently dropped fds

// VK_LOCK / VK_SHMEM (M2.5): the wineserver runtime files (lock, tmpmap-*) that the client and the
// in-process wineserver share. fsdev can't open the same file from both instances (2nd open -> EIO)
// and file-backed mmap copies per instance, so back them with IN-PROCESS shared state keyed by path.
typedef enum { VK_FREE = 0, VK_DIR, VK_PIPE, VK_SOCK, VK_LISTEN, VK_LOCK, VK_SHMEM,
               VK_EPOLL, VK_SINK, VK_TMPFILE, VK_TMPDIR, VK_TAKEN } vkind_t;
               // SINK: write-discard sink (reg*.tmp); TMPFILE/TMPDIR: RAM-backed /tmp tmpfs node (Phase C);
               // TAKEN: slot_alloc'd, kind not yet set (never escapes g_mx)

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

// VK_DIR entry snapshot: read at open (opendir -> readdir all -> closedir immediately) so an open
// dir vfd holds NO persistent fsdev directory handle. Horizon's per-session FS handle limit is low
// (~30 concurrent open dirs exhausted it, making later file opens — the .reg registry files — fail
// ENOSYS: the ntdll:directory flaky-hang / registry-save livelock). nx_dent_t now lives in
// nx_fsfunnel.h — nx_fs_getdents hands back the snapshot and funnels the enumeration onto the worker.

typedef struct {
    vkind_t  kind;
    int      refs;                // LEGACY numbering only — how many owners share this fd NUMBER.
                                  // Under LOWFD each vfd has a real newlib handle and newlib's own
                                  // refcount does this job, so the field is untouched there.
    int      nonblock;
    unsigned ino;                 // synthetic identity for fstat
    // VK_DIR
    DIR*     d;                   // legacy (unused now the snapshot is read at open)
    nx_dent_t* dents;             // snapshot (malloc'd); NULL until first getdents
    int      dent_n, dent_i;      // snapshot count, current read index
    char     host[512];
    char     guest[512];
    // VK_PIPE / VK_SOCK: inbound ring (the PEER writes into it)
    uint8_t* buf;                 // lazy RING_CAP
    size_t   rd, wr;              // rd<=wr, used=wr-rd (absolute counters, mod on access)
    fdpass_t fdq[FDQ_MAX];        // SCM_RIGHTS queue: fd visible once rd (bytes consumed) > at
    int      fdq_n;
    int      peer;                // slot idx, -1 = closed/never
    int      pid;                 // creator's guest pid (SO_PEERCRED)
    int      rd_shut;             // peer did shutdown(SHUT_WR): reads here see EOF once the ring drains
    // VK_SOCK bound / VK_LISTEN
    char     bpath[256];
    int      backlog[8];
    int      backlog_n;
    // VK_LOCK / VK_SHMEM
    int      shobj;               // index into g_sh
    size_t   fpos;                // per-fd position (shmem read/write/lseek)
    // VK_EPOLL: the interest set (lazy). Each entry is a watched fd + its epoll events + user data.
    void*    epset;               // struct nx_epitem[ep_cap]
    int      ep_n, ep_cap;
} vfd_t;

static vfd_t g_v[NX_VFD_MAX];
static pthread_mutex_t g_mx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  g_cv = PTHREAD_COND_INITIALIZER;   // broadcast on ANY state change
static unsigned g_ino_next = 0x1000;

// RAM /tmp tmpfs open-fd bodies (Phase C) — defined in the tmpfs section further down, but the vfd
// dispatch functions above that section (lseek/ftruncate/mmap/stat/getdents) call them, so forward-declare.
static long  nx_tmpfs_lseek_body(vfd_t* v, off_t off, int whence);
static int   nx_tmpfs_ftruncate_body(vfd_t* v, off_t len);
static void* nx_tmpfs_mmap_body(vfd_t* v, size_t length, off_t offset);
static int   nx_tmpfs_fstat_body(vfd_t* v, struct stat* st);
static int   nx_tmpfs_fill_dents(vfd_t* v);

// Guest-console tee origin: Wine hands the guest a DUP of unix fd 1/2 (fd 1 is SCM_RIGHTS-passed to
// the wineserver at startup, dup'd there, dup'd again into every get_handle_fd reply), so the final
// WriteFile lands on write(<dup>), not write(1). Track dup chains from 1/2 so the result-file tee
// (nx_guest_output) still sees the output — on real HW that tee is the only proof channel.
static unsigned char g_tee[1024];
int nx_tee_origin(int fd) {
    if (fd == 1 || fd == 2) return fd;
    return (fd >= 0 && fd < 1024) ? g_tee[fd] : 0;
}
static void tee_mark(int newfd, int fromfd) {
    int o = nx_tee_origin(fromfd);
    if (o && newfd >= 0 && newfd < 1024) g_tee[newfd] = (unsigned char)o;
}
// Clear a stale tee flag when a real fd is closed: the number is about to be recycled, and if it were
// left marked, a later unrelated file on that fd (e.g. the wineserver's reg*.tmp) would be spuriously
// teed to svcOutputDebugString — dumping the whole 1.7 MiB registry to the log every save, which
// throttled Ryujinx to a crawl and starved the wine client.
void nx_tee_forget(int fd) { if (fd >= 0 && fd < 1024) g_tee[fd] = 0; }

// M2.7 fast registry save: the wineserver flushes each registry branch by writing a `reg<pid>.tmp`
// file then renaming it over the real `.reg`. Through fsdev+dynarec each 8 KiB write is ms-slow, so
// one save-all (system/user/userdef.reg) pins the SINGLE-THREADED server for 25 s+ inside write()/
// rename() — it never returns to select(), and the wine client starves mid-startup (confirmed by a
// timestamped trace: client quiescent after MapOwner @43 s while the server logged nonstop 8192-byte
// writes to reg20000.tmp through 69 s+). Registry PERSISTENCE is irrelevant to `cmd /c echo`, so make
// the save near-instant: discard writes to a reg*.tmp fd (nx_regtmp_is) and short-circuit the
// reg*.tmp->*.reg rename (below) so the real .reg files stay intact for a fast next-run startup.
// Keyed on (pid,fd): the client and wineserver are separate guests with independent fd tables, so a
// bare fd number aliases across them — only the owning instance's reg*.tmp fd must be discarded.
int nx_regtmp_name(const char* p) {
    if (!p) return 0;
    const char* b = strrchr(p, '/'); b = b ? b + 1 : p;
    size_t n = strlen(b);
    return n >= 8 && !strncmp(b, "reg", 3) && !strcmp(b + n - 4, ".tmp");
}
static struct { int pid, fd; } g_regtmp[64];
static int g_regtmp_n = 0;
void nx_regtmp_mark(int fd) {
    if (g_regtmp_n < 64) { g_regtmp[g_regtmp_n].pid = nx_guest_pid(); g_regtmp[g_regtmp_n].fd = fd; g_regtmp_n++; }
}
int nx_regtmp_is(int fd) {
    int pid = nx_guest_pid();
    for (int i = 0; i < g_regtmp_n; i++) if (g_regtmp[i].fd == fd && g_regtmp[i].pid == pid) return 1;
    return 0;
}
void nx_regtmp_forget(int fd) {
    int pid = nx_guest_pid();
    for (int i = 0; i < g_regtmp_n; i++)
        if (g_regtmp[i].fd == fd && g_regtmp[i].pid == pid) { g_regtmp[i] = g_regtmp[--g_regtmp_n]; return; }
}

// ---- fd numbering --------------------------------------------------------------------------------
// Two numbering schemes coexist in one binary so the change can be A/B'd on hardware over FTP.
//
// LEGACY: a vfd IS its number, NX_VFD_BASE + slot. Simple, and it can never collide with a newlib
// fd — but 0x40000000 is far above FD_SETSIZE, so no fd_set can carry a pipe (glibc's FD_SET()
// writes ~128 MB past the end of the set), and dup2() cannot pin a vfd to a chosen number, so a
// guest shell cannot do `2>&1` and posix_spawn file-actions cannot work.
//
// LOWFD (default): the vfd layer registers its own devoptab and allocates a REAL newlib fd per vfd,
// keeping the slot index in the handle's fileStruct. Numbers come from newlib's 1024-entry table
// (lowest free first), so they fit an fd_set — and newlib refcounts the handle, which gives
// dup()/dup2() correct POSIX aliasing for free. This is the same mechanism nx_net_is_socket()
// already relies on for libnx's "soc" device.
//
// The one cost: a vfd now consumes a newlib handle, where legacy numbering consumed none. Worst case
// is NX_VFD_MAX (256) of newlib's 1024, and Wine's own fds come out of the same pool — so a handle
// exhaustion that used to hit only real files can now be reached by pipes and sockets too. Every
// publish site rolls its slot back on failure rather than stranding it.
//
// KX_NO_VFD_LOWFD=1 restores the legacy numbering for A/B.
static int kxvfd_close_r(struct _reent* r, void* fileStruct);
int nx_vfd_close(int fd);                  // the slot teardown closes queued SCM_RIGHTS fds
static const devoptab_t g_kxvfd_devoptab = {
    .name       = "kxvfd",
    .structSize = sizeof(int),        // the g_v slot index this fd refers to
    .close_r    = kxvfd_close_r,
};
enum { KXVFD_DEVICE_NONE = -1 };
static int g_kxvfd_device = KXVFD_DEVICE_NONE;
static int g_lowfd_mode   = 0;
static pthread_once_t g_kxvfd_once = PTHREAD_ONCE_INIT;

static void kxvfd_init(void) {
    if (getenv("KX_NO_VFD_LOWFD")) return;           // legacy numbering for A/B
    int device = AddDevice(&g_kxvfd_devoptab);
    if (device < 0) return;                          // no free devoptab slot: stay legacy rather than fail
    g_kxvfd_device = device;
    g_lowfd_mode   = 1;
}
// Safe to call unlocked and from any thread — is_vfd() runs on every fd-taking syscall.
static inline int lowfd_mode(void) { pthread_once(&g_kxvfd_once, kxvfd_init); return g_lowfd_mode; }

enum { VFD_SLOT_NONE = -1 };

// The one place a guest fd number is turned into a g_v index. Returns VFD_SLOT_NONE if the fd is
// not a vfd at all, which is what makes is_vfd() a pure function of the fd.
static inline int vfd_slot_of(int fd) {
    if (fd < 0) return VFD_SLOT_NONE;
    if (lowfd_mode()) {
        __handle* handle = __get_handle(fd);
        if (!handle || (int)handle->device != g_kxvfd_device) return VFD_SLOT_NONE;
        return *(int*)handle->fileStruct;
    }
    if (fd < NX_VFD_BASE || fd >= NX_VFD_BASE + NX_VFD_MAX) return VFD_SLOT_NONE;
    return fd - NX_VFD_BASE;
}

static inline int  is_vfd(int fd)  { return vfd_slot_of(fd) != VFD_SLOT_NONE; }
static inline vfd_t* V(int fd)     { return &g_v[vfd_slot_of(fd)]; }
static inline size_t rused(vfd_t* v){ return v->wr - v->rd; }

int nx_vfd_is(int fd) {
    int slot = vfd_slot_of(fd);
    return slot != VFD_SLOT_NONE && g_v[slot].kind != VK_FREE;
}

// Give a slot a guest-visible fd number. Deliberately NOT done in slot_alloc(): nx_connect creates
// a peer slot that sits on a listener's backlog and may never be accepted, so slots and fds have
// independent lifetimes and a slot must be publishable exactly once, when it is handed to the guest.
// Returns -1 with errno set (ENFILE/ENOMEM from __alloc_handle) if no handle is available.
static int vfd_publish(int slot) {
    if (!lowfd_mode()) return NX_VFD_BASE + slot;
    int fd = __alloc_handle(g_kxvfd_device);
    if (fd < 0) return -1;
    *(int*)__get_handle(fd)->fileStruct = slot;
    return fd;
}

// Publish a freshly-initialised slot, returning it to the pool if no handle is available. Call with
// g_mx held. Without the rollback an exhausted handle table would strand slots permanently, turning
// a recoverable ENFILE into a slow leak of the 256-slot pool.
static int vfd_publish_or_free(int slot) {
    int fd = vfd_publish(slot);
    if (fd < 0) {
        int saved_errno = errno;
        free(g_v[slot].buf);
        memset(&g_v[slot], 0, sizeof g_v[slot]);
        g_v[slot].kind = VK_FREE;
        errno = saved_errno;
    }
    return fd;
}

// v2 data-op guard (Phase A): true only for a REAL SD-file fd, so the data funnel skips std fds, vfds
// (>=NX_VFD_BASE), stdout/err tee-dup targets, and reg*.tmp discard fds (all handled on the caller thread).
//
// M2.8: a libnx bsd socket is ALSO a plain newlib fd > 2 and passes every other test here, so it must
// be excluded explicitly. Without this a blocking guest recv() is enqueued onto the single fsdev
// worker and executed there — the worker then sits in the socket read while its producer parks in
// svcWaitForAddress(-1), and ALL guest file I/O in the process stops until a packet arrives. That is a
// deadlock, not a slowdown, so this one predicate is what gates every funnel call site (read/write/
// pread/pwrite/writev in x64syscall.c + nx_posix.c, and the mmap fill in nx_virtmem.c).
int nx_fs_real_file(int fd) {
    return fd > 2 && !nx_vfd_is(fd) && !nx_tee_origin(fd) && !nx_regtmp_is(fd) && !nx_net_is_socket(fd);
}

static int slot_alloc(void) {          // g_mx held
    for (int i = 0; i < NX_VFD_MAX; i++)
        if (g_v[i].kind == VK_FREE) {
            memset(&g_v[i], 0, sizeof g_v[i]);
            g_v[i].refs = 1; g_v[i].peer = -1;
            g_v[i].ino  = g_ino_next++;
            g_v[i].kind = VK_TAKEN;    // reserve NOW: a second slot_alloc under the same g_mx hold
            return i;                  // must not return this slot again (make_pair got a==b: every
        }                              // pipe/socketpair was ONE self-peered fd — no EOF/POLLHUP,
    return -1;                         // and both guests shared one refcount on the "two" ends)
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
    int fd = vfd_publish_or_free(i);
    pthread_mutex_unlock(&g_mx);
    return fd;
}

// A write-discard sink vfd. The wineserver's periodic registry flush writes each branch to a
// reg<pid>.tmp then renames it over the .reg — but registry PERSISTENCE is irrelevant to the
// tests, and doing the real save is both slow (fsdev) AND fragile: the raw open() of a reg file
// can transiently FAIL (e88/ENOSYS — seen under the shared-fd-table pressure of a big dir
// enumeration), and the existing "discard the writes" nerf never engages because it only marks a
// reg*.tmp fd AFTER a successful open — so the failed open loops forever (registry-save livelock:
// `directory` hung ~1/6). Routing reg*.tmp to a SINK vfd makes the open ALWAYS succeed WITHOUT
// consuming a scarce newlib fd: writes are dropped, read is EOF, and the reg*.tmp->*.reg rename is
// already short-circuited (nx_rename_guest). The real .reg files stay intact for a fast next-run.
int nx_vfd_open_sink(void) {
    pthread_mutex_lock(&g_mx);
    int i = slot_alloc();
    if (i < 0) { pthread_mutex_unlock(&g_mx); errno = EMFILE; return -1; }
    g_v[i].kind = VK_SINK;
    int fd = vfd_publish_or_free(i);
    pthread_mutex_unlock(&g_mx);
    return fd;
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
    if (v->kind != VK_DIR && v->kind != VK_TMPDIR) { errno = ENOTDIR; return -1; }
    { static int on = -1; if (on < 0) on = getenv("KX_REQLOG") ? 1 : 0;
      if (on) vlog("nx_vfd: GETDENTS pid=%d fd=%d dir='%s'\n", nx_guest_pid(), fd, v->guest); }
    // Snapshot the directory ONCE on the first getdents (opendir -> readdir all -> closedir), so the
    // open dir vfd holds NO persistent fsdev handle. Serve subsequent getdents from the buffer.
    if (!v->dents) {
        // The whole opendir->readdir*->closedir enumeration (+ its metadata governor) funnels onto the
        // SD I/O worker as ONE job (a DIR* handle can't cross threads mid-iteration): it is a real fsdev
        // burst that does NOT pass through nx_translate_path, so funneling it keeps a readdir storm
        // (dirstress) from anti-scaling onto the serial device. It hands back the malloc'd nx_dent_t[]
        // snapshot + count + capacity; the dosdevices synth below stays on THIS thread (pure memory).
        if (v->kind == VK_TMPDIR) {
            if (nx_tmpfs_fill_dents(v) < 0) return -1;   // RAM /tmp: enumerate the node table (no fsdev)
        } else {
        int cap = 0;
        if (nx_fs_getdents(v->host, &v->dents, &v->dent_n, &cap) < 0) return -1;   // errno set (ENOENT/ENOMEM)
        v->dent_i = 0;
        // M2.5: Windows can't create "z:"/"c:" files on the SD, so synthesize the DOS-drive entries
        // for a $WINEPREFIX/dosdevices dir; Wine readlink()s each (z:->/, <x>:->drive_<x>).
        size_t gl = strlen(v->guest);
        if (gl >= 11 && !strcmp(v->guest + gl - 11, "/dosdevices")) {
            if (v->dent_n + 2 > cap) {           // ensure room for the 2 synth entries (worker may size tight)
                int nc = v->dent_n + 2;
                nx_dent_t* nn = (nx_dent_t*)realloc(v->dents, (size_t)nc * sizeof(nx_dent_t));
                if (nn) { v->dents = nn; cap = nc; }
            }
            static const char* drives[] = { "z:", "c:" };
            for (int k = 0; k < 2 && v->dent_n < cap; k++) {
                snprintf(v->dents[v->dent_n].name, sizeof v->dents[0].name, "%s", drives[k]);
                v->dents[v->dent_n].type = 10;   // DT_LNK
                v->dent_n++;
            }
        }
        }
    }
    // Serve buffered entries into the caller's getdents64 buffer (Linux layout: d_ino u64, d_off s64,
    // d_reclen u16, d_type u8, name...). d_off is an opaque cookie; Wine/glibc read sequentially.
    uint8_t* out = (uint8_t*)ubuf; size_t off = 0;
    while (v->dent_i < v->dent_n) {
        const char* name = v->dents[v->dent_i].name;
        size_t nl = strlen(name);
        size_t rl = (19 + nl + 1 + 7) & ~(size_t)7;
        if (off + rl > count) { if (off == 0) { errno = EINVAL; return -1; } break; }
        *(uint64_t*)(out + off)      = v->ino + (unsigned)(v->dent_i + 1);
        *(int64_t*) (out + off + 8)  = (int64_t)(v->dent_i + 1);
        *(uint16_t*)(out + off + 16) = (uint16_t)rl;
        out[off + 18] = v->dents[v->dent_i].type;
        memcpy(out + off + 19, name, nl + 1);
        off += rl;
        v->dent_i++;
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
    if (v->kind == VK_TMPFILE || v->kind == VK_TMPDIR) return nx_tmpfs_fstat_body(v, st);   // RAM /tmp
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
    if (v->kind == VK_SINK) {
        st->st_mode = S_IFREG | 0600; st->st_size = 0;   // discard sink (reg*.tmp): empty regular file
    } else if (v->kind == VK_SHMEM || v->kind == VK_LOCK) {
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
    int fd = vfd_publish_or_free(i);
    if (fd < 0 && g_sh[si].refs > 0) g_sh[si].refs--;   // undo the shobj_get reference
    pthread_mutex_unlock(&g_mx);
    if (fd < 0) return -1;
    vlog("nx_vfd: open %s '%s' -> vfd=%d pid=%d\n", is_lock ? "LOCK" : "SHMEM",
         guestpath, fd, nx_guest_pid());
    return fd;
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
    if (nx_vfd_is(fd) && V(fd)->kind == VK_SINK) { (void)len; return 0; }   // discard sink: accept
    if (nx_vfd_is(fd) && V(fd)->kind == VK_TMPFILE) return nx_tmpfs_ftruncate_body(V(fd), len);  // RAM /tmp
    if (!nx_vfd_is(fd) || V(fd)->kind != VK_SHMEM) { errno = EINVAL; return -1; }
    pthread_mutex_lock(&g_mx);
    int r = shmem_ensure(&g_sh[V(fd)->shobj], (size_t)len);
    pthread_mutex_unlock(&g_mx);
    return r;
}

// mmap of a VK_SHMEM fd: return the shared buffer + offset (same address for every mapper).
void* nx_vfd_mmap(int fd, size_t length, off_t offset) {
    if (nx_vfd_is(fd) && V(fd)->kind == VK_TMPFILE) return nx_tmpfs_mmap_body(V(fd), length, offset);  // RAM /tmp
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
    if (nx_vfd_is(fd) && V(fd)->kind == VK_SINK) return (whence == 0) ? (long)off : 0;  // sink: accept
    if (nx_vfd_is(fd) && V(fd)->kind == VK_TMPFILE) return nx_tmpfs_lseek_body(V(fd), off, whence);  // RAM /tmp
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

// ---- RAM-backed /tmp tmpfs (Phase C) -----------------------------------------------------------
// Guest /tmp is served ENTIRELY from RAM (no fsdev, no SD) so a temp-file storm (floodmeta's
// /tmp/kx-meta scratch, Wine's TMPDIR=/tmp churn) stops anti-scaling onto the serial SD device. A flat
// in-RAM node table keyed by absolute normalized path (dirs are nodes too, so getdents/rmdir work);
// file I/O mirrors the VK_SHMEM RAM-buffer bodies. Reuses the vfd fd-space (VK_TMPFILE/VK_TMPDIR) +
// dispatch. Gate KX_NO_TMPFS; hard byte cap KX_TMPFS_CAP_MB (ENOSPC on overflow — no SD spill in v1).
#define NX_TMPFS_MAX 2048
typedef struct {
    int           used, is_dir, unlinked, refs, mmapped, next;   // next = hash-bucket chain link (-1 end)
    unsigned      hash;                    // FNV-1a 32 of path — bucket key
    unsigned long ino;                     // FNV-1a 64 of path — stat identity (never 0)
    char          path[256];               // absolute normalized guest path
    uint8_t*      data; size_t size, cap;  // file contents (NULL/0 until first write); dirs: none
    long          mtime;
} tnode_t;
#define NX_TMPFS_BUCKETS 2048              // power of 2 (& mask); ~1 node/bucket at full occupancy
static tnode_t g_tn[NX_TMPFS_MAX];
static int     g_tn_bkt[NX_TMPFS_BUCKETS]; // per-bucket head slot (-1 empty) — O(1) hashed lookup
static int     g_tn_free[NX_TMPFS_MAX];    // free-slot stack — O(1) alloc (no linear scan under the lock)
static int     g_tn_free_n = -1;           // -1 until tn_init()
static pthread_mutex_t g_tmpfs_mx = PTHREAD_MUTEX_INITIALIZER;
static size_t g_tmpfs_bytes = 0, g_tmpfs_cap = 0;
static long   g_tmpfs_mtime = 1;

static int nx_tmpfs_enabled(void) { static int on = -1; if (on < 0) on = getenv("KX_NO_TMPFS") ? 0 : 1; return on; }
static size_t nx_tmpfs_capbytes(void) {
    if (!g_tmpfs_cap) { const char* c = getenv("KX_TMPFS_CAP_MB"); int mb = c ? atoi(c) : 64;
                        if (mb < 1) mb = 1; g_tmpfs_cap = (size_t)mb * 1024 * 1024; }
    return g_tmpfs_cap;
}
// Is `p` under the RAM /tmp? Matches "/tmp" and "/tmp/…" only (never /run/user/0/wine/* — those stay
// VK_SHMEM/VK_LOCK). Off => 0, so /tmp falls back to the SD as before (KX_NO_TMPFS A/B).
int nx_tmpfs_is_path(const char* p) {
    return nx_tmpfs_enabled() && p && (!strcmp(p, "/tmp") || !strncmp(p, "/tmp/", 5));
}
static unsigned tfnv32(const char* s){ unsigned h=2166136261u; for(;*s;++s){ h^=(unsigned char)*s; h*=16777619u; } return h; }
static unsigned long tfnv64(const char* s){ unsigned long h=1469598103934665603UL; for(;*s;++s){ h^=(unsigned char)*s; h*=1099511628211UL; } return h?h:1; }

static void tn_init(void) {   // g_tmpfs_mx held; lazy one-time bucket-head + free-list init
    if (g_tn_free_n >= 0) return;
    for (int i = 0; i < NX_TMPFS_BUCKETS; i++) g_tn_bkt[i] = -1;
    for (int i = 0; i < NX_TMPFS_MAX; i++) g_tn_free[i] = NX_TMPFS_MAX - 1 - i;  // pop order 0,1,2,…
    g_tn_free_n = NX_TMPFS_MAX;
}
static int tn_find(const char* p, unsigned h) {   // g_tmpfs_mx held; O(1); skips unlinked-but-open nodes
    tn_init();
    for (int i = g_tn_bkt[h & (NX_TMPFS_BUCKETS - 1)]; i >= 0; i = g_tn[i].next)
        if (!g_tn[i].unlinked && g_tn[i].hash == h && !strcmp(g_tn[i].path, p)) return i;
    return -1;
}
static int tn_new(const char* p, int is_dir) {    // g_tmpfs_mx held; O(1); -1 (ENOSPC) if the table is full
    tn_init();
    if (g_tn_free_n == 0) { errno = ENOSPC; return -1; }
    int i = g_tn_free[--g_tn_free_n];
    memset(&g_tn[i], 0, sizeof g_tn[i]);
    g_tn[i].used = 1; g_tn[i].is_dir = is_dir;
    g_tn[i].hash = tfnv32(p); g_tn[i].ino = tfnv64(p);
    snprintf(g_tn[i].path, sizeof g_tn[i].path, "%s", p);
    g_tn[i].mtime = g_tmpfs_mtime++;
    unsigned b = g_tn[i].hash & (NX_TMPFS_BUCKETS - 1);   // prepend to bucket chain
    g_tn[i].next = g_tn_bkt[b]; g_tn_bkt[b] = i;
    return i;
}
static void tn_free_data(tnode_t* n){ if (n->data) { g_tmpfs_bytes = (g_tmpfs_bytes>=n->cap)?g_tmpfs_bytes-n->cap:0; free(n->data); n->data=NULL; n->size=n->cap=0; } }
static void tn_remove(int idx) {   // g_tmpfs_mx held; unlink from its bucket chain + return the slot to the free-list
    tn_free_data(&g_tn[idx]);
    unsigned b = g_tn[idx].hash & (NX_TMPFS_BUCKETS - 1);
    int* pp = &g_tn_bkt[b];
    while (*pp >= 0 && *pp != idx) pp = &g_tn[*pp].next;
    if (*pp == idx) *pp = g_tn[idx].next;
    memset(&g_tn[idx], 0, sizeof g_tn[idx]);
    g_tn_free[g_tn_free_n++] = idx;
}
static void tn_rebucket(int idx, const char* newpath) {   // g_tmpfs_mx held; move a node to a new path/bucket (rename)
    unsigned ob = g_tn[idx].hash & (NX_TMPFS_BUCKETS - 1);
    int* pp = &g_tn_bkt[ob];
    while (*pp >= 0 && *pp != idx) pp = &g_tn[*pp].next;
    if (*pp == idx) *pp = g_tn[idx].next;
    snprintf(g_tn[idx].path, sizeof g_tn[idx].path, "%s", newpath);
    g_tn[idx].hash = tfnv32(newpath); g_tn[idx].ino = tfnv64(newpath);
    unsigned nb = g_tn[idx].hash & (NX_TMPFS_BUCKETS - 1);
    g_tn[idx].next = g_tn_bkt[nb]; g_tn_bkt[nb] = idx;
}
static int tn_ensure(tnode_t* n, size_t need) {   // g_tmpfs_mx held; grow data to >= need; honors the cap
    if (n->cap >= need) return 0;
    if (n->mmapped) { errno = EBUSY; return -1; }        // pinned by an mmap — cannot move
    size_t ncap = n->cap ? n->cap : 4096;
    while (ncap < need) ncap *= 2;
    size_t delta = ncap - n->cap;
    if (g_tmpfs_bytes + delta > nx_tmpfs_capbytes()) { errno = ENOSPC; return -1; }
    uint8_t* nd = (uint8_t*)realloc(n->data, ncap);
    if (!nd) { errno = ENOMEM; return -1; }
    g_tmpfs_bytes += delta; n->data = nd; n->cap = ncap;
    return 0;
}
static void tn_release(int idx) {   // g_tmpfs_mx held; drop one open ref, free if unlinked + unreferenced
    if (g_tn[idx].refs > 0) g_tn[idx].refs--;
    if (g_tn[idx].refs == 0 && g_tn[idx].unlinked) tn_remove(idx);
}

// ---- tmpfs path ops (extern: called from nx_posix.c openat/fstatat + the mutation helpers) --------
// openat flags arrive HOST-converted (box64 applies of_convert before dispatch), so O_* are newlib bits.
int nx_tmpfs_openat(const char* p, int flags, mode_t mode) {
    (void)mode;
    pthread_mutex_lock(&g_mx);
    int vi = slot_alloc();
    if (vi < 0) { pthread_mutex_unlock(&g_mx); errno = EMFILE; return -1; }
    pthread_mutex_lock(&g_tmpfs_mx);
    unsigned h = tfnv32(p);
    int idx = tn_find(p, h);
    int want_dir = (flags & O_DIRECTORY) != 0;
    int fail = 0;
    if (idx < 0) {
        if (!(flags & O_CREAT) || want_dir) { errno = ENOENT; fail = 1; }
        else { idx = tn_new(p, 0); if (idx < 0) fail = 1; }   // create a regular file (errno=ENOSPC on fail)
    } else {
        if ((flags & O_CREAT) && (flags & O_EXCL) && !g_tn[idx].is_dir) { errno = EEXIST; fail = 1; }
        else if (want_dir && !g_tn[idx].is_dir)                         { errno = ENOTDIR; fail = 1; }
        else if (!want_dir && g_tn[idx].is_dir && (flags & 3) != 0)     { errno = EISDIR; fail = 1; }
        else if ((flags & O_TRUNC) && !g_tn[idx].is_dir) { tn_free_data(&g_tn[idx]); g_tn[idx].size = 0; }
    }
    if (fail) { g_v[vi].kind = VK_FREE; pthread_mutex_unlock(&g_tmpfs_mx); pthread_mutex_unlock(&g_mx); return -1; }
    int is_dir = g_tn[idx].is_dir;
    g_tn[idx].refs++;
    g_v[vi].kind  = is_dir ? VK_TMPDIR : VK_TMPFILE;
    g_v[vi].shobj = idx;
    g_v[vi].fpos  = 0;
    snprintf(g_v[vi].guest, sizeof g_v[vi].guest, "%s", p);   // dir path for getdents; else diagnostics
    int fd = vfd_publish_or_free(vi);
    if (fd < 0) tn_release(idx);            // undo the node ref taken just above
    pthread_mutex_unlock(&g_tmpfs_mx);
    pthread_mutex_unlock(&g_mx);
    return fd;
}
int nx_tmpfs_stat(const char* p, struct stat* st) {
    pthread_mutex_lock(&g_tmpfs_mx);
    int idx = tn_find(p, tfnv32(p));
    if (idx < 0) { pthread_mutex_unlock(&g_tmpfs_mx); errno = ENOENT; return -1; }
    tnode_t* n = &g_tn[idx];
    memset(st, 0, sizeof *st);
    st->st_dev = 1; st->st_ino = n->ino; st->st_nlink = 1; st->st_blksize = 4096;
    st->st_mode = n->is_dir ? (S_IFDIR | 0700) : (S_IFREG | 0600);
    st->st_size = n->is_dir ? 0 : (off_t)n->size;
    st->st_blocks = (st->st_size + 511) / 512;
    st->st_mtime = st->st_ctime = st->st_atime = n->mtime;
    pthread_mutex_unlock(&g_tmpfs_mx);
    return 0;
}
int nx_tmpfs_mkdir(const char* p, mode_t mode) {
    (void)mode;
    pthread_mutex_lock(&g_tmpfs_mx);
    int idx = tn_find(p, tfnv32(p));
    if (idx >= 0) { pthread_mutex_unlock(&g_tmpfs_mx); errno = EEXIST; return -1; }
    idx = tn_new(p, 1);
    pthread_mutex_unlock(&g_tmpfs_mx);
    return idx < 0 ? -1 : 0;
}
int nx_tmpfs_unlink(const char* p) {
    pthread_mutex_lock(&g_tmpfs_mx);
    int idx = tn_find(p, tfnv32(p));
    if (idx < 0) { pthread_mutex_unlock(&g_tmpfs_mx); errno = ENOENT; return -1; }
    tnode_t* n = &g_tn[idx];
    if (n->is_dir) { pthread_mutex_unlock(&g_tmpfs_mx); errno = EISDIR; return -1; }
    n->unlinked = 1;                                     // hidden from tn_find; freed on last close
    if (n->refs == 0) tn_remove(idx);
    pthread_mutex_unlock(&g_tmpfs_mx);
    return 0;
}
int nx_tmpfs_rmdir(const char* p) {
    pthread_mutex_lock(&g_tmpfs_mx);
    int idx = tn_find(p, tfnv32(p));
    if (idx < 0) { pthread_mutex_unlock(&g_tmpfs_mx); errno = ENOENT; return -1; }
    if (!g_tn[idx].is_dir) { pthread_mutex_unlock(&g_tmpfs_mx); errno = ENOTDIR; return -1; }
    size_t pl = strlen(p);
    for (int i = 0; i < NX_TMPFS_MAX; i++)               // reject if any live child exists
        if (g_tn[i].used && !g_tn[i].unlinked && i != idx &&
            !strncmp(g_tn[i].path, p, pl) && g_tn[i].path[pl] == '/') {
            pthread_mutex_unlock(&g_tmpfs_mx); errno = ENOTEMPTY; return -1; }
    tn_remove(idx);
    pthread_mutex_unlock(&g_tmpfs_mx);
    return 0;
}
int nx_tmpfs_rename(const char* a, const char* b) {      // both sides already known to be /tmp
    pthread_mutex_lock(&g_tmpfs_mx);
    int ia = tn_find(a, tfnv32(a));
    if (ia < 0) { pthread_mutex_unlock(&g_tmpfs_mx); errno = ENOENT; return -1; }
    int ib = tn_find(b, tfnv32(b));
    if (ib >= 0) {                                       // replace an existing target (not a dir)
        if (g_tn[ib].is_dir) { pthread_mutex_unlock(&g_tmpfs_mx); errno = EISDIR; return -1; }
        g_tn[ib].unlinked = 1;
        if (g_tn[ib].refs == 0) tn_remove(ib);
    }
    tn_rebucket(ia, b);
    pthread_mutex_unlock(&g_tmpfs_mx);
    return 0;                                            // NB: renaming a DIR strands its children (v1 limit)
}
int nx_tmpfs_access(const char* p, int mode) {
    (void)mode;
    pthread_mutex_lock(&g_tmpfs_mx);
    int idx = tn_find(p, tfnv32(p));
    pthread_mutex_unlock(&g_tmpfs_mx);
    if (idx < 0) { errno = ENOENT; return -1; }
    return 0;
}

// ---- tmpfs open-fd bodies (called from the vfd dispatch cases; operate on the node via v->shobj) --
static long nx_tmpfs_read_body(vfd_t* v, void* buf, size_t n) {
    pthread_mutex_lock(&g_tmpfs_mx);
    tnode_t* nd = &g_tn[v->shobj];
    size_t avail = (v->fpos < nd->size) ? nd->size - v->fpos : 0;
    size_t k = n < avail ? n : avail;
    if (k && nd->data) memcpy(buf, nd->data + v->fpos, k);
    v->fpos += k;
    pthread_mutex_unlock(&g_tmpfs_mx);
    return (long)k;
}
static long nx_tmpfs_write_body(vfd_t* v, const void* buf, size_t n) {
    pthread_mutex_lock(&g_tmpfs_mx);
    tnode_t* nd = &g_tn[v->shobj];
    if (tn_ensure(nd, v->fpos + n) != 0) { int e = errno; pthread_mutex_unlock(&g_tmpfs_mx); errno = e; return -1; }
    memcpy(nd->data + v->fpos, buf, n);
    v->fpos += n;
    if (v->fpos > nd->size) nd->size = v->fpos;
    pthread_mutex_unlock(&g_tmpfs_mx);
    return (long)n;
}
static long nx_tmpfs_lseek_body(vfd_t* v, off_t off, int whence) {
    pthread_mutex_lock(&g_tmpfs_mx);
    tnode_t* nd = &g_tn[v->shobj];
    size_t np = (whence == 1) ? v->fpos + off : (whence == 2) ? nd->size + off : (size_t)off;
    v->fpos = np;
    pthread_mutex_unlock(&g_tmpfs_mx);
    return (long)np;
}
static int nx_tmpfs_ftruncate_body(vfd_t* v, off_t len) {
    pthread_mutex_lock(&g_tmpfs_mx);
    tnode_t* nd = &g_tn[v->shobj];
    int r = 0;
    if ((size_t)len > nd->cap) r = tn_ensure(nd, (size_t)len);
    if (r == 0) { if ((size_t)len > nd->size && nd->data) memset(nd->data + nd->size, 0, (size_t)len - nd->size);
                  nd->size = (size_t)len; }
    int e = errno; pthread_mutex_unlock(&g_tmpfs_mx); errno = e;
    return r;
}
static void* nx_tmpfs_mmap_body(vfd_t* v, size_t length, off_t offset) {
    pthread_mutex_lock(&g_tmpfs_mx);
    tnode_t* nd = &g_tn[v->shobj];
    if (tn_ensure(nd, (size_t)offset + length) != 0) { int e=errno; pthread_mutex_unlock(&g_tmpfs_mx); errno=e; return (void*)-1; }
    if ((size_t)offset + length > nd->size) nd->size = (size_t)offset + length;
    nd->mmapped = 1;                                    // pin: no realloc-move after a mapping exists
    void* ret = nd->data + offset;
    pthread_mutex_unlock(&g_tmpfs_mx);
    return ret;
}
static int nx_tmpfs_fstat_body(vfd_t* v, struct stat* st) {
    pthread_mutex_lock(&g_tmpfs_mx);
    tnode_t* nd = &g_tn[v->shobj];
    memset(st, 0, sizeof *st);
    st->st_dev = 1; st->st_ino = nd->ino; st->st_nlink = 1; st->st_blksize = 4096;
    st->st_mode = nd->is_dir ? (S_IFDIR | 0700) : (S_IFREG | 0600);
    st->st_size = nd->is_dir ? 0 : (off_t)nd->size;
    st->st_blocks = (st->st_size + 511) / 512;
    st->st_mtime = st->st_ctime = st->st_atime = nd->mtime;
    pthread_mutex_unlock(&g_tmpfs_mx);
    return 0;
}
// Snapshot the DIRECT children of the dir path v->guest into v->dents (name + d_type), so the shared
// getdents64 serve loop below can stream them. Enumerates the live RAM table (no fsdev).
static int nx_tmpfs_fill_dents(vfd_t* v) {
    size_t pl = strlen(v->guest);
    int cap = 64;
    v->dents = (nx_dent_t*)malloc((size_t)cap * sizeof(nx_dent_t));
    if (!v->dents) { errno = ENOMEM; return -1; }
    v->dent_n = 0; v->dent_i = 0;
    pthread_mutex_lock(&g_tmpfs_mx);
    for (int i = 0; i < NX_TMPFS_MAX; i++) {
        if (!g_tn[i].used || g_tn[i].unlinked) continue;
        const char* q = g_tn[i].path;
        if (strncmp(q, v->guest, pl) || q[pl] != '/') continue;   // not under this dir
        const char* name = q + pl + 1;
        if (strchr(name, '/')) continue;                          // not a DIRECT child
        if (v->dent_n == cap) { int nc = cap*2; nx_dent_t* nn = (nx_dent_t*)realloc(v->dents, (size_t)nc*sizeof(nx_dent_t));
                                if (!nn) break; v->dents = nn; cap = nc; }
        snprintf(v->dents[v->dent_n].name, sizeof v->dents[0].name, "%s", name);
        v->dents[v->dent_n].type = g_tn[i].is_dir ? 4 : 8;        // DT_DIR / DT_REG
        v->dent_n++;
    }
    pthread_mutex_unlock(&g_tmpfs_mx);
    return 0;
}

// ---- close / read / write ----------------------------------------------------------------------

// Tear down a slot and return it to the pool. Keyed on the SLOT, never on an fd: newlib's _close_r
// clears handles[fd] BEFORE invoking close_r, so V(fd) would already fail by the time the teardown
// runs. Idempotent — a slot already VK_FREE is left alone.
static void vfd_slot_free(int slot) {
    if (slot < 0 || slot >= NX_VFD_MAX) return;
    pthread_mutex_lock(&g_mx);
    vfd_t* v = &g_v[slot];
    if (v->kind == VK_FREE) { pthread_mutex_unlock(&g_mx); return; }
    if ((v->kind == VK_LOCK || v->kind == VK_SHMEM) && v->shobj >= 0) {
        shobj_t* o = &g_sh[v->shobj];
        if (v->kind == VK_LOCK && o->lock_owner == nx_guest_pid()) o->lock_owner = 0;
        if (o->refs > 0) o->refs--;   // keep mem/lock alive while other fds reference it
    }
    if (v->kind == VK_TMPFILE || v->kind == VK_TMPDIR) {   // drop the tmpfs node ref (frees if unlinked)
        pthread_mutex_lock(&g_tmpfs_mx); tn_release(v->shobj); pthread_mutex_unlock(&g_tmpfs_mx);
    }
    if (v->kind == VK_DIR || v->kind == VK_TMPDIR) { if (v->d) closedir(v->d); free(v->dents); }
    if ((v->kind == VK_PIPE || v->kind == VK_SOCK) && v->peer >= 0 && g_v[v->peer].kind != VK_FREE)
        g_v[v->peer].peer = -1;              // peer sees EOF/EPIPE
    if (v->kind == VK_LISTEN)
        // Un-accepted backlog entries have a SLOT but no fd (nx_accept4 is what publishes one), so
        // there is no handle to release — free them directly, including any ring the connector
        // already wrote into.
        for (int i = 0; i < v->backlog_n; i++) {
            vfd_t* pending = &g_v[v->backlog[i]];
            if (pending->kind == VK_FREE) continue;
            free(pending->buf);
            memset(pending, 0, sizeof *pending);
            pending->kind = VK_FREE;
        }
    free(v->buf);
    if (v->kind == VK_EPOLL) free(v->epset);
    // Unclaimed passed fds: drop our reference. A queued REAL fd is a dup() this layer made in
    // nx_sendmsg, so it is ours to close — leaving it open leaked a newlib handle slot and, for a
    // socket, a bsd descriptor too. ws2_32 passes socket fds constantly, and both pools are finite
    // (1024 handles, FDQ_MAX 256 per vfd), so the leak is reachable rather than theoretical.
    for (int i = 0; i < v->fdq_n; i++) {
        int queued_fd = v->fdq[i].fd;
        pthread_mutex_unlock(&g_mx);
        if (nx_vfd_is(queued_fd)) nx_vfd_close(queued_fd);
        else close(queued_fd);
        pthread_mutex_lock(&g_mx);
    }
    memset(v, 0, sizeof *v);
    v->kind = VK_FREE;
    pthread_cond_broadcast(&g_cv);
    pthread_mutex_unlock(&g_mx);
}

// newlib calls this once the LAST fd naming a vfd is closed (its handle refcount hit 0), which is
// what makes dup()/dup2() on a vfd correct without any refcounting of our own.
static int kxvfd_close_r(struct _reent* r, void* fileStruct) {
    (void)r;
    vfd_slot_free(*(int*)fileStruct);
    return 0;
}

int nx_vfd_close(int fd) {
    if (!nx_vfd_is(fd)) { errno = EBADF; return -1; }
    // LOWFD: newlib owns the fd and its refcount; the teardown runs from kxvfd_close_r at zero.
    // Never call __release_handle here — it frees the handle WITHOUT consulting the refcount, so it
    // would pull the object out from under any dup() still naming it.
    if (lowfd_mode()) return close(fd);
    pthread_mutex_lock(&g_mx);
    vfd_t* v = V(fd);
    if (--v->refs > 0) { pthread_mutex_unlock(&g_mx); return 0; }
    pthread_mutex_unlock(&g_mx);
    vfd_slot_free(fd - NX_VFD_BASE);
    return 0;
}

// Wake every thread parked in a vfd wait (pipe/socketpair read, poll, select, epoll_wait). Used by the
// directed-signal path (nx_signals.c): a thread queued a signal for another thread, and the target may
// be blocked here rather than at a syscall boundary where it would notice on its own. The waiters
// re-check their own condition after waking, so a spurious broadcast is harmless.
void nx_vfd_wake_all(void) {
    pthread_mutex_lock(&g_mx);
    pthread_cond_broadcast(&g_cv);
    pthread_mutex_unlock(&g_mx);
}

long nx_vfd_read(int fd, void* buf, size_t n) {
    if (!nx_vfd_is(fd)) { errno = EBADF; return -1; }
    if (V(fd)->kind == VK_SINK) { (void)buf; (void)n; return 0; }   // discard sink: always EOF
    if (V(fd)->kind == VK_SHMEM) return shmem_rw(fd, buf, n, 0);
    if (V(fd)->kind == VK_TMPFILE) return nx_tmpfs_read_body(V(fd), buf, n);   // RAM /tmp
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
        if (v->peer < 0 || v->rd_shut) { pthread_mutex_unlock(&g_mx); return 0; }  // EOF (peer closed or shutdown(SHUT_WR))
        if (v->nonblock) { pthread_mutex_unlock(&g_mx); errno = EAGAIN; return -1; }
        { static int on = -1; if (on < 0) on = getenv("KX_REQLOG") ? 1 : 0;
          if (on) vlog("nx_vfd: RDBLK pid=%d tid=%d fd=%d kind=%d peer=%d n=%zu\n",
                       nx_guest_pid(), nx_gettid(), fd, (int)v->kind, v->peer, n); }
        pthread_cond_wait(&g_cv, &g_mx);
        // Deliver here, then ABORT this read with EINTR. Both halves are required.
        //
        // Blocking in this read means a wineserver request is IN FLIGHT — the reply has not arrived.
        // Wine's usr1_handler calls wait_suspend(), which issues its OWN server_select and blocks
        // until the server resumes it. A per-thread server connection carries one request at a time,
        // so letting the handler run while resuming this read leaves two outstanding: the server sees
        // a second request before answering the first, and both sides wait forever (measured: client
        // parked in RDBLK n=16 while the server ran on for another 23 s).
        //
        // A real kernel does not leave the outer call pending either — the signal interrupts it, and
        // Wine's caller re-issues. So drop g_mx (the handler re-enters this layer), run the handler,
        // and return EINTR so that retry actually happens.
        // EINTR only when a handler ACTUALLY ran: with delivery gated off the pending bit is still
        // cleared, and reporting an interruption we did not cause is its own (nondeterministic) bug.
        if (nx_signal_pending_self()) {
            pthread_mutex_unlock(&g_mx);
            int ran = nx_signal_deliver_pending();
            if (ran) { errno = EINTR; return -1; }
            pthread_mutex_lock(&g_mx);
        }
    }
}

// write lands in the PEER's inbound ring
long nx_vfd_write(int fd, const void* buf, size_t n) {
    if (!nx_vfd_is(fd)) { errno = EBADF; return -1; }
    // M2.5 deadlock diag (gated on KX_REQLOG): a wine request header starts with a small int `req`;
    // logging it per write traces the client's LAST server call before a hang — cheap, unlike +server.
    if (buf && n >= 12 && n <= 65536 && nx_vfd_is(fd)) {
        static int on = -1; if (on < 0) on = getenv("KX_REQLOG") ? 1 : 0;
        if (on) { int rq = *(const int*)buf; if (rq > 0 && rq < 256)
            vlog("nx_vfd: REQ pid=%d fd=%d code=%d n=%zu\n", nx_guest_pid(), fd, rq, n); }
    }
    if (V(fd)->kind == VK_SINK) return (long)n;   // discard sink (reg*.tmp): drop the bytes
    if (V(fd)->kind == VK_SHMEM) return shmem_rw(fd, (void*)buf, n, 1);
    if (V(fd)->kind == VK_TMPFILE) {              // RAM /tmp
        if (nx_vfd_buf_bad(buf, n)) { errno = EFAULT; return -1; }
        return nx_tmpfs_write_body(V(fd), buf, n);
    }
    if (nx_vfd_buf_bad(buf, n)) { errno = EFAULT; return -1; }   // bad guest buffer -> -EFAULT, not a fault
    { static int on = -1; if (on < 0) on = getenv("KX_REQLOG") ? 1 : 0;
      if (on) vlog("nx_vfd: VW pid=%d tid=%d fd=%d peer=%d n=%zu\n", nx_guest_pid(), nx_gettid(), fd, V(fd)->peer, n); }
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

// Atomic scatter-write: put ALL iovs into the peer's ring under ONE lock with ONE wakeup, so a reader
// can never observe a partial message. Wine's wineserver reads a request's FIXED header (poll-gated)
// then its VARIABLE data in a BLOCKING loop — it relies on the client's single writev() landing the
// whole request atomically (a <PIPE_BUF pipe write is atomic on Linux). Writing the iovs as separate
// nx_vfd_write()s let the server wake after the header, read it, then block reading data not yet
// written → deadlock. Returns total bytes, or -1/EPIPE. Blocks only if the ring can't hold the burst.
long nx_vfd_writev(int fd, const void* iov, int iovcnt) {
    struct kx_iovec { const void* base; size_t len; };
    const struct kx_iovec* v = (const struct kx_iovec*)iov;
    size_t want = 0;
    for (int i = 0; i < iovcnt; i++) if (v[i].base) want += v[i].len;
    if (!want) return 0;
    if (!nx_vfd_is(fd)) { errno = EBADF; return -1; }
    if (V(fd)->kind == VK_SINK) return (long)want;   // discard sink (reg*.tmp): drop the bytes
    // -EFAULT on a bad guest buffer (Linux writev semantics), NOT a box64 fault -> cascade (see nx_vfd_buf_bad).
    for (int i = 0; i < iovcnt; i++)
        if (nx_vfd_buf_bad(v[i].base, v[i].len)) { errno = EFAULT; return -1; }
    // Trace the request code (first int of the first iov = wine request_header.req) — the loop that
    // wedges the client uses writev, not write, so the nx_vfd_write REQ log misses it.
    { static int on = -1; if (on < 0) on = getenv("KX_REQLOG") ? 1 : 0;
      if (on && v[0].base && v[0].len >= 4) { int rq = *(const int*)v[0].base;
        if (rq > 0 && rq < 256) vlog("nx_vfd: REQV pid=%d fd=%d code=%d want=%zu\n", nx_guest_pid(), fd, rq, want);
        // Decode a `select` (code 28) to identify the awaited object: request_header(12)+flags(4)+
        // cookie(8)+timeout(8 @+24). iov[1] carries apc_result + select_op (op int + handles). Dump
        // the timeout (infinite=0x7fffffffffffffff) and the select_op vararg hex.
        if (rq == 28 && v[0].len >= 32) {
            long long to = *(const long long*)((const char*)v[0].base + 24);
            char hx[200]; int hn = 0; hx[0] = 0;
            if (iovcnt >= 2 && v[1].base) { size_t m = v[1].len < 64 ? v[1].len : 64;
                for (size_t k = 0; k < m && hn < (int)sizeof hx - 3; k++)
                    hn += snprintf(hx + hn, sizeof hx - hn, "%02x", ((const unsigned char*)v[1].base)[k]); }
            vlog("nx_vfd: SELECT pid=%d timeout=0x%llx iov0len=%zu iov1=%s\n",
                 nx_guest_pid(), to, v[0].len, hx);
        } } }
    pthread_mutex_lock(&g_mx);
    vfd_t* s = V(fd);
    if (s->kind != VK_PIPE && s->kind != VK_SOCK) { pthread_mutex_unlock(&g_mx); errno = EINVAL; return -1; }
    for (;;) {
        if (s->peer < 0) { pthread_mutex_unlock(&g_mx); errno = EPIPE; return -1; }
        vfd_t* p = &g_v[s->peer];
        if (!p->buf) { p->buf = (uint8_t*)malloc(RING_CAP); if (!p->buf) { pthread_mutex_unlock(&g_mx); errno = ENOMEM; return -1; } }
        if (RING_CAP - rused(p) >= want) {                 // whole burst fits: write it all atomically
            for (int i = 0; i < iovcnt; i++) {
                if (!v[i].base) continue;
                const uint8_t* b = (const uint8_t*)v[i].base;
                for (size_t j = 0; j < v[i].len; j++) p->buf[(p->wr + j) % RING_CAP] = b[j];
                p->wr += v[i].len;
            }
            pthread_cond_broadcast(&g_cv);
            pthread_mutex_unlock(&g_mx);
            return (long)want;
        }
        if (s->nonblock) { pthread_mutex_unlock(&g_mx); errno = EAGAIN; return -1; }
        pthread_cond_wait(&g_cv, &g_mx);                   // ring full: wait for the reader to drain
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
    // Publish both ends or neither: a half-created pair would hand the guest one usable fd whose
    // peer slot is stranded, which reads as a pipe that never sees EOF.
    int fd_a = vfd_publish_or_free(a);
    if (fd_a < 0) {                       // a is already back in the pool; b never got a handle
        int saved_errno = errno;
        g_v[b].kind = VK_FREE;
        pthread_mutex_unlock(&g_mx);
        errno = saved_errno;
        return -1;
    }
    int fd_b = vfd_publish_or_free(b);
    if (fd_b < 0) {                       // b is already back in the pool; a is published, so close it
        int saved_errno = errno;
        pthread_mutex_unlock(&g_mx);
        nx_vfd_close(fd_a);
        errno = saved_errno;
        return -1;
    }
    pthread_mutex_unlock(&g_mx);
    fds[0] = fd_a; fds[1] = fd_b;
    vlog("nx_vfd: pair kind=%d [%d,%d] pid=%d\n", (int)kind, fds[0], fds[1], nx_guest_pid());
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
    int fd = vfd_publish_or_free(i);
    pthread_mutex_unlock(&g_mx);
    return fd;
}

int nx_socketpair(int domain, int type, int protocol, int sv[2]) {
    if (domain != 1) { errno = EAFNOSUPPORT; return -1; }
    (void)protocol;
    return make_pair(VK_SOCK, sv, (type & 0x800) ? 1 : 0);
}

// shutdown(SHUT_WR/SHUT_RDWR) half-closes our write side: the PEER's reads see EOF once its ring
// drains. Wine's wineserver sock_check_pollhup probe relies on this (socketpair + SHUT_WR on one
// end, then poll the other for POLLIN/read()==0). A no-op here left the peer's poll timing out ->
// the "sock_init: ERROR in sock_check_pollhup()" message. Real (non-vfd) fds: accept as a no-op.
int nx_shutdown(int fd, int how) {
    if (!nx_vfd_is(fd)) return 0;                     // real fd: nothing to do on Horizon
    pthread_mutex_lock(&g_mx);
    vfd_t* v = V(fd);
    int peer = v->peer;
    if ((v->kind == VK_SOCK || v->kind == VK_PIPE) && peer >= 0 && (how == 1 || how == 2))
        g_v[peer].rd_shut = 1;                        // SHUT_WR/RDWR: peer reads hit EOF when drained
    pthread_cond_broadcast(&g_cv);                    // wake a poll()/read() blocked on the peer
    pthread_mutex_unlock(&g_mx);
    vlog("nx_vfd: shutdown fd=%d how=%d peer=%d pid=%d\n", fd, how, peer, nx_guest_pid());
    return 0;
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
    // The new slot is NOT published here: it goes onto the listener's backlog and only becomes a
    // guest fd if and when accept() takes it.
    s->peer = vfd_slot_of(fd); c->peer = si;
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
    // This is where a backlog slot becomes a guest fd. If no handle is available the connection is
    // lost either way, so tear the slot down rather than strand it — but tell the peer first, or it
    // waits forever on a socket nobody will ever read.
    int accepted_fd = vfd_publish(si);
    if (accepted_fd < 0) {
        int saved_errno = errno;
        if (g_v[si].peer >= 0 && g_v[g_v[si].peer].kind != VK_FREE) g_v[g_v[si].peer].peer = -1;
        free(g_v[si].buf);
        memset(&g_v[si], 0, sizeof g_v[si]);
        g_v[si].kind = VK_FREE;
        pthread_cond_broadcast(&g_cv);
        pthread_mutex_unlock(&g_mx);
        errno = saved_errno;
        return -1;
    }
    pthread_mutex_unlock(&g_mx);
    if (addr && alen && *alen >= 2) { memset(addr, 0, *alen); *(uint16_t*)addr = 1; *alen = 2; }
    return accepted_fd;
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
    // Write the iov bytes FIRST, THEN queue the SCM_RIGHTS fds stamped at the peer's ring position
    // AFTER those bytes (= the END of this message). recvmsg then delivers a queued fd once the reader
    // has consumed up to that mark (rd >= at). Stamping at the END (not the start) is what makes ALL
    // of wine's fd-passing patterns work with one rule: an fd-only send (init reply/wait fds — no iov)
    // stamps at the current position and is delivered the moment the reader reaches it; a "1 dummy byte
    // + fd" send_client_fd stamps after that byte so exactly ONE fd is handed over per receive_fd; and
    // a reply+fd stamps after the reply so the fd rides with that reply — with no over-delivery of a
    // following message's fd and no stranding of an end-stamped fd.
    long total = 0;
    for (size_t i = 0; i < msg->iovlen; i++) {
        if (!msg->iov[i].len) continue;
        long r = nx_vfd_write(fd, msg->iov[i].base, msg->iov[i].len);
        if (r < 0) return total ? total : -1;
        total += r;
        if ((size_t)r < msg->iov[i].len) break;
    }
    if (msg->control && msg->controllen >= sizeof(l_cmsghdr)) {
        pthread_mutex_lock(&g_mx);
        vfd_t* v = V(fd);
        if (v->peer < 0) { pthread_mutex_unlock(&g_mx); errno = EPIPE; return total ? total : -1; }
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
                    if (!lowfd_mode() && nx_vfd_is(passfd)) {
                        // Legacy numbering has no alias fds, so the queued entry IS the sender's
                        // number — bump the object's refcount so it survives the sender's close.
                        g_v[vfd_slot_of(passfd)].refs++;
                    } else {
                        // A real dup() is correct for BOTH kinds here: newlib aliases the handle and
                        // refcounts it, so a passed vfd outlives the sender's close on its own.
                        int d = dup(passfd);
                        if (d >= 0) {
                            if (!nx_vfd_is(passfd)) { tee_mark(d, passfd); nx_net_shadow_dup(passfd, d); }
                            passfd = d;
                        } else vlog("nx_vfd: dup(%d) fail e=%d\n", passfd, errno);
                    }
                    p->fdq[p->fdq_n].fd = passfd;
                    p->fdq[p->fdq_n].at = p->wr;   // END of this message (iov already written above)
                    p->fdq_n++;
                    { static int on = -1; if (on < 0) on = getenv("KX_REQLOG") ? 1 : 0;
                      if (on) vlog("nx_vfd: FDQ+ pid=%d peer=%d fd=%d at=%zu q=%d\n",
                                   nx_guest_pid(), v->peer, passfd, (size_t)p->wr, p->fdq_n); }
                }
            }
            size_t adv = (cm->len + 7) & ~(size_t)7;
            if (adv >= rem) break;
            c += adv; rem -= adv;
        }
        pthread_mutex_unlock(&g_mx);
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
        // Deliver queued SCM_RIGHTS fds whose stamped position has been reached (`at <= rd`). Wine
        // sends most fds fd-only (no iov bytes) AFTER their reply — the init reply/wait fds and the
        // get_handle_fd fds sit at the EXACT end of the consumed bytes, so `<` strands them and the
        // client deadlocks waiting for a fd the server already sent (e.g. the locale.nls mapping fd).
        // (An earlier attempt to also gate on `rused==0` to avoid over-delivering a pipelined next
        // message's fd instead RE-STRANDED these end-stamped fds — `<=` is the correct, verified rule.)
        while (v->fdq_n && nout < nfit && v->fdq[0].at <= v->rd) {
            fda[nout++] = v->fdq[0].fd;
            memmove(v->fdq, v->fdq + 1, --v->fdq_n * sizeof(fdpass_t));
        }
        { static int on = -1; if (on < 0) on = getenv("KX_REQLOG") ? 1 : 0;
          if (on && (v->fdq_n || nout)) vlog("nx_vfd: FDQ- pid=%d fd=%d rd=%zu front_at=%zu nout=%d q=%d nfit=%d\n",
                   nx_guest_pid(), fd, (size_t)v->rd, v->fdq_n ? (size_t)v->fdq[0].at : 0, nout, v->fdq_n, nfit); }
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
        if (rused(v) || v->rd_shut) re |= 0x001;                         // POLLIN: buffered data, or drained after peer shutdown(SHUT_WR) -> read()==0 EOF
        if (v->peer < 0) re |= 0x010;                                    // POLLHUP: peer closed
        else if (RING_CAP - rused(&g_v[v->peer]) > 0) re |= 0x004;       // POLLOUT
        // wineserver's sock_check_pollhup expects EXACTLY POLLHUP on a drained hung-up socket, so
        // do NOT add POLLIN on hangup — POLLHUP alone is in the always-report set below and wakes
        // readers; a hangup WITH unread data still reports POLLIN (from rused above), as Linux does.
    } else re |= 0x020;                                                  // POLLNVAL
    return re & (events | 0x010 | 0x020 | 0x008);                        // HUP/NVAL/ERR always reported
}

// Poll a set that may mix THREE kinds of fd, each of which learns about readiness differently:
//  - vfds (pipes/socketpairs/epoll): the in-process scoreboard, woken by a g_cv broadcast.
//  - plain real fds (SD files): always ready — a read on a file does not block on Horizon.
//  - bsd sockets (M2.8): only libnx can answer, and NOTHING about them touches g_cv.
//
// The socket case is why this is not just the old loop with an extra branch. Before M2.8 every
// non-vfd set has_plain_file, which reports the fd ready for whatever was asked AND forces an
// immediate return; a socket scored that way would be permanently "ready", turning any Wine select
// loop into a 100% CPU spin. So has_plain_file is narrowed to plain files only, and a set containing
// sockets waits in SHORT SLICES instead of indefinitely — a socket becoming readable can never
// broadcast g_cv, so the only way to notice it is to look again.
//
// Slicing rather than blocking inside libnx's poll() is deliberate: a blocking bsdPoll would hold the
// wakeup latency of every OTHER fd in the set hostage to the socket timeout, delaying every wineserver
// condvar wakeup by up to a full slice and regressing usock/cmd-echo. Sockets pay the added latency
// (network round-trips dwarf it); vfds keep their immediate condvar wakeup.
enum {
    NX_POLL_SLICE_MS  = 20,      // re-scan cadence when the set contains a socket
    NX_POLL_IN        = 0x001,
    NX_POLL_PRIORITY  = 0x002,
    NX_POLL_OUT       = 0x004,
    NX_POLL_ERROR     = 0x008,
    NX_POLL_HANGUP    = 0x010,
    NX_POLL_INVALID   = 0x020,   // POLLNVAL — the fd is not open
};

int nx_poll(l_pollfd* pollfds, unsigned long count, int timeout_ms) {
    // A positive timeout becomes an ABSOLUTE deadline ONCE: the slice loop re-scans many times and
    // must not restart the countdown on each pass (that would make a 50 ms poll never time out).
    struct timespec deadline = {0, 0};
    if (timeout_ms > 0) {
        struct timeval now; gettimeofday(&now, NULL);
        long microseconds = now.tv_usec + (timeout_ms % 1000) * 1000;
        deadline.tv_sec  = now.tv_sec + timeout_ms / 1000 + microseconds / 1000000;
        deadline.tv_nsec = (microseconds % 1000000) * 1000;
    }
    for (;;) {
        // Socket pass FIRST and OUTSIDE g_mx: it is a bsd:u IPC round trip, and holding the vfd mutex
        // across it would stall every pipe/socketpair op in the process (the wineserver's included).
        // Doing it before the lock also means the locked section below runs straight into the
        // cond_wait with no window for a vfd state change to be missed.
        int has_socket = 0;
        int ready_count = nx_net_poll(pollfds, count, 0 /*non-blocking scan*/, &has_socket);
        if (ready_count < 0) ready_count = 0;

        pthread_mutex_lock(&g_mx);
        int has_plain_file = 0;
        for (unsigned long i = 0; i < count; i++) {
            if (pollfds[i].fd < 0) { pollfds[i].revents = 0; continue; }
            if (nx_net_is_socket(pollfds[i].fd)) continue;   // already scored above — do not clear it
            pollfds[i].revents = 0;
            if (!nx_vfd_is(pollfds[i].fd)) {
                // A number in the vfd BAND whose slot is free is a CLOSED vfd, not a real fd. Scoring
                // it as a plain file below would report it permanently ready, and a caller that polls
                // a stale fd would then spin at 100% CPU instead of seeing an error. POSIX says
                // POLLNVAL — and POLLNVAL does not count toward the ready total the way a requested
                // event does, but it must still wake the call, so it is counted here as Linux does.
                if (is_vfd(pollfds[i].fd)) {
                    pollfds[i].revents = NX_POLL_INVALID;
                    ready_count++;
                    continue;
                }
                // real newlib fd: no host poll on Horizon — report it ready for whatever was
                // asked (a read on a real file won't block anyway)
                //
                // KX_REQLOG: this branch is ALWAYS-READY, so anything that lands here wrongly makes
                // every poll on it complete instantly. That is the signature behind ws2_32:afd's
                // "expected STATUS_TIMEOUT, got 0" failures (afd.c:1069/1095/1193/1222) — a socket
                // that nx_net_is_socket() failed to recognise would be scored here.
                { static int on = -1; if (on < 0) on = getenv("KX_REQLOG") ? 1 : 0;
                  if (on) vlog("nx_vfd: POLL-ALWAYSREADY pid=%d fd=%d ev=%#x\n",
                               nx_guest_pid(), pollfds[i].fd, (unsigned)pollfds[i].events); }
                has_plain_file = 1;
                pollfds[i].revents = pollfds[i].events & (NX_POLL_IN | NX_POLL_OUT);
                if (pollfds[i].revents) ready_count++;
                continue;
            }
            pollfds[i].revents = vfd_ready(V(pollfds[i].fd), pollfds[i].events);
            if (pollfds[i].revents) ready_count++;
        }
        if (ready_count || timeout_ms == 0 || has_plain_file) {
            pthread_mutex_unlock(&g_mx);
            return ready_count;
        }

        if (timeout_ms < 0 && !has_socket) {
            { static int log_enabled = -1; if (log_enabled < 0) log_enabled = getenv("KX_REQLOG") ? 1 : 0;
              if (log_enabled) { char line[128];
                  int length = snprintf(line, sizeof line, "nx_vfd: POLLBLK pid=%d n=%lu fd0=%d fd1=%d\n",
                      nx_guest_pid(), count, count > 0 ? pollfds[0].fd : -1, count > 1 ? pollfds[1].fd : -1);
                  svcOutputDebugString(line, length); } }
            pthread_cond_wait(&g_cv, &g_mx);
            pthread_mutex_unlock(&g_mx);
            if (nx_signal_pending_self() && nx_signal_deliver_pending()) { errno = EINTR; return -1; }  // see nx_vfd_read
        } else {
            struct timespec wake_at;
            int wake_is_deadline;
            if (has_socket) {
                // Wait until the earlier of (the caller's deadline, one slice from now). An infinite
                // timeout with a socket in the set has no deadline — it just keeps slicing.
                struct timeval now; gettimeofday(&now, NULL);
                long microseconds = now.tv_usec + (NX_POLL_SLICE_MS % 1000) * 1000;
                wake_at.tv_sec  = now.tv_sec + NX_POLL_SLICE_MS / 1000 + microseconds / 1000000;
                wake_at.tv_nsec = (microseconds % 1000000) * 1000;
                wake_is_deadline = timeout_ms > 0 && (deadline.tv_sec < wake_at.tv_sec ||
                    (deadline.tv_sec == wake_at.tv_sec && deadline.tv_nsec <= wake_at.tv_nsec));
                if (wake_is_deadline) wake_at = deadline;
            } else {
                // No socket in the set: sleep the WHOLE remaining timeout on the condvar exactly as
                // before M2.8. Slicing a socket-free poll would add a spurious wakeup every 20 ms to
                // the wineserver's hot path for nothing.
                wake_at = deadline;
                wake_is_deadline = 1;
            }
            int wait_result = pthread_cond_timedwait(&g_cv, &g_mx, &wake_at);
            pthread_mutex_unlock(&g_mx);
            if (nx_signal_pending_self() && nx_signal_deliver_pending()) { errno = EINTR; return -1; }  // see nx_vfd_read
            // Only the CALLER's deadline ends the poll; a slice expiry just means "look again".
            // Setting timeout_ms to 0 gives one final scoreboard pass, so a readiness change racing
            // the deadline is not lost.
            if (wait_result == ETIMEDOUT && wake_is_deadline) timeout_ms = 0;
        }
    }
}

// ---- select --------------------------------------------------------------------------------------

// x86-64 NR 23. box64's shim defines no __NR_select, so its scwrap entry compiles out and the big
// switch calls libnx's select() directly — which runs every fd through _socketGetFd and fails the
// WHOLE call with ENOTSOCK the moment it meets a file. Route it through nx_poll instead, so a select
// over files, sockets and vfds together behaves.
//
// Linux fd_set is a bitmap of `long` words, so it can only hold fds below FD_SETSIZE (1024) — which is
// precisely why M2.8 gives sockets real newlib fds instead of vfd numbers: FD_SET() on a vfd
// (>=0x40000000) would write ~128 MB past the end of the set. A vfd reaching here is already a guest
// bug, but it is scored anyway since nx_poll can.
enum {
    NX_FD_SET_SIZE      = 1024,   // Linux FD_SETSIZE — the bitmap's capacity in fds
    NX_FD_BITS_PER_WORD = 64,
    NX_FD_BYTES_PER_WORD = NX_FD_BITS_PER_WORD / 8,
    NX_SELECT_STACK_MAX = 128,    // selected fds scored without touching the heap; more spill to malloc
    NX_MSEC_PER_SEC     = 1000,
    NX_USEC_PER_MSEC    = 1000,
    NX_USEC_PER_SEC     = 1000000,
};

typedef struct { unsigned long words[NX_FD_SET_SIZE / NX_FD_BITS_PER_WORD]; } linux_fd_set;

static int fd_set_test(const linux_fd_set* set, int fd) {
    return set && (set->words[fd / NX_FD_BITS_PER_WORD] >> (fd % NX_FD_BITS_PER_WORD)) & 1UL;
}
static void fd_set_add(linux_fd_set* set, int fd) {
    if (set) set->words[fd / NX_FD_BITS_PER_WORD] |= 1UL << (fd % NX_FD_BITS_PER_WORD);
}

struct linux_timeval { long seconds, microseconds; };

// Linux only ever touches the words covering fds [0, nfds) — never the caller's whole fd_set. Sizing
// the validation and the write-back the same way keeps a caller that allocated only what it needs
// (legal: it declared nfds) from being smashed by a blind 128-byte memcpy.
static size_t fd_set_bytes_used(int highest_fd_plus_one) {
    return (size_t)((highest_fd_plus_one + NX_FD_BITS_PER_WORD - 1) / NX_FD_BITS_PER_WORD)
           * NX_FD_BYTES_PER_WORD;
}

// Convert select()'s timeval to a poll() millisecond count, rejecting exactly what Linux rejects.
// Returns 0 on success, -1 with errno set on a malformed timeval.
//
// The accept/reject split was MEASURED against glibc+Linux (tests/m2/m2.5-wineserver/selectfd.c
// section 4), not assumed: a NEGATIVE field is EINVAL, but tv_usec >= 1000000 is perfectly legal and
// carries into tv_sec. Rejecting the carry would break any caller that passes an un-normalised
// timeval — and the first draft of this function did exactly that.
static int select_timeout_ms(const struct linux_timeval* tv, int* out_ms) {
    if (!tv) { *out_ms = -1; return 0; }                       // NULL timeout = block indefinitely
    long seconds = tv->seconds, microseconds = tv->microseconds;
    if (seconds < 0 || microseconds < 0) {
        // A negative tv_sec used to fall through the (int) cast as a negative millisecond count,
        // which nx_poll reads as INFINITE — turning a caller's bounded wait into a permanent block.
        // (Linux rejects a negative tv_sec even when a large tv_usec would carry it positive.)
        errno = EINVAL;
        return -1;
    }
    // Clamp instead of overflowing. seconds * 1000 wrapped for any tv_sec past ~24.8 days, landing on
    // an arbitrary short timeout or (worse) a negative one, i.e. infinite again. Both terms are
    // range-checked BEFORE the addition so the sum itself cannot overflow.
    const long max_seconds = (long)(INT_MAX / NX_MSEC_PER_SEC);
    long carry_seconds = microseconds / NX_USEC_PER_SEC;
    if (seconds >= max_seconds || carry_seconds >= max_seconds ||
        seconds + carry_seconds >= max_seconds) { *out_ms = INT_MAX; return 0; }
    seconds += carry_seconds;
    microseconds %= NX_USEC_PER_SEC;
    int ms = (int)(seconds * NX_MSEC_PER_SEC + microseconds / NX_USEC_PER_MSEC);
    // Round a non-zero sub-millisecond timeout UP to 1 ms. Truncating it to 0 turns "sleep briefly"
    // into "poll and return immediately", and Wine's ntdll uses select(0,NULL,NULL,NULL,tv) as its
    // ONLY sleep primitive (dlls/ntdll/unix/sync.c) — so truncating there is a busy-spin, not a
    // rounding error. Sleeping marginally too long is always safe; never sleeping is not.
    if (!ms && (seconds || microseconds)) ms = 1;
    *out_ms = ms;
    return 0;
}

int nx_select(int highest_fd_plus_one, void* read_set, void* write_set, void* except_set, void* timeout) {
    if (highest_fd_plus_one < 0 || highest_fd_plus_one > NX_FD_SET_SIZE) { errno = EINVAL; return -1; }
    int timeout_ms;
    if (select_timeout_ms((const struct linux_timeval*)timeout, &timeout_ms) < 0) return -1;

    // Validate the guest pointers before dereferencing them, as every nx_net_* entry point does.
    // A bad fd_set pointer must be EFAULT, not a host fault inside the emulator.
    //
    // The fd_set pointers are always raw syscall arguments, so they are always guest-owned. The
    // TIMEOUT is not: the pselect6 entry point (nx_posix.c case 72) converts the guest's timespec
    // into a timeval on the HOST stack and passes that, which no guest-page check can accept.
    // Each caller therefore validates its own timeout, where the provenance is known.
    size_t set_bytes = fd_set_bytes_used(highest_fd_plus_one);
    if ((read_set   && nx_vfd_buf_bad(read_set,   set_bytes)) ||
        (write_set  && nx_vfd_buf_bad(write_set,  set_bytes)) ||
        (except_set && nx_vfd_buf_bad(except_set, set_bytes))) { errno = EFAULT; return -1; }

    // Two passes: count the selected fds, then score exactly that many. The old single pass stopped
    // at a fixed 128 and returned a confident answer computed from the prefix — a silent wrong
    // result, not a degraded one. (Its truncation warning also false-fired whenever a call selected
    // exactly 128 fds and nothing was actually dropped.)
    int selected_count = 0;
    for (int fd = 0; fd < highest_fd_plus_one; fd++)
        if (fd_set_test((const linux_fd_set*)read_set,   fd) ||
            fd_set_test((const linux_fd_set*)write_set,  fd) ||
            fd_set_test((const linux_fd_set*)except_set, fd)) selected_count++;

    if (!selected_count) {   // no fds selected: select() degenerates to a sleep
        if (timeout_ms > 0) svcSleepThread((u64)timeout_ms * 1000000ULL);
        return 0;
    }

    l_pollfd stack_pollfds[NX_SELECT_STACK_MAX];
    int      stack_selected_fd[NX_SELECT_STACK_MAX];
    l_pollfd* pollfds     = stack_pollfds;
    int*      selected_fd = stack_selected_fd;
    void*     heap_pollfds = NULL;
    void*     heap_selected_fd = NULL;
    if (selected_count > NX_SELECT_STACK_MAX) {
        heap_pollfds     = malloc((size_t)selected_count * sizeof *pollfds);
        heap_selected_fd = malloc((size_t)selected_count * sizeof *selected_fd);
        if (!heap_pollfds || !heap_selected_fd) {
            free(heap_pollfds); free(heap_selected_fd);
            errno = ENOMEM;
            return -1;
        }
        pollfds     = (l_pollfd*)heap_pollfds;
        selected_fd = (int*)heap_selected_fd;
    }

    int filled = 0;
    for (int fd = 0; fd < highest_fd_plus_one && filled < selected_count; fd++) {
        short events = 0;
        if (fd_set_test((const linux_fd_set*)read_set,   fd)) events |= NX_POLL_IN;
        if (fd_set_test((const linux_fd_set*)write_set,  fd)) events |= NX_POLL_OUT;
        if (fd_set_test((const linux_fd_set*)except_set, fd)) events |= NX_POLL_PRIORITY;
        if (!events) continue;
        pollfds[filled].fd      = fd;
        pollfds[filled].events  = events;
        pollfds[filled].revents = 0;
        selected_fd[filled]     = fd;
        filled++;
    }

    int ready_count = nx_poll(pollfds, (unsigned long)filled, timeout_ms);
    if (ready_count < 0) { free(heap_pollfds); free(heap_selected_fd); return -1; }

    // Rebuild the sets from revents. POLLERR/POLLHUP make an fd both readable and writable in select's
    // model (that is how a caller learns about them at all — select has no error bit of its own).
    linux_fd_set ready_read, ready_write, ready_except;
    memset(&ready_read,   0, sizeof ready_read);
    memset(&ready_write,  0, sizeof ready_write);
    memset(&ready_except, 0, sizeof ready_except);
    // select() returns the number of READY BITS, not the number of ready fds: an fd that is both
    // readable and writable contributes 2. Counting fds made a caller looping `while (n--)` over the
    // set bits stop early and leave ready fds unserviced.
    int ready_bits = 0;
    for (int i = 0; i < filled; i++) {
        short revents = pollfds[i].revents;
        if (!revents) continue;
        if (read_set   && (revents & (NX_POLL_IN | NX_POLL_HANGUP | NX_POLL_ERROR)))
            { fd_set_add(&ready_read,   selected_fd[i]); ready_bits++; }
        if (write_set  && (revents & (NX_POLL_OUT | NX_POLL_ERROR)))
            { fd_set_add(&ready_write,  selected_fd[i]); ready_bits++; }
        if (except_set && (revents & NX_POLL_PRIORITY))
            { fd_set_add(&ready_except, selected_fd[i]); ready_bits++; }
    }
    free(heap_pollfds); free(heap_selected_fd);
    if (read_set)   memcpy(read_set,   &ready_read,   set_bytes);
    if (write_set)  memcpy(write_set,  &ready_write,  set_bytes);
    if (except_set) memcpy(except_set, &ready_except, set_bytes);
    return ready_bits;
}

// ---- epoll (vfd) ---------------------------------------------------------------------------------
// A VK_EPOLL vfd holds an interest set; epoll_wait builds an l_pollfd array and reuses nx_poll (which
// already handles vfd readiness + the condvar block/timeout). Linux x86-64 struct epoll_event is
// PACKED: uint32 events; then an 8-byte data union (no padding) = 12 bytes. Wine (fsync/wineserver
// select path) and glibc use epoll; ENOSYS forced the poll() fallback, which works but this closes
// the gap. Levels only (EPOLLET/oneshot are ignored — a spurious extra wake is harmless for a
// re-poll loop, and Wine re-arms each iteration).
typedef struct { int fd; unsigned events; unsigned long long data; } nx_epitem;
#pragma pack(push, 1)
typedef struct { unsigned int events; unsigned long long data; } l_epoll_event;
#pragma pack(pop)
#define NX_EPOLL_CTL_ADD 1
#define NX_EPOLL_CTL_DEL 2
#define NX_EPOLL_CTL_MOD 3

int nx_epoll_create(void) {
    pthread_mutex_lock(&g_mx);
    int i = slot_alloc();
    if (i < 0) { pthread_mutex_unlock(&g_mx); errno = EMFILE; return -1; }
    g_v[i].kind = VK_EPOLL;
    int fd = vfd_publish_or_free(i);
    pthread_mutex_unlock(&g_mx);
    return fd;
}

int nx_epoll_ctl(int epfd, int op, int fd, void* uev) {
    if (!nx_vfd_is(epfd) || V(epfd)->kind != VK_EPOLL) { errno = EBADF; return -1; }
    l_epoll_event* ev = (l_epoll_event*)uev;
    pthread_mutex_lock(&g_mx);
    vfd_t* v = V(epfd);
    nx_epitem* set = (nx_epitem*)v->epset;
    int found = -1;
    for (int k = 0; k < v->ep_n; k++) if (set[k].fd == fd) { found = k; break; }
    long r = 0;
    if (op == NX_EPOLL_CTL_DEL) {
        if (found < 0) { errno = ENOENT; r = -1; }
        else set[found] = set[--v->ep_n];
    } else if (op == NX_EPOLL_CTL_ADD || op == NX_EPOLL_CTL_MOD) {
        if (!ev) { errno = EFAULT; r = -1; }
        else if (op == NX_EPOLL_CTL_ADD && found >= 0) { errno = EEXIST; r = -1; }
        else if (op == NX_EPOLL_CTL_MOD && found < 0) { errno = ENOENT; r = -1; }
        else {
            if (found < 0) {
                if (v->ep_n == v->ep_cap) {
                    int nc = v->ep_cap ? v->ep_cap * 2 : 8;
                    nx_epitem* ns = (nx_epitem*)realloc(set, (size_t)nc * sizeof *ns);
                    if (!ns) { pthread_mutex_unlock(&g_mx); errno = ENOMEM; return -1; }
                    v->epset = set = ns; v->ep_cap = nc;
                }
                found = v->ep_n++;
            }
            set[found].fd = fd; set[found].events = ev->events; set[found].data = ev->data;
        }
    } else { errno = EINVAL; r = -1; }
    pthread_mutex_unlock(&g_mx);
    return r;
}

// How many interest entries are snapshotted on the stack before falling back to the heap. Sized for
// the common case (a handful of fds) — the wineserver's main loop registers far more.
enum { NX_EPOLL_STACK_MAX = 64 };

int nx_epoll_wait(int epfd, void* uevents, int maxevents, int timeout_ms) {
    if (!nx_vfd_is(epfd) || V(epfd)->kind != VK_EPOLL) { errno = EBADF; return -1; }
    if (maxevents <= 0) { errno = EINVAL; return -1; }
    // Snapshot the interest set under the lock, then poll it via nx_poll (which takes the lock itself).
    //
    // The WHOLE set is polled, never a prefix of it. maxevents bounds how many ready events the caller
    // can RECEIVE; it says nothing about how many fds may be examined. Truncating the interest set to
    // it (as this did) meant epoll_wait(...,maxevents=1,...) only ever watched the first registered
    // fd — and a second, fixed 64-entry stack cap silently starved everything past index 63. The
    // wineserver's main loop is epoll-based over many sockets, so both were real starvation bugs.
    pthread_mutex_lock(&g_mx);
    int n = V(epfd)->ep_n;
    nx_epitem* set = (nx_epitem*)V(epfd)->epset;
    l_pollfd stack_pf[NX_EPOLL_STACK_MAX];
    nx_epitem stack_snap[NX_EPOLL_STACK_MAX];
    l_pollfd* pf = stack_pf;
    nx_epitem* snap = stack_snap;
    void* heap_pf = NULL;
    void* heap_snap = NULL;
    if (n > NX_EPOLL_STACK_MAX) {
        // realloc() already runs under g_mx in nx_epoll_ctl, so allocating here breaks no lock order.
        heap_pf = malloc((size_t)n * sizeof *pf);
        heap_snap = malloc((size_t)n * sizeof *snap);
        if (!heap_pf || !heap_snap) {
            free(heap_pf); free(heap_snap);
            pthread_mutex_unlock(&g_mx);
            errno = ENOMEM;
            return -1;
        }
        pf = (l_pollfd*)heap_pf;
        snap = (nx_epitem*)heap_snap;
    }
    for (int k = 0; k < n; k++) {
        snap[k] = set[k];
        pf[k].fd = set[k].fd;
        // epoll IN/OUT/HUP/ERR map 1:1 to poll bits (0x001/0x004/0x010/0x008).
        pf[k].events = (short)(set[k].events & (0x001 | 0x004));
        pf[k].revents = 0;
    }
    pthread_mutex_unlock(&g_mx);
    if (n == 0) {   // nothing registered: just honor the timeout
        if (timeout_ms > 0) svcSleepThread((u64)timeout_ms * 1000000ULL);
        return 0;
    }
    int ready = nx_poll(pf, (unsigned long)n, timeout_ms);
    if (ready <= 0) { free(heap_pf); free(heap_snap); return ready; }
    l_epoll_event* out = (l_epoll_event*)uevents;
    int o = 0;
    for (int k = 0; k < n && o < maxevents; k++) {
        if (!pf[k].revents) continue;
        out[o].events = (unsigned)(pf[k].revents & (0x001 | 0x004 | 0x010 | 0x008));
        out[o].data = snap[k].data;
        o++;
    }
    // Truncating the OUTPUT is legal epoll behaviour (the caller comes back for the rest), but it is
    // worth seeing: a caller that never drains the backlog looks like a stall with no other symptom.
    if (o < ready)
        vlog("nx_vfd: epoll_wait ep=%d reported %d of %d ready (maxevents=%d)\n", epfd, o, ready, maxevents);
    free(heap_pf); free(heap_snap);
    return o;
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
    { static int cnt = 0; static int on = -1; if (on < 0) on = getenv("KX_REQLOG") ? 1 : 0;
      if (on && cnt < 60) { cnt++; vlog("nx_vfd: IOCTL pid=%d fd=%d req=0x%lx kind=%d\n",
          nx_guest_pid(), fd, req, (int)v->kind); } }
    switch (req) {
        case 0x5421: v->nonblock = arg && *(int*)arg ? 1 : 0; return 0;  // FIONBIO
        case 0x541B: if (arg) *(int*)arg = (int)rused(v); return 0;      // FIONREAD
        // EVERYTHING else -> ENOTTY ("inappropriate ioctl for device"), exactly like a real Linux fd.
        // Returning 0 (success) is a LIVELOCK LANDMINE: Wine PROBES fds with ioctls and, on success,
        // drives that path forever. Confirmed hits, all via this default:
        //  - terminal ioctls (TCGETS/TIOCGWINSZ 0x54xx): isatty()->true -> console spin (3.26M ioctls
        //    on the drive_c/windows dir vfd -- the old "console-stage hang").
        //  - VFAT_IOCTL_READDIR_BOTH (0x82307201 = _IOR('r',1,KERNEL_DIRENT[2])): Wine's
        //    find_file_in_dir/NtQueryDirectoryFile probe. On success it reads the dir VIA the ioctl,
        //    but we never fill KERNEL_DIRENT, so kde[0].d_reclen stays garbage-nonzero and the inner
        //    ioctl keeps "succeeding" -> Wine loops `while(kde[0].d_reclen)` forever (file.c:2748-2778).
        //  - EXT2_IOC_GETFLAGS (0x80086601): case-fold probe -> garbage flags misclassify the FS.
        // ENOTTY makes every probe FAIL, so Wine uses the normal getdents64 path (nx_vfd_getdents64)
        // and its own case-insensitive matching. Any vfd ioctl that legitimately needs success must be
        // added as an explicit case above (like FIONBIO/FIONREAD), never left to a fake 0.
        default:
            errno = ENOTTY; return -1;
    }
}

// ---- guest-path helpers for the big-switch fallback cases ----------------------------------------

// Phase 1/2 (2026-07-23): resolution-cache invalidation + fsdev-IPC counters. Every SUCCESSFUL mutation
// here drops the stale cached path->host resolution (nx_pc_invalidate for a single path; nx_pc_flush for
// a directory removal/rename that could strand cached child entries). The counters (defined in nx_posix.c)
// feed nx_ipc_stats_dump under KX_REQLOG. See "Fewer FS-service IPCs per guest file op" in nx_posix.c.
extern void nx_pc_invalidate(const char* raw_guest_path);
extern void nx_pc_flush(void);
extern unsigned long nx_ipc_unlink, nx_ipc_mkdir, nx_ipc_rmdir, nx_ipc_rename;

int nx_mkdir_guest(const char* p, unsigned mode) {
    char hp[512];
    if (!p) { errno = EFAULT; return -1; }
    if (nx_tmpfs_is_path(p)) { int r = nx_tmpfs_mkdir(p, (mode_t)mode); if (r < 0 && errno == EEXIST) r = 0; return r; }
    if (nx_translate_path(p, hp, sizeof hp) != 0) return -1;
    __atomic_add_fetch(&nx_ipc_mkdir, 1, __ATOMIC_RELAXED);
    int r = nx_fs_mkdir(hp, (mode_t)mode);       // SD I/O funnel (host path; counter + invalidate stay here)
    if (r < 0 && errno == EEXIST) r = 0;         // dir already exists -> success (still invalidate below)
    if (r == 0) nx_pc_invalidate(p);             // a new (or now-known-present) dir flips a cached exists 0->1
    return r;
}
int nx_unlink_guest(const char* p) {
    char hp[512];
    if (!p) { errno = EFAULT; return -1; }
    if (nx_tmpfs_is_path(p)) return nx_tmpfs_unlink(p);
    if (nx_translate_path(p, hp, sizeof hp) != 0) return -1;
    nx_libcache_invalidate(hp);                  // drop any cached blob for the file being removed
    __atomic_add_fetch(&nx_ipc_unlink, 1, __ATOMIC_RELAXED);
    int r = nx_fs_unlink(hp);                    // SD I/O funnel (host path)
    if (r == 0) nx_pc_invalidate(p);             // removed -> flip a cached exists 1->0
    return r;
}
int nx_rmdir_guest(const char* p) {
    char hp[512];
    if (!p) { errno = EFAULT; return -1; }
    if (nx_tmpfs_is_path(p)) return nx_tmpfs_rmdir(p);
    if (nx_translate_path(p, hp, sizeof hp) != 0) return -1;
    __atomic_add_fetch(&nx_ipc_rmdir, 1, __ATOMIC_RELAXED);
    int r = nx_fs_rmdir(hp);                     // SD I/O funnel (host path)
    if (r == 0) nx_pc_flush();                    // a removed dir can strand cached child entries -> flush
    return r;
}
// unlinkat(dirfd, path, flags): resolve a relative path against a vfd dir fd (the dir-fd layer —
// open(O_DIRECTORY) yields a vfd, and glibc's remove()/unlinkat() pass that fd), then unlink or
// (AT_REMOVEDIR) rmdir the joined guest path. Mirrors the openat dirfd resolution (nx_posix.c:349).
#define NX_AT_REMOVEDIR 0x200
int nx_unlinkat_guest(int dirfd, const char* p, int flags) {
    if (!p) { errno = EFAULT; return -1; }
    char gp[1024];
    const char* path = p;
    if (p[0] != '/' && nx_vfd_is(dirfd) && nx_vfd_dir_guest(dirfd)) {
        snprintf(gp, sizeof gp, "%s/%s", nx_vfd_dir_guest(dirfd), p);
        path = gp;
    }
    return (flags & NX_AT_REMOVEDIR) ? nx_rmdir_guest(path) : nx_unlink_guest(path);
}
int nx_access_guest(const char* p, int mode) {
    char hp[512]; struct stat st;
    if (!p) { errno = EFAULT; return -1; }
    if (nx_tmpfs_is_path(p)) return nx_tmpfs_access(p, mode);
    if (nx_translate_path(p, hp, sizeof hp) != 0) return -1;
    (void)mode;                                  // fsdev has no perms — existence check suffices
    return nx_fs_stat(hp, &st);                  // SD I/O funnel (host path)
}
// Composite REPLACE, run as ONE funnel job so the rename+clobber+retry is ATOMIC on the single SD worker
// (else another thread's rename of the same target could interpose between a failed rename and the retry).
// HOST paths only. The two rename counters + the uncounted clobber unlink stay HERE, so the KX_REQLOG
// nx_ipc: totals are byte-identical funnel-on vs -off. Called by the FSOP_RENAME worker (or directly on
// the caller thread when the funnel is off); nx_fs_rename() is the wrapper that funnels it.
int nx_fs_rename_direct(const char* ha, const char* hb) {
    __atomic_add_fetch(&nx_ipc_rename, 1, __ATOMIC_RELAXED);
    int r = rename(ha, hb);
    if (r != 0) {
        // fsdev's rename does NOT atomically replace an existing target (POSIX rename overwrites; fsdev
        // fails EEXIST). The wineserver's registry save renames reg*.tmp OVER system.reg every flush —
        // a failed rename left the registry "unsaved" (dirty), so its flush timer re-saved FOREVER,
        // starving the single-threaded server and the wine client. Remove the target and retry.
        unlink(hb);
        __atomic_add_fetch(&nx_ipc_rename, 1, __ATOMIC_RELAXED);
        r = rename(ha, hb);
    }
    return r;
}
int nx_rename_guest(const char* a, const char* b) {
    char ha[512], hb[512];
    if (!a || !b) { errno = EFAULT; return -1; }
    if (nx_tmpfs_is_path(a) || nx_tmpfs_is_path(b)) {   // RAM /tmp: both-in-tmpfs moves; cross-fs -> EXDEV
        if (nx_tmpfs_is_path(a) && nx_tmpfs_is_path(b)) return nx_tmpfs_rename(a, b);
        errno = EXDEV; return -1;
    }
    if (nx_translate_path(a, ha, sizeof ha) != 0) return -1;
    if (nx_translate_path(b, hb, sizeof hb) != 0) return -1;
    nx_libcache_invalidate(ha); nx_libcache_invalidate(hb);   // both paths' content changes
    // Fast registry save: the reg*.tmp source was written empty (writes discarded, see nx_regtmp_is),
    // so DON'T clobber the real .reg with it — report success and drop the empty temp. The in-memory
    // registry the server already loaded is authoritative for this run; the on-disk .reg stays valid
    // for a fast next-run startup. (Applies only to the reg*.tmp->*.reg save rename.)
    // reg*.tmp save short-circuit: only the temp source was unlinked, so drop just its cached entry —
    // NOT a whole-table flush, which would cold-cache every warm library resolution on each periodic
    // wineserver registry save and defeat the cache during a long Wine run.
    if (nx_regtmp_name(a)) { nx_fs_unlink(ha); nx_pc_invalidate(a); return 0; }   // funneled empty-temp drop
    int r = nx_fs_rename(ha, hb);                 // funneled atomic replace (nx_fs_rename_direct body)
    if (r == 0) nx_pc_flush();                    // rename can move a DIR (stranding cached children) + changes both a and b
    return r;
}

// ---- x86-64 big-switch pre-dispatch ---------------------------------------------------------------
// Handles the x86-64 NRs that box64's big switch would pass to newlib with raw fds/paths.
// Returns 1 with *ret set (result or -host_errno; the caller's seam translates errno) or 0.

int nx_x64_precase(long s, unsigned long a1, unsigned long a2, unsigned long a3,
                   unsigned long a4, unsigned long a5, unsigned long a6, long* ret) {
    (void)a6;
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
            if (!nx_vfd_is((int)a1)) {
                nx_tee_forget((int)a1);                        // clear stale tee flag
                // A socket close must be taken here: box64's big-switch close hands every real fd to
                // the SD funnel worker (x64syscall.c cases 3), and a socket has no business on the
                // fsdev queue. Closing it inline is also what releases the newlib handle that
                // nx_net_is_socket() keys on.
                if (nx_net_is_socket((int)a1)) { r = close((int)a1); break; }
                return 0;                                      // ordinary real fd: let box64 close it
            }
            // Under LOWFD numbering a vfd holds an ordinary newlib fd NUMBER, which newlib will hand
            // out again after this close. Any fd-keyed side table still holding that number would
            // then apply to an unrelated fd, so clear them here as the real-fd path already does.
            nx_tee_forget((int)a1);
            nx_regtmp_forget((int)a1);
            r = nx_vfd_close((int)a1);
            break;
        case 7:   // poll
            r = nx_poll((l_pollfd*)a1, (unsigned long)a2, (int)a3);
            break;
        case 23:  // select — see nx_select(). Without this the big switch calls libnx's select(),
                  // which ENOTSOCKs the whole call on the first non-socket fd in the set.
            // The timeval here IS a guest pointer (a raw syscall argument), unlike the host-stack
            // one pselect6 synthesises — so it is validated here rather than inside nx_select.
            if (a5 && nx_vfd_buf_bad((void*)a5, sizeof(struct linux_timeval))) { errno = EFAULT; r = -1; break; }
            r = nx_select((int)a1, (void*)a2, (void*)a3, (void*)a4, (void*)a5);
            break;
        case 48:  // shutdown — half-close a vfd socketpair so the PEER sees EOF. box64's scwrap has no
                  // entry for shutdown, so without this it hit the big-switch default -> ENOSYS, which
                  // failed the wineserver's sock_check_pollhup probe ("ERROR in sock_check_pollhup()").
            if (nx_net_is_socket((int)a1)) { r = nx_net_shutdown((int)a1, (int)a2); break; }
            r = nx_shutdown((int)a1, (int)a2);
            break;
        case 16:  // ioctl
            if (!nx_vfd_is((int)a1)) {
                // A socket honors FIONBIO/FIONREAD and refuses everything else with ENOTTY — the same
                // discipline as below, and the reason Wine's fd probing doesn't livelock on it.
                if (nx_net_is_socket((int)a1)) { r = nx_net_ioctl((int)a1, (unsigned long)a2, (void*)a3); break; }
                // Terminal ioctls on a REAL fd (the client's stdin/out/err): report NOT-a-tty. Wine's
                // get_initial_console() calls isatty(0/1/2) (-> ioctl TCGETS); if it says "tty" Wine
                // takes CONSOLE_HANDLE_SHELL and tries to spawn a conhost pseudo-console (impossible on
                // Horizon -> cmd.exe spins). ENOTTY -> isatty=false -> CONSOLE_HANDLE_SHELL_NO_WINDOW:
                // no console, and cmd.exe's std handles map straight to the unix fds -> echo's WriteFile
                // reaches write(1) -> the box64 result tee. (No fd on Horizon is a real terminal.)
                unsigned long q = (unsigned long)a2;
                if (q == 0x5401 /*TCGETS*/  || q == 0x5402 /*TCSETS*/  || q == 0x5403 /*TCSETSW*/ ||
                    q == 0x5413 /*TIOCGWINSZ*/ || q == 0x5414 /*TIOCSWINSZ*/ ||
                    q == 0x540F /*TIOCGPGRP*/ || q == 0x5410 /*TIOCSPGRP*/) {
                    errno = ENOTTY; r = -1; break;
                }
                return 0;   // other ioctls on real fds: let box64's default path handle them
            }
            r = nx_vfd_ioctl((int)a1, (unsigned long)a2, (void*)a3);
            break;
        case 21: r = nx_access_guest((const char*)a1, (int)a2); break;
        case 22: r = nx_pipe2((int*)a1, 0); break;
        case 8:   // lseek (vfd SHMEM only; real fds fall through to box64)
            if (!nx_vfd_is((int)a1)) return 0;
            r = nx_vfd_lseek((int)a1, (off_t)a2, (int)a3);
            break;
        case 72:  // fcntl (vfd; plus the flag ops on real fds — newlib has no fcntl, and glibc
                  // fdopen() requires a working F_GETFL: the wineserver registry save dies on it)
            if (!nx_vfd_is((int)a1)) {
                // A socket must take a REAL fcntl: the generic "F_SETFL -> return 0" below would
                // swallow O_NONBLOCK, and a non-blocking connect() is exactly how both Wine's ws2_32
                // and glibc's resolver drive a socket.
                if (nx_net_is_socket((int)a1)) { r = nx_net_fcntl((int)a1, (int)a2, (long)a3); break; }
                if ((int)a2 == 1 || (int)a2 == 2 || (int)a2 == 4) { r = 0; break; }  // F_GETFD/F_SETFD/F_SETFL
                if ((int)a2 == 3) { r = 2 /*O_RDWR*/; break; }                        // F_GETFL
                return 0;
            }
            r = nx_vfd_fcntl((int)a1, (int)a2, (long)a3);
            break;
        case 73:  // flock: vfd LOCK is the wineserver `lock`; on a REAL fd just accept — the
                  // wineserver flock()s every file it opens for sharing checks, and newlib has no
                  // flock (ENOSYS there failed every server-side open -> c0000001 image loads).
            if (!nx_vfd_is((int)a1)) { r = 0; break; }
            r = nx_vfd_flock((int)a1, (int)a2);
            break;
        case 32:  // dup — the wineserver dups the stored unix fd into every get_handle_fd reply.
            if (!lowfd_mode() && nx_vfd_is((int)a1)) {
                pthread_mutex_lock(&g_mx);
                V((int)a1)->refs++;          // no alias slots: same number, one more owner. POSIX
                pthread_mutex_unlock(&g_mx); // wants a fresh number, but wine only stores/closes it.
                r = (long)a1;
            } else {
                // LOWFD: a vfd is a real newlib fd, so dup() gives a genuinely fresh number aliasing
                // the same handle — POSIX behaviour, with the refcount doing the lifetime work.
                int was_vfd = nx_vfd_is((int)a1);
                r = dup((int)a1);
                if (r >= 0 && !was_vfd) { tee_mark((int)r, (int)a1); nx_net_shadow_dup((int)a1, (int)r); }
            }
            break;
        case 33:  // dup2
            if (!lowfd_mode() && (nx_vfd_is((int)a1) || nx_vfd_is((int)a2))) {
                // Legacy numbering cannot pin a vfd to an arbitrary number: the number IS the object.
                vlog("nx_vfd: dup2(%d,%d) with vfd UNSUPPORTED\n", (int)a1, (int)a2);
                errno = EBADF; r = -1; break;
            }
            {   // LOWFD: newlib's dup2 closes the target properly (via kxvfd_close_r if it was a vfd)
                // and aliases the source, so `2>&1` and posix_spawn file-actions work on a pipe.
                int was_vfd = nx_vfd_is((int)a1);
                r = dup2((int)a1, (int)a2);
                if (r >= 0 && !was_vfd) { tee_mark((int)r, (int)a1); nx_net_shadow_dup((int)a1, (int)r); }
            }
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
        // Modern glibc rename() emits renameat2(AT_FDCWD, old, AT_FDCWD, new, 0), NOT legacy rename(82);
        // the wineserver's registry save renames its reg*.tmp over system.reg this way. Unhandled it
        // fell through to the host-syscall passthrough -> ENOSYS -> the save FAILED, the registry stayed
        // dirty, and the flush timer re-saved forever (the "file_set_error: Function not implemented"
        // loop that starved the wine client). renameat=264(old,new @ a2,a4); renameat2=316(same+flags).
        case 264: r = nx_rename_guest((const char*)a2, (const char*)a4); break;   // renameat
        case 316: r = nx_rename_guest((const char*)a2, (const char*)a4); break;   // renameat2 (flags ignored)
        case 83: r = nx_mkdir_guest((const char*)a1, (unsigned)a2); break;
        case 84: r = nx_rmdir_guest((const char*)a1); break;
        case 87: r = nx_unlink_guest((const char*)a1); break;
        case 263: r = nx_unlinkat_guest((int)a1, (const char*)a2, (int)a3); break;  // unlinkat
        case 213: r = nx_epoll_create(); break;                                     // epoll_create(size)
        case 291: r = nx_epoll_create(); break;                                     // epoll_create1(flags)
        case 233: r = nx_epoll_ctl((int)a1, (int)a2, (int)a3, (void*)a4); break;    // epoll_ctl
        case 232: r = nx_epoll_wait((int)a1, (void*)a2, (int)a3, (int)a4); break;   // epoll_wait
        case 281: r = nx_epoll_wait((int)a1, (void*)a2, (int)a3, (int)a4); break;   // epoll_pwait (sigmask ignored)
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
