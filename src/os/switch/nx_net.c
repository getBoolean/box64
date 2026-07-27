// nx_net.c — guest AF_INET/AF_INET6 sockets over Horizon's bsd:u. See nx_net.h for the design note.
//
// Everything here speaks LINUX on the guest side and BSD on the libnx side. The two ABIs are close
// enough to look interchangeable and different enough that assuming so silently breaks: SOL_SOCKET is
// 1 on Linux and 0xffff on BSD, AF_INET6 is 10 vs 28, and every sockaddr carries a length byte on BSD
// where Linux has a 16-bit family. So each direction gets an explicit table below; nothing is passed
// through untranslated unless a comment says the two values are verified identical.

#ifdef __SWITCH__

#include <switch.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>          // close() on the socket error paths
#include <sys/iosupport.h>   // __get_handle / devoptab_list / FindDevice — socket-fd identification
#include <sys/socket.h>      // libnx's FreeBSD-derived AF_*/SO_*/MSG_* — the BSD side of every table
#include <netinet/in.h>      // IPPROTO_*/IPV6_* + struct sockaddr_in{,6} sizes

#include "nx_net.h"

extern void nx_result_log(const char*);   // nx_main.c — heap-free SD result line (the real-HW channel)
extern int  nx_guest_buf_bad(const void*, size_t);   // nx_vfd.c — memprot check before a guest deref

// libnx's socket entry points, declared by hand instead of via its headers.
//
// This is not paranoia: box64-nx force-includes shim/static_compat.h into every TU, and its shim
// headers SHADOW libnx's. <poll.h> resolves to shim/poll.h, where nfds_t is `unsigned long` (libnx:
// `unsigned int`) and POLLWRNORM is 0x100 (libnx: 0x004 == POLLOUT) — so calling poll() normally would
// bind libnx's symbol through a mismatched declaration and silently mean a different thing by
// POLLWRNORM. <sys/filio.h> is worse: it drags in ioccom.h, whose `int ioctl(int, int, ...)` is a HARD
// conflict with the shim's `int ioctl(int, unsigned long, ...)` and will not compile at all.
//
// So: bind the symbols by asm name with libnx's true prototypes, and never include the headers that
// would fight the shim. The `nx_bsd_` prefix also makes every call site read as "this crosses into
// Horizon's stack", which is the whole point of this file.
extern int     nx_bsd_socket(int domain, int type, int protocol)                       __asm__("socket");
extern int     nx_bsd_bind(int fd, const void* addr, unsigned addrlen)                 __asm__("bind");
extern int     nx_bsd_connect(int fd, const void* addr, unsigned addrlen)              __asm__("connect");
extern int     nx_bsd_listen(int fd, int backlog)                                      __asm__("listen");
extern int     nx_bsd_accept(int fd, void* addr, unsigned* addrlen)                    __asm__("accept");
extern int     nx_bsd_getsockname(int fd, void* addr, unsigned* addrlen)               __asm__("getsockname");
extern int     nx_bsd_getpeername(int fd, void* addr, unsigned* addrlen)               __asm__("getpeername");
extern int     nx_bsd_getsockopt(int fd, int lvl, int opt, void* val, unsigned* len)   __asm__("getsockopt");
extern int     nx_bsd_setsockopt(int fd, int lvl, int opt, const void* val, unsigned l)__asm__("setsockopt");
extern ssize_t nx_bsd_sendto(int fd, const void* buf, size_t n, int flags,
                             const void* addr, unsigned addrlen)                       __asm__("sendto");
extern ssize_t nx_bsd_recvfrom(int fd, void* buf, size_t n, int flags,
                               void* addr, unsigned* addrlen)                          __asm__("recvfrom");
extern int     nx_bsd_shutdown(int fd, int how)                                        __asm__("shutdown");
extern int     nx_bsd_ioctl(int fd, int request, ...)                                  __asm__("ioctl");
extern int     nx_bsd_fcntl(int fd, int cmd, ...)                                      __asm__("fcntl");
// libnx's poll(), with ITS nfds_t (unsigned int) and ITS pollfd bit values. Only ever called on an
// array of socket fds — see nx_net_poll().
extern int     nx_bsd_poll(void* fds, unsigned int nfds, int timeout)                  __asm__("poll");

// ---- the two ABIs --------------------------------------------------------------------------------
//
// LINUX side (the guest's values — no header here defines them, so they are spelled out).
enum {
    L_AF_UNIX = 1, L_AF_INET = 2, L_AF_INET6 = 10, L_AF_NETLINK = 16,

    L_SOCK_STREAM = 1, L_SOCK_DGRAM = 2, L_SOCK_RAW = 3,
    L_SOCK_NONBLOCK = 0x800, L_SOCK_CLOEXEC = 0x80000,   // type-word flag bits (BSD numbers them differently)

    L_SOL_SOCKET = 1,                                    // BSD: 0xffff — the single most dangerous delta
    L_IPPROTO_IP = 0, L_IPPROTO_TCP = 6, L_IPPROTO_UDP = 17, L_IPPROTO_IPV6 = 41,

    // SOL_SOCKET options
    L_SO_DEBUG = 1, L_SO_REUSEADDR = 2, L_SO_TYPE = 3, L_SO_ERROR = 4, L_SO_DONTROUTE = 5,
    L_SO_BROADCAST = 6, L_SO_SNDBUF = 7, L_SO_RCVBUF = 8, L_SO_KEEPALIVE = 9, L_SO_OOBINLINE = 10,
    L_SO_LINGER = 13, L_SO_REUSEPORT = 15, L_SO_RCVLOWAT = 18, L_SO_SNDLOWAT = 19,
    L_SO_RCVTIMEO = 20, L_SO_SNDTIMEO = 21, L_SO_ACCEPTCONN = 30,

    // IPPROTO_IP options
    L_IP_TOS = 1, L_IP_TTL = 2, L_IP_HDRINCL = 3, L_IP_OPTIONS = 4,
    L_IP_MULTICAST_IF = 32, L_IP_MULTICAST_TTL = 33, L_IP_MULTICAST_LOOP = 34,
    L_IP_ADD_MEMBERSHIP = 35, L_IP_DROP_MEMBERSHIP = 36,

    // IPPROTO_IPV6 options
    L_IPV6_UNICAST_HOPS = 16, L_IPV6_MULTICAST_IF = 17, L_IPV6_MULTICAST_HOPS = 18,
    L_IPV6_MULTICAST_LOOP = 19, L_IPV6_JOIN_GROUP = 20, L_IPV6_LEAVE_GROUP = 21, L_IPV6_V6ONLY = 26,

    // IPPROTO_TCP options — TCP_NODELAY is 1 in both ABIs (verified against netinet/tcp.h).
    L_TCP_NODELAY = 1,

    // send/recv flags
    L_MSG_OOB = 0x01, L_MSG_PEEK = 0x02, L_MSG_DONTROUTE = 0x04, L_MSG_CTRUNC = 0x08,
    L_MSG_TRUNC = 0x20, L_MSG_DONTWAIT = 0x40, L_MSG_EOR = 0x80, L_MSG_WAITALL = 0x100,
    L_MSG_NOSIGNAL = 0x4000,

    L_O_NONBLOCK = 0x800,        // newlib's is 0x4000 (_FNONBLOCK) — never pass one for the other
    L_FIONBIO = 0x5421, L_FIONREAD = 0x541B,

    L_SHUT_RD = 0, L_SHUT_WR = 1, L_SHUT_RDWR = 2,   // identical in both ABIs
};

// BSD values that libnx's usable headers do NOT give us. FIONBIO/FIONREAD live in <sys/filio.h>, which
// cannot be included here (see the ioctl conflict above), so the _IOW/_IOR encodings are inlined:
//   FIONBIO = _IOW('f', 126, int) = 0x8004667E,  FIONREAD = _IOR('f', 127, int) = 0x4004667F.
enum { B_FIONBIO = 0x8004667E, B_FIONREAD = 0x4004667F };

// BSD sockaddr length byte: FreeBSD's `struct sockaddr` leads with {u8 sa_len, u8 sa_family} where
// Linux has a single {u16 sa_family}. Both sockaddr_in (16 B) and sockaddr_in6 (28 B) are otherwise
// byte-identical between the two ABIs, so conversion is a two-byte head fixup, not a struct rebuild.
//
// NB libnx's own `struct sockaddr_in6` is INCONSISTENT with its `struct sockaddr`: it declares
// `sa_family_t sin6_family` first with no sin6_len, leaving byte 1 as implicit padding. Following that
// would put the family in byte 0 and garbage in byte 1, which FreeBSD reads as a length. We therefore
// build the BSD sockaddr as bytes ourselves, per the documented FreeBSD ABI, and never lay libnx's
// sockaddr_in6 over the wire buffer.
enum { NX_SA_MAX = 128 };   // sockaddr_storage-sized scratch; larger than any family we route

#define NX_ARRAY_LEN(a) ((int)(sizeof(a) / sizeof((a)[0])))

typedef struct { int l, b; } nx_map_t;

// Look a Linux value up in a table; returns `miss` when absent (callers turn that into ENOPROTOOPT
// rather than guessing, because a wrong option number silently configures the WRONG option).
static int map_l2b(const nx_map_t* t, int n, int l, int miss) {
    for (int i = 0; i < n; i++) if (t[i].l == l) return t[i].b;
    return miss;
}

// ---- diagnostics ---------------------------------------------------------------------------------

// Horizon Result codes that libnx's _socketParseBsdResult() cannot map become a bare EPIPE (its
// switch has three cases and an EPIPE default), so a service-level failure is indistinguishable from
// a real broken pipe. When KX_NET_LOG is set, print the raw Result alongside each failure so that
// ambiguity is resolvable without a rebuild.
static int net_log_on(void) {
    static int on = -1;
    if (on < 0) on = getenv("KX_NET_LOG") ? 1 : 0;
    return on;
}

static void netlog(const char* fmt, ...) {
    if (!net_log_on()) return;
    char b[192]; va_list ap; va_start(ap, fmt);
    int n = vsnprintf(b, sizeof b, fmt, ap); va_end(ap);
    if (n > 0) svcOutputDebugString(b, (size_t)n);
}

// ---- availability --------------------------------------------------------------------------------

enum { NX_SOC_DEV_NONE = -1 };   // no "soc" devoptab registered => no sockets exist

// KX_NET_SMALLBUF profile — enough for DNS and a few modest TCP streams, ~8x below libnx's default.
enum {
    NX_NET_SMALL_TCP_BUF       = 0x8000,   // 32 KiB initial send/recv window per socket
    NX_NET_SMALL_TCP_BUF_MAX   = 0x20000,  // 128 KiB ceiling when the stack grows the window
    NX_NET_SMALL_SB_EFFICIENCY = 1,        // one buffer per socket (default is 4)
};

static int g_net_ok      = 0;                 // bsd:u usable
static int g_nifm_ok     = 0;                 // nifm:u usable (DNS server + link status)
static int g_soc_dev     = NX_SOC_DEV_NONE;   // devoptab_list index of libnx's "soc" device

int nx_net_available(void) { return g_net_ok; }
int nx_net_nifm_available(void) { return g_nifm_ok; }

// A socket fd is any live newlib handle whose devoptab is libnx's "soc". Asking the handle table is
// exact where a shadow table is only as good as its bookkeeping: newlib releases the handle itself on
// close (and on the accept/socket failure paths), so there is no forget() to forget to call, and no
// fd-number ceiling to overflow. __get_handle() already returns NULL for out-of-range and for
// refcount==0, which is the whole validity check.
int nx_net_is_socket(int fd) {
    if (g_soc_dev == NX_SOC_DEV_NONE || fd < 0) return 0;   // fast out when M2.8 is off entirely
    __handle* h = __get_handle(fd);
    return h && (int)h->device == g_soc_dev;
}

int nx_net_family_is_inet(int l_domain) {
    return l_domain == 2 /*AF_INET*/ || l_domain == 10 /*AF_INET6*/;
}

// ---- init / teardown -----------------------------------------------------------------------------

// nx_main.c already calls socketInitializeDefault() for the homebrew NRO, because hbloader's SAC
// grants bsd:u unconditionally and netloader needs the socket stack up before main. It CANNOT do the
// same for an installed title: a title whose NPDM never requested bsd:u hangs on a black screen
// inside the service connect. So the title path initializes here instead, behind KX_NET, after
// load_env_file() has made the gate readable — which also makes the whole feature FTP-flippable with
// no rebuild.
void nx_net_init(void) {
    if (!getenv("KX_NET")) return;

    // The NRO already has sockets up from nx_main's netloader block; a second socketInitialize would
    // fail. Detect that by asking for the devoptab rather than re-deriving "am I homebrew".
    int dev = FindDevice("soc:");
    if (dev < 0) {
        // libnx's default socket buffers are backed by a transfer memory block carved out of the SAME
        // heap the guest address space comes from — and on real HW the Wine low-VA path (KX_FORCE_HEAP)
        // is sensitive to what that heap looks like. KX_NET_SMALLBUF trims the buffers to a DNS +
        // modest-TCP profile so the cost of enabling networking can be A/B'd against a Wine run
        // without a rebuild.
        const SocketInitConfig* cfg = socketGetDefaultInitConfig();
        SocketInitConfig small;
        if (getenv("KX_NET_SMALLBUF")) {
            small = *cfg;
            small.tcp_tx_buf_size = small.tcp_rx_buf_size = NX_NET_SMALL_TCP_BUF;
            small.tcp_tx_buf_max_size = small.tcp_rx_buf_max_size = NX_NET_SMALL_TCP_BUF_MAX;
            small.sb_efficiency = NX_NET_SMALL_SB_EFFICIENCY;
            cfg = &small;
        }
        Result rc = socketInitialize(cfg);
        if (R_FAILED(rc)) {
            char b[96]; int n = snprintf(b, sizeof b, "nx_net: socketInitialize FAILED rc=0x%x (no bsd:u in NPDM?)", rc);
            if (n > 0) nx_result_log(b);
            return;
        }
        dev = FindDevice("soc:");
    }
    if (dev < 0) { nx_result_log("nx_net: no 'soc' devoptab after init"); return; }

    g_soc_dev = dev;
    g_net_ok  = 1;

    // nifm supplies the DNS servers for the synthesized /etc/resolv.conf and the link-status
    // pre-flight. Its absence is not fatal — resolv.conf falls back to a public resolver.
    Result rc = nifmInitialize(NifmServiceType_User);
    g_nifm_ok = R_SUCCEEDED(rc);

    char b[128];
    int n = snprintf(b, sizeof b, "nx_net: ready bsd:u dev=%d nifm=%d", g_soc_dev, g_nifm_ok);
    if (n > 0) nx_result_log(b);
    netlog("nx_net: init nifm rc=0x%x\n", rc);
}

void nx_net_exit(void) {
    if (g_nifm_ok) { nifmExit(); g_nifm_ok = 0; }
    // socketExit() stays with nx_main's teardown: on the NRO it owns the socket stack (netloader),
    // and calling it here would tear down nxlink's stdio channel out from under it.
    g_net_ok  = 0;
    g_soc_dev = NX_SOC_DEV_NONE;
}

// ---- address translation -------------------------------------------------------------------------

static int family_l2b(int l_af) {
    switch (l_af) {
        case L_AF_INET:  return AF_INET;    // 2 -> 2
        case L_AF_INET6: return AF_INET6;   // 10 -> 28
        default:         return -1;
    }
}

static int family_b2l(int b_af) {
    switch (b_af) {
        case AF_INET:  return L_AF_INET;
        case AF_INET6: return L_AF_INET6;
        default:       return -1;
    }
}

// The wire length Horizon expects for a family. FreeBSD validates sa_len, and a Linux guest routinely
// passes sizeof(struct sockaddr_storage) (128) as addrlen rather than the exact family size, so derive
// the length from the FAMILY instead of trusting the guest's count.
static unsigned addr_wire_len(int b_af) {
    switch (b_af) {
        case AF_INET:  return sizeof(struct sockaddr_in);    // 16
        case AF_INET6: return sizeof(struct sockaddr_in6);   // 28
        default:       return 0;
    }
}

// Linux sockaddr -> BSD, into `out` (NX_SA_MAX bytes). Returns the BSD wire length, or 0 if the family
// is not one we route. Only bytes 0..1 change: Linux's u16 sa_family becomes BSD's {u8 sa_len,
// u8 sa_family}; every later byte (port, address, scope) is identical in both ABIs.
static unsigned addr_l2b(const void* l_addr, unsigned l_len, uint8_t* out) {
    if (!l_addr || l_len < 2) return 0;
    int b_af = family_l2b(((const uint8_t*)l_addr)[0] | (((const uint8_t*)l_addr)[1] << 8));
    if (b_af < 0) return 0;
    unsigned wire = addr_wire_len(b_af);
    if (!wire) return 0;
    unsigned copy = l_len < wire ? l_len : wire;
    memset(out, 0, wire);
    if (copy > 2) memcpy(out + 2, (const uint8_t*)l_addr + 2, copy - 2);
    out[0] = (uint8_t)wire;     // sa_len
    out[1] = (uint8_t)b_af;     // sa_family
    return wire;
}

// BSD sockaddr -> Linux, in place semantics: writes at most *l_cap bytes into l_addr and reports the
// FULL length in *l_cap, which is what Linux getsockname/accept do (a short buffer is truncated, and
// the caller learns the real size). Returns 0 on success, -1 with errno set on an unroutable family.
static int addr_b2l(const uint8_t* b_addr, unsigned b_len, void* l_addr, unsigned* l_cap) {
    int l_af = family_b2l(b_addr[1]);
    if (l_af < 0) { errno = EAFNOSUPPORT; return -1; }
    unsigned full = b_len;
    if (l_addr && l_cap && *l_cap) {
        uint8_t tmp[NX_SA_MAX];
        unsigned n = full < sizeof tmp ? full : (unsigned)sizeof tmp;
        memcpy(tmp, b_addr, n);
        tmp[0] = (uint8_t)(l_af & 0xff);   // Linux u16 sa_family, little-endian
        tmp[1] = (uint8_t)(l_af >> 8);
        unsigned copy = *l_cap < n ? *l_cap : n;
        memcpy(l_addr, tmp, copy);
    }
    if (l_cap) *l_cap = full;
    return 0;
}

// ---- socket creation and connection setup --------------------------------------------------------

int nx_net_socket(int l_domain, int l_type, int l_proto) {
    if (!g_net_ok) { errno = EAFNOSUPPORT; return -1; }
    int b_af = family_l2b(l_domain);
    if (b_af < 0) { errno = EAFNOSUPPORT; return -1; }

    int base = l_type & 0xff;
    int b_type;
    switch (base) {
        case L_SOCK_STREAM: b_type = SOCK_STREAM; break;   // 1 -> 1
        case L_SOCK_DGRAM:  b_type = SOCK_DGRAM;  break;   // 2 -> 2
        case L_SOCK_RAW:    b_type = SOCK_RAW;    break;   // 3 -> 3 (bsd:u will likely refuse it)
        default: errno = EPROTONOSUPPORT; return -1;
    }
    // IPPROTO_* are identical in both ABIs (0/6/17/41 — verified against netinet/in.h), so the
    // protocol passes through.
    int fd = nx_bsd_socket(b_af, b_type, l_proto);
    if (fd < 0) {
        netlog("nx_net: socket(af=%d type=%d proto=%d) failed e=%d rc=0x%x\n",
               l_domain, l_type, l_proto, errno, socketGetLastResult());
        return -1;
    }
    // SOCK_NONBLOCK/SOCK_CLOEXEC are encoded in the type word on Linux (0x800/0x80000) and differently
    // on BSD (0x20000000/0x10000000). Rather than depend on Horizon's bsd honoring the type-word
    // encoding at all, apply non-blocking afterwards through the fcntl path that is known to work.
    // CLOEXEC is meaningless here — Horizon has no exec.
    if ((l_type & L_SOCK_NONBLOCK) && nx_net_set_nonblock(fd, 1) < 0) {
        int e = errno; close(fd); errno = e; return -1;
    }
    return fd;
}

// Non-blocking is set through libnx's fcntl, which speaks NEWLIB O_NONBLOCK (0x4000) and rejects any
// other bit with EINVAL — passing the guest's Linux 0x800 straight through would fail. Shared by
// socket(SOCK_NONBLOCK), accept4(SOCK_NONBLOCK), fcntl(F_SETFL) and ioctl(FIONBIO).
enum { NX_NEWLIB_O_NONBLOCK = 0x4000, NX_F_GETFL = 3, NX_F_SETFL = 4 };

int nx_net_set_nonblock(int fd, int on) {
    int fl = nx_bsd_fcntl(fd, NX_F_GETFL);
    if (fl < 0) return -1;
    fl = on ? (fl | NX_NEWLIB_O_NONBLOCK) : (fl & ~NX_NEWLIB_O_NONBLOCK);
    return nx_bsd_fcntl(fd, NX_F_SETFL, fl);
}

int nx_net_get_nonblock(int fd) {
    int fl = nx_bsd_fcntl(fd, NX_F_GETFL);
    if (fl < 0) return -1;
    return (fl & NX_NEWLIB_O_NONBLOCK) ? 1 : 0;
}

int nx_net_bind(int fd, const void* l_addr, unsigned l_len) {
    if (nx_guest_buf_bad(l_addr, l_len)) { errno = EFAULT; return -1; }
    uint8_t b[NX_SA_MAX];
    unsigned wire = addr_l2b(l_addr, l_len, b);
    if (!wire) { errno = EAFNOSUPPORT; return -1; }
    int r = nx_bsd_bind(fd, b, wire);
    if (r < 0) netlog("nx_net: bind fd=%d failed e=%d rc=0x%x\n", fd, errno, socketGetLastResult());
    return r;
}

int nx_net_connect(int fd, const void* l_addr, unsigned l_len) {
    if (nx_guest_buf_bad(l_addr, l_len)) { errno = EFAULT; return -1; }
    uint8_t b[NX_SA_MAX];
    unsigned wire = addr_l2b(l_addr, l_len, b);
    if (!wire) { errno = EAFNOSUPPORT; return -1; }
    int r = nx_bsd_connect(fd, b, wire);
    // EINPROGRESS on a non-blocking connect is the NORMAL path (it is how both Wine's ws2_32 and
    // glibc's resolver connect), so do not log it as a failure.
    if (r < 0 && errno != EINPROGRESS)
        netlog("nx_net: connect fd=%d failed e=%d rc=0x%x\n", fd, errno, socketGetLastResult());
    return r;
}

int nx_net_listen(int fd, int backlog) {
    return nx_bsd_listen(fd, backlog);
}

int nx_net_accept4(int fd, void* l_addr, unsigned* l_len, int l_flags) {
    if (l_len && nx_guest_buf_bad(l_addr, *l_len)) { errno = EFAULT; return -1; }
    uint8_t b[NX_SA_MAX];
    unsigned blen = sizeof b;
    int nfd = nx_bsd_accept(fd, b, &blen);
    if (nfd < 0) return -1;
    if (blen >= 2 && addr_b2l(b, blen, l_addr, l_len) < 0) { close(nfd); return -1; }
    if ((l_flags & L_SOCK_NONBLOCK) && nx_net_set_nonblock(nfd, 1) < 0) {
        int e = errno; close(nfd); errno = e; return -1;
    }
    return nfd;
}

int nx_net_getsockname(int fd, void* l_addr, unsigned* l_len) {
    if (l_len && nx_guest_buf_bad(l_addr, *l_len)) { errno = EFAULT; return -1; }
    uint8_t b[NX_SA_MAX];
    unsigned blen = sizeof b;
    if (nx_bsd_getsockname(fd, b, &blen) < 0) return -1;
    if (blen < 2) { errno = EINVAL; return -1; }
    return addr_b2l(b, blen, l_addr, l_len);
}

// Distinct from getsockname: the M2.5 vfd layer aliased the two (harmless for AF_UNIX, where neither
// end has a meaningful peer address), but for TCP the peer address is the whole point — Wine's
// ws2_32 getpeername and glibc both rely on it.
int nx_net_getpeername(int fd, void* l_addr, unsigned* l_len) {
    if (l_len && nx_guest_buf_bad(l_addr, *l_len)) { errno = EFAULT; return -1; }
    uint8_t b[NX_SA_MAX];
    unsigned blen = sizeof b;
    if (nx_bsd_getpeername(fd, b, &blen) < 0) return -1;
    if (blen < 2) { errno = ENOTCONN; return -1; }
    return addr_b2l(b, blen, l_addr, l_len);
}

// ---- send / receive ------------------------------------------------------------------------------

// MSG_* differ in nearly every bit position. Anything not listed is dropped rather than passed
// through: an unrecognized flag reaching FreeBSD as a DIFFERENT flag is worse than not honoring it
// (MSG_NOSIGNAL in particular has no BSD equivalent and is a no-op here — Horizon raises no SIGPIPE).
static int msgflags_l2b(int l_flags) {
    static const nx_map_t tbl[] = {
        { L_MSG_OOB,       MSG_OOB       },   // 0x01 -> 0x01
        { L_MSG_PEEK,      MSG_PEEK      },   // 0x02 -> 0x02
        { L_MSG_DONTROUTE, MSG_DONTROUTE },   // 0x04 -> 0x04
        { L_MSG_EOR,       MSG_EOR       },   // 0x80 -> 0x08
        { L_MSG_TRUNC,     MSG_TRUNC     },   // 0x20 -> 0x10
        { L_MSG_CTRUNC,    MSG_CTRUNC    },   // 0x08 -> 0x20
        { L_MSG_WAITALL,   MSG_WAITALL   },   // 0x100 -> 0x40
        { L_MSG_DONTWAIT,  MSG_DONTWAIT  },   // 0x40 -> 0x80
    };
    int b = 0;
    for (int i = 0; i < NX_ARRAY_LEN(tbl); i++) if (l_flags & tbl[i].l) b |= tbl[i].b;
    return b;
}

// Returned revents-style flags on recvmsg: only the two Linux cares about.
static int msgflags_b2l(int b_flags) {
    int l = 0;
    if (b_flags & MSG_TRUNC)  l |= L_MSG_TRUNC;
    if (b_flags & MSG_CTRUNC) l |= L_MSG_CTRUNC;
    return l;
}

long nx_net_sendto(int fd, const void* buf, size_t len, int l_flags,
                   const void* l_addr, unsigned l_alen) {
    if (nx_guest_buf_bad(buf, len)) { errno = EFAULT; return -1; }
    uint8_t b[NX_SA_MAX];
    unsigned wire = 0;
    if (l_addr && l_alen) {
        if (nx_guest_buf_bad(l_addr, l_alen)) { errno = EFAULT; return -1; }
        wire = addr_l2b(l_addr, l_alen, b);
        if (!wire) { errno = EAFNOSUPPORT; return -1; }
    }
    return (long)nx_bsd_sendto(fd, buf, len, msgflags_l2b(l_flags), wire ? b : NULL, wire);
}

long nx_net_recvfrom(int fd, void* buf, size_t len, int l_flags,
                     void* l_addr, unsigned* l_alen) {
    if (nx_guest_buf_bad(buf, len)) { errno = EFAULT; return -1; }
    uint8_t b[NX_SA_MAX];
    unsigned blen = sizeof b;
    int want_addr = (l_addr && l_alen && *l_alen);
    if (want_addr && nx_guest_buf_bad(l_addr, *l_alen)) { errno = EFAULT; return -1; }
    long r = (long)nx_bsd_recvfrom(fd, buf, len, msgflags_l2b(l_flags),
                                   want_addr ? b : NULL, want_addr ? &blen : NULL);
    if (r < 0) return -1;
    if (want_addr && blen >= 2) addr_b2l(b, blen, l_addr, l_alen);
    else if (l_alen) *l_alen = 0;
    return r;
}

// Linux x86-64 layouts, mirroring the declarations in nx_vfd.c (the vfd layer owns the AF_UNIX side of
// these same structs). NOT interchangeable with libnx's: BSD's msghdr is 48 bytes to Linux's 56
// because msg_iovlen and msg_controllen are 32-bit there. Hence field-by-field, never a cast.
typedef struct { void* base; size_t len; } l_iovec;
typedef struct { void* name; unsigned namelen; l_iovec* iov; size_t iovlen;
                 void* control; size_t controllen; int flags; } l_msghdr;

// libnx exposes no devoptab sendmsg/recvmsg, so scatter/gather is done here around sendto/recvfrom.
// A single-iovec message (the overwhelmingly common case, and what glibc's resolver emits) passes
// through with no copy; multi-iovec messages are packed through a bounce buffer, because a datagram
// MUST leave as one packet — looping sendto() per iovec would fragment one message into several.
enum { NX_MSG_BOUNCE_MAX = 64 * 1024 };   // datagram ceiling; larger multi-iov sends report EMSGSIZE

long nx_net_sendmsg(int fd, const void* l_msg, int l_flags) {
    if (nx_guest_buf_bad(l_msg, sizeof(l_msghdr))) { errno = EFAULT; return -1; }
    const l_msghdr* m = (const l_msghdr*)l_msg;
    // Ancillary data over INET has no meaning here: SCM_RIGHTS is an AF_UNIX concept and the vfd layer
    // owns it. Ignore control rather than fail — Linux ignores unknown cmsgs on INET too.
    if (m->iovlen == 0) return (long)nx_bsd_sendto(fd, "", 0, msgflags_l2b(l_flags), NULL, 0);
    if (m->iovlen == 1)
        return nx_net_sendto(fd, m->iov[0].base, m->iov[0].len, l_flags, m->name, m->namelen);

    size_t total = 0;
    for (size_t i = 0; i < m->iovlen; i++) total += m->iov[i].len;
    if (total > NX_MSG_BOUNCE_MAX) { errno = EMSGSIZE; return -1; }
    uint8_t* pack = (uint8_t*)malloc(total ? total : 1);
    if (!pack) { errno = ENOMEM; return -1; }
    size_t off = 0;
    for (size_t i = 0; i < m->iovlen; i++) {
        if (nx_guest_buf_bad(m->iov[i].base, m->iov[i].len)) { free(pack); errno = EFAULT; return -1; }
        memcpy(pack + off, m->iov[i].base, m->iov[i].len);
        off += m->iov[i].len;
    }
    long r = nx_net_sendto(fd, pack, total, l_flags, m->name, m->namelen);
    int e = errno;
    free(pack);
    errno = e;
    return r;
}

long nx_net_recvmsg(int fd, void* l_msg, int l_flags) {
    if (nx_guest_buf_bad(l_msg, sizeof(l_msghdr))) { errno = EFAULT; return -1; }
    l_msghdr* m = (l_msghdr*)l_msg;
    m->controllen = 0;                       // no ancillary data is ever produced on an INET socket
    if (m->iovlen == 0) { m->flags = 0; return 0; }
    if (m->iovlen == 1) {
        unsigned nlen = m->namelen;
        long r = nx_net_recvfrom(fd, m->iov[0].base, m->iov[0].len, l_flags,
                                 m->name, m->name ? &nlen : NULL);
        if (r >= 0) { m->namelen = m->name ? nlen : 0; m->flags = 0; }
        return r;
    }
    // Multi-iovec: receive the whole datagram once into a bounce buffer, then scatter. Reading per
    // iovec would consume one datagram per call and drop the remainder of each.
    size_t total = 0;
    for (size_t i = 0; i < m->iovlen; i++) total += m->iov[i].len;
    if (total > NX_MSG_BOUNCE_MAX) total = NX_MSG_BOUNCE_MAX;
    uint8_t* pack = (uint8_t*)malloc(total ? total : 1);
    if (!pack) { errno = ENOMEM; return -1; }
    unsigned nlen = m->namelen;
    long r = nx_net_recvfrom(fd, pack, total, l_flags, m->name, m->name ? &nlen : NULL);
    if (r < 0) { int e = errno; free(pack); errno = e; return -1; }
    size_t off = 0;
    for (size_t i = 0; i < m->iovlen && off < (size_t)r; i++) {
        size_t chunk = m->iov[i].len;
        if (chunk > (size_t)r - off) chunk = (size_t)r - off;
        if (nx_guest_buf_bad(m->iov[i].base, chunk)) { free(pack); errno = EFAULT; return -1; }
        memcpy(m->iov[i].base, pack + off, chunk);
        off += chunk;
    }
    free(pack);
    m->namelen = m->name ? nlen : 0;
    m->flags   = 0;
    return r;
}

// ---- socket options ------------------------------------------------------------------------------

static const nx_map_t g_so_tbl[] = {          // SOL_SOCKET (Linux 1 -> BSD 0xffff)
    { L_SO_DEBUG,      SO_DEBUG      },   { L_SO_REUSEADDR, SO_REUSEADDR },
    { L_SO_TYPE,       SO_TYPE       },   { L_SO_ERROR,     SO_ERROR     },
    { L_SO_DONTROUTE,  SO_DONTROUTE  },   { L_SO_BROADCAST, SO_BROADCAST },
    { L_SO_SNDBUF,     SO_SNDBUF     },   { L_SO_RCVBUF,    SO_RCVBUF    },
    { L_SO_KEEPALIVE,  SO_KEEPALIVE  },   { L_SO_OOBINLINE, SO_OOBINLINE },
    { L_SO_LINGER,     SO_LINGER     },   { L_SO_REUSEPORT, SO_REUSEPORT },
    { L_SO_RCVLOWAT,   SO_RCVLOWAT   },   { L_SO_SNDLOWAT,  SO_SNDLOWAT  },
    { L_SO_RCVTIMEO,   SO_RCVTIMEO   },   { L_SO_SNDTIMEO,  SO_SNDTIMEO  },
    { L_SO_ACCEPTCONN, SO_ACCEPTCONN },
};

static const nx_map_t g_ip_tbl[] = {          // IPPROTO_IP (0 in both)
    { L_IP_TOS,              IP_TOS              }, { L_IP_TTL,             IP_TTL             },
    { L_IP_HDRINCL,          IP_HDRINCL          }, { L_IP_OPTIONS,         IP_OPTIONS         },
    { L_IP_MULTICAST_IF,     IP_MULTICAST_IF     }, { L_IP_MULTICAST_TTL,   IP_MULTICAST_TTL   },
    { L_IP_MULTICAST_LOOP,   IP_MULTICAST_LOOP   }, { L_IP_ADD_MEMBERSHIP,  IP_ADD_MEMBERSHIP  },
    { L_IP_DROP_MEMBERSHIP,  IP_DROP_MEMBERSHIP  },
};

static const nx_map_t g_ip6_tbl[] = {         // IPPROTO_IPV6 (41 in both)
    { L_IPV6_UNICAST_HOPS,   IPV6_UNICAST_HOPS   }, { L_IPV6_MULTICAST_IF,   IPV6_MULTICAST_IF   },
    { L_IPV6_MULTICAST_HOPS, IPV6_MULTICAST_HOPS }, { L_IPV6_MULTICAST_LOOP, IPV6_MULTICAST_LOOP },
    { L_IPV6_JOIN_GROUP,     IPV6_JOIN_GROUP     }, { L_IPV6_LEAVE_GROUP,    IPV6_LEAVE_GROUP    },
    { L_IPV6_V6ONLY,         IPV6_V6ONLY         },
};

// Resolve a (level, optname) pair. Returns 0 on success. An UNKNOWN option is refused with
// ENOPROTOOPT rather than passed through: the two ABIs reuse each other's numbers for different
// options, so a pass-through would silently configure the wrong one.
static int sockopt_l2b(int l_level, int l_opt, int* b_level, int* b_opt) {
    const nx_map_t* tbl; int n;
    switch (l_level) {
        case L_SOL_SOCKET:   *b_level = SOL_SOCKET;    tbl = g_so_tbl;  n = NX_ARRAY_LEN(g_so_tbl);  break;
        case L_IPPROTO_IP:   *b_level = IPPROTO_IP;    tbl = g_ip_tbl;  n = NX_ARRAY_LEN(g_ip_tbl);  break;
        case L_IPPROTO_IPV6: *b_level = IPPROTO_IPV6;  tbl = g_ip6_tbl; n = NX_ARRAY_LEN(g_ip6_tbl); break;
        case L_IPPROTO_TCP:  *b_level = IPPROTO_TCP;                  // TCP_NODELAY is 1 either way
                             if (l_opt != L_TCP_NODELAY) { errno = ENOPROTOOPT; return -1; }
                             *b_opt = l_opt; return 0;
        default: errno = ENOPROTOOPT; return -1;
    }
    int b = map_l2b(tbl, n, l_opt, -1);
    if (b < 0) { errno = ENOPROTOOPT; return -1; }
    *b_opt = b;
    return 0;
}

// Linux struct timeval is {long tv_sec; long tv_usec} — same as BSD's on aarch64/64-bit, so SO_*TIMEO
// payloads pass through. SO_LINGER is {int l_onoff; int l_linger} in both. The only payload that could
// need renumbering is SO_ERROR, and it does not: libnx's own source notes that Nintendo built their
// FreeBSD stack with LINUX errno values, so the errno SO_ERROR reports is already what the guest
// expects. (Flagged as an open risk — the net.c gate's non-blocking-connect section checks it.)
int nx_net_getsockopt(int fd, int l_level, int l_opt, void* val, unsigned* len) {
    if (len && nx_guest_buf_bad(val, *len)) { errno = EFAULT; return -1; }
    int b_level, b_opt;
    if (sockopt_l2b(l_level, l_opt, &b_level, &b_opt) < 0) return -1;
    int r = nx_bsd_getsockopt(fd, b_level, b_opt, val, len);
    // SO_TYPE reports a socket type, which IS renumbered between the ABIs for anything but
    // STREAM/DGRAM/RAW (1/2/3 are identical), so the common cases need no fixup.
    if (r < 0) netlog("nx_net: getsockopt fd=%d lvl=%d opt=%d failed e=%d rc=0x%x\n",
                      fd, l_level, l_opt, errno, socketGetLastResult());
    return r;
}

int nx_net_setsockopt(int fd, int l_level, int l_opt, const void* val, unsigned len) {
    if (nx_guest_buf_bad(val, len)) { errno = EFAULT; return -1; }
    int b_level, b_opt;
    if (sockopt_l2b(l_level, l_opt, &b_level, &b_opt) < 0) return -1;
    int r = nx_bsd_setsockopt(fd, b_level, b_opt, val, len);
    if (r < 0) netlog("nx_net: setsockopt fd=%d lvl=%d opt=%d failed e=%d rc=0x%x\n",
                      fd, l_level, l_opt, errno, socketGetLastResult());
    return r;
}

// ---- ioctl / fcntl / shutdown --------------------------------------------------------------------

// SHUT_RD/WR/RDWR are 0/1/2 in both ABIs. This replaces the vfd layer's "return 0 for any real fd",
// which would have silently no-op'd a TCP half-close.
int nx_net_shutdown(int fd, int how) {
    return nx_bsd_shutdown(fd, how);
}

// Only the two ioctls that mean something on a socket are honored. Everything else returns ENOTTY,
// per the standing rule (nx_vfd.c): Wine PROBES fds with terminal/ext-flag/readdir ioctls and a faked
// success either livelocks it or makes it misclassify the fd as a console.
int nx_net_ioctl(int fd, unsigned long l_req, void* arg) {
    switch (l_req) {
        case L_FIONBIO: {
            if (nx_guest_buf_bad(arg, sizeof(int))) { errno = EFAULT; return -1; }
            return nx_net_set_nonblock(fd, *(const int*)arg != 0);
        }
        case L_FIONREAD: {
            if (nx_guest_buf_bad(arg, sizeof(int))) { errno = EFAULT; return -1; }
            return nx_bsd_ioctl(fd, B_FIONREAD, arg);
        }
        default:
            errno = ENOTTY;
            return -1;
    }
}

// fcntl on a socket: Horizon's bsd supports exactly O_NONBLOCK, so the flag word is rebuilt in LINUX
// numbering rather than forwarded. An unknown cmd must not be forwarded either — libnx's fcntl returns
// a POSITIVE EOPNOTSUPP (not -1) for those, which a caller checking `< 0` reads as success.
enum { NX_L_F_GETFD = 1, NX_L_F_SETFD = 2, NX_L_F_GETFL = 3, NX_L_F_SETFL = 4 };

// ---- DNS configuration ---------------------------------------------------------------------------

// Fallback nameserver when nifm has none to offer (no link, or nifm itself unavailable). A wrong
// answer here is harmless — the resolver simply times out — whereas an EMPTY resolv.conf makes glibc
// fall back to 127.0.0.1:53, where nothing is listening, and the failure looks like a socket bug.
#define NX_NET_FALLBACK_DNS "8.8.8.8"

int nx_net_link_up(void) {
    if (!g_nifm_ok) return 0;
    NifmInternetConnectionType type = 0;
    NifmInternetConnectionStatus status = 0;
    u32 strength = 0;
    if (R_FAILED(nifmGetInternetConnectionStatus(&type, &strength, &status))) return 0;
    return status == NifmInternetConnectionStatus_Connected;
}

// Render /etc/resolv.conf into `buf`; returns the byte count written.
//
// `options single-request` matters: without it glibc's resolver sends the A and AAAA queries in
// PARALLEL on one socket, and modern glibc reaches for sendmmsg(2) to do it — which box64-nx does not
// route (it is in neither the scwrap table nor nx_x64_precase, so it ENOSYSes). single-request makes
// the resolver issue them sequentially with ordinary sendto/recvfrom, which is exactly the path this
// module implements.
int nx_net_resolv_conf(char* buf, size_t cap) {
    u32 addr = 0, mask = 0, gw = 0, dns1 = 0, dns2 = 0;
    int have = 0;
    if (g_nifm_ok && R_SUCCEEDED(nifmGetCurrentIpConfigInfo(&addr, &mask, &gw, &dns1, &dns2)))
        have = 1;

    int n = 0;
    // Horizon reports these as host-order u32; print octets explicitly rather than going through
    // inet_ntoa, which would pull in another libnx symbol for no benefit.
    #define NX_DNS_OCTETS(v) (unsigned)(((v) >> 24) & 0xff), (unsigned)(((v) >> 16) & 0xff), \
                             (unsigned)(((v) >>  8) & 0xff), (unsigned)((v) & 0xff)
    if (have && dns1) n += snprintf(buf + n, cap - (size_t)n, "nameserver %u.%u.%u.%u\n", NX_DNS_OCTETS(dns1));
    if (have && dns2) n += snprintf(buf + n, cap - (size_t)n, "nameserver %u.%u.%u.%u\n", NX_DNS_OCTETS(dns2));
    if (!n)           n += snprintf(buf + n, cap - (size_t)n, "nameserver " NX_NET_FALLBACK_DNS "\n");
    n += snprintf(buf + n, cap - (size_t)n, "options single-request timeout:5 attempts:2\n");
    #undef NX_DNS_OCTETS
    netlog("nx_net: resolv.conf nifm=%d dns1=0x%x dns2=0x%x\n", g_nifm_ok, dns1, dns2);
    return n;
}

// ---- poll ----------------------------------------------------------------------------------------

// Poll bits. Eight of the ten are numerically identical in both ABIs (IN/PRI/OUT/ERR/HUP/NVAL/RDNORM/
// RDBAND = 0x001..0x080); the top two collide dangerously and must never pass through:
//   Linux POLLWRNORM 0x100 == BSD POLLWRBAND 0x100     (asking to write would request out-of-band!)
//   Linux POLLWRBAND 0x200 == nothing in BSD
// BSD has no separate POLLWRNORM at all — it is an alias of POLLOUT.
enum {
    NX_POLL_SHARED     = 0x0FF,   // IN|PRI|OUT|ERR|HUP|NVAL|RDNORM|RDBAND — same value both sides
    L_POLLOUT          = 0x004,
    L_POLLNVAL         = 0x020,
    L_POLLWRNORM       = 0x100,
    L_POLLWRBAND       = 0x200,
    B_POLLOUT          = 0x004,
    B_POLLWRBAND       = 0x100,
};

typedef struct { int fd; short events; short revents; } nx_pollfd;   // identical layout in both ABIs

static short pollev_l2b(short l) {
    short b = (short)(l & NX_POLL_SHARED);
    if (l & L_POLLWRNORM) b |= B_POLLOUT;       // NOT a pass-through: 0x100 means WRBAND to BSD
    if (l & L_POLLWRBAND) b |= B_POLLWRBAND;
    return b;
}

static short pollev_b2l(short b, short l_events) {
    short l = (short)(b & NX_POLL_SHARED);
    if (b & B_POLLWRBAND) l |= L_POLLWRBAND;
    // Linux reports POLLWRNORM alongside POLLOUT on a writable socket; mirror it only when the caller
    // asked, so revents stays a subset of events (plus the always-reported ERR/HUP/NVAL).
    if ((b & B_POLLOUT) && (l_events & L_POLLWRNORM)) l |= L_POLLWRNORM;
    return l;
}

enum { NX_POLL_STACK_FDS = 64 };   // sockets polled without a heap allocation; beyond this, malloc

// Score the SOCKET entries of a Linux pollfd array via libnx, leaving every other entry untouched.
// Returns the number of socket entries with a non-zero revents, and sets *out_has_socket.
//
// libnx's poll() cannot be handed the guest's array directly for two reasons: it hard-FAILS the whole
// call with ENOTSOCK on the first non-socket fd it sees (so a mixed set must be compacted to sockets
// only), and its pollfd bit values differ from the guest's (above). A compact sub-array plus an index
// map solves both.
int nx_net_poll(void* l_pfds, unsigned long n, int timeout_ms, int* out_has_socket) {
    nx_pollfd* pf = (nx_pollfd*)l_pfds;
    if (out_has_socket) *out_has_socket = 0;
    if (!g_net_ok || !pf || !n) return 0;

    int stack_idx[NX_POLL_STACK_FDS];
    nx_pollfd stack_sub[NX_POLL_STACK_FDS];
    int* idx = stack_idx;
    nx_pollfd* sub = stack_sub;
    int* heap_idx = NULL;
    nx_pollfd* heap_sub = NULL;
    if (n > NX_POLL_STACK_FDS) {
        heap_idx = (int*)malloc(n * sizeof *heap_idx);
        heap_sub = (nx_pollfd*)malloc(n * sizeof *heap_sub);
        if (!heap_idx || !heap_sub) { free(heap_idx); free(heap_sub); errno = ENOMEM; return -1; }
        idx = heap_idx; sub = heap_sub;
    }

    unsigned nsub = 0;
    for (unsigned long i = 0; i < n; i++) {
        if (pf[i].fd < 0 || !nx_net_is_socket(pf[i].fd)) continue;
        idx[nsub] = (int)i;
        sub[nsub].fd      = pf[i].fd;
        sub[nsub].events  = pollev_l2b(pf[i].events);
        sub[nsub].revents = 0;
        nsub++;
    }
    if (out_has_socket) *out_has_socket = nsub != 0;

    int ready = 0;
    if (nsub) {
        int r = nx_bsd_poll(sub, nsub, timeout_ms);
        if (r < 0) {
            // A failed poll must not look like "nothing ready forever" — mark the sockets POLLNVAL so
            // the caller's loop terminates instead of spinning on a set it can never satisfy.
            netlog("nx_net: poll(n=%u) failed e=%d rc=0x%x\n", nsub, errno, socketGetLastResult());
            for (unsigned k = 0; k < nsub; k++) { pf[idx[k]].revents = L_POLLNVAL; ready++; }
        } else {
            for (unsigned k = 0; k < nsub; k++) {
                short l = pollev_b2l(sub[k].revents, pf[idx[k]].events);
                pf[idx[k]].revents = l;
                if (l) ready++;
            }
        }
    }
    free(heap_idx); free(heap_sub);
    return ready;
}

long nx_net_fcntl(int fd, int cmd, long arg) {
    switch (cmd) {
        case NX_L_F_GETFD: return 0;
        case NX_L_F_SETFD: return 0;                      // FD_CLOEXEC — no exec on Horizon
        case NX_L_F_GETFL: {
            int nb = nx_net_get_nonblock(fd);
            if (nb < 0) return -1;
            return 2 /*O_RDWR*/ | (nb ? L_O_NONBLOCK : 0);
        }
        case NX_L_F_SETFL:
            return nx_net_set_nonblock(fd, (arg & L_O_NONBLOCK) ? 1 : 0);
        default:
            errno = EINVAL;
            return -1;
    }
}

#endif // __SWITCH__
