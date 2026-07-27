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

#endif // __SWITCH__
