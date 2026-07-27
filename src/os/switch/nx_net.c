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
// This is not paranoia: box64-nx force-includes shim/static_compat.h into every translation unit, and
// its shim headers SHADOW libnx's. <poll.h> resolves to shim/poll.h, where nfds_t is `unsigned long`
// (libnx: `unsigned int`) and POLLWRNORM is 0x100 (libnx: 0x004 == POLLOUT) — so calling poll()
// normally would bind libnx's symbol through a mismatched declaration and silently mean a different
// thing by POLLWRNORM. <sys/filio.h> is worse: it drags in ioccom.h, whose `int ioctl(int, int, ...)`
// is a HARD conflict with the shim's `int ioctl(int, unsigned long, ...)` and will not compile at all.
//
// So: bind the symbols by asm name with libnx's true prototypes, and never include the headers that
// would fight the shim. The `nx_bsd_` prefix also makes every call site read as "this crosses into
// Horizon's stack", which is the whole point of this file.
extern int     nx_bsd_socket(int domain, int type, int protocol)                            __asm__("socket");
extern int     nx_bsd_bind(int fd, const void* address, unsigned address_length)            __asm__("bind");
extern int     nx_bsd_connect(int fd, const void* address, unsigned address_length)         __asm__("connect");
extern int     nx_bsd_listen(int fd, int backlog)                                           __asm__("listen");
extern int     nx_bsd_accept(int fd, void* address, unsigned* address_length)               __asm__("accept");
extern int     nx_bsd_getsockname(int fd, void* address, unsigned* address_length)          __asm__("getsockname");
extern int     nx_bsd_getpeername(int fd, void* address, unsigned* address_length)          __asm__("getpeername");
extern int     nx_bsd_getsockopt(int fd, int level, int option, void* value,
                                 unsigned* value_length)                                    __asm__("getsockopt");
extern int     nx_bsd_setsockopt(int fd, int level, int option, const void* value,
                                 unsigned value_length)                                     __asm__("setsockopt");
extern ssize_t nx_bsd_sendto(int fd, const void* buffer, size_t length, int flags,
                             const void* address, unsigned address_length)                  __asm__("sendto");
extern ssize_t nx_bsd_recvfrom(int fd, void* buffer, size_t length, int flags,
                               void* address, unsigned* address_length)                     __asm__("recvfrom");
extern int     nx_bsd_shutdown(int fd, int how)                                             __asm__("shutdown");
extern int     nx_bsd_ioctl(int fd, int request, ...)                                       __asm__("ioctl");
extern int     nx_bsd_fcntl(int fd, int command, ...)                                       __asm__("fcntl");
// libnx's poll(), with ITS nfds_t (unsigned int) and ITS pollfd bit values. Only ever called on an
// array of socket fds — see nx_net_poll().
extern int     nx_bsd_poll(void* pollfds, unsigned int count, int timeout_ms)                __asm__("poll");
// The RAW service call, below the devoptab layer — it takes a bsd descriptor, not a newlib fd. Its
// header (switch/services/bsd.h) is not includable here: it pulls <poll.h>, which the shim owns.
// Needed because libnx's public ioctl() implements FIONBIO by delegating to its fcntl(), leaving no
// way to set non-blocking on a stack that has no fcntl. See nx_net_set_nonblock().
extern int     bsdIoctl(int descriptor, int request, void* data);

// ---- the two ABIs --------------------------------------------------------------------------------
//
// LINUX side (the guest's values — no header here defines them, so they are spelled out).
enum {
    LINUX_AF_UNIX = 1, LINUX_AF_INET = 2, LINUX_AF_INET6 = 10, LINUX_AF_NETLINK = 16,

    LINUX_SOCK_STREAM = 1, LINUX_SOCK_DGRAM = 2, LINUX_SOCK_RAW = 3,
    // type-word flag bits (BSD numbers these differently: 0x20000000 / 0x10000000)
    LINUX_SOCK_NONBLOCK = 0x800, LINUX_SOCK_CLOEXEC = 0x80000,

    LINUX_SOL_SOCKET = 1,                             // BSD: 0xffff — the single most dangerous delta
    LINUX_IPPROTO_IP = 0, LINUX_IPPROTO_TCP = 6, LINUX_IPPROTO_UDP = 17, LINUX_IPPROTO_IPV6 = 41,

    // SOL_SOCKET options
    LINUX_SO_DEBUG = 1, LINUX_SO_REUSEADDR = 2, LINUX_SO_TYPE = 3, LINUX_SO_ERROR = 4,
    LINUX_SO_DONTROUTE = 5, LINUX_SO_BROADCAST = 6, LINUX_SO_SNDBUF = 7, LINUX_SO_RCVBUF = 8,
    LINUX_SO_KEEPALIVE = 9, LINUX_SO_OOBINLINE = 10, LINUX_SO_LINGER = 13, LINUX_SO_REUSEPORT = 15,
    LINUX_SO_RCVLOWAT = 18, LINUX_SO_SNDLOWAT = 19, LINUX_SO_RCVTIMEO = 20, LINUX_SO_SNDTIMEO = 21,
    LINUX_SO_ACCEPTCONN = 30,

    // IPPROTO_IP options
    LINUX_IP_TOS = 1, LINUX_IP_TTL = 2, LINUX_IP_HDRINCL = 3, LINUX_IP_OPTIONS = 4,
    LINUX_IP_MULTICAST_IF = 32, LINUX_IP_MULTICAST_TTL = 33, LINUX_IP_MULTICAST_LOOP = 34,
    LINUX_IP_ADD_MEMBERSHIP = 35, LINUX_IP_DROP_MEMBERSHIP = 36,

    // IPPROTO_IPV6 options
    LINUX_IPV6_UNICAST_HOPS = 16, LINUX_IPV6_MULTICAST_IF = 17, LINUX_IPV6_MULTICAST_HOPS = 18,
    LINUX_IPV6_MULTICAST_LOOP = 19, LINUX_IPV6_JOIN_GROUP = 20, LINUX_IPV6_LEAVE_GROUP = 21,
    LINUX_IPV6_V6ONLY = 26,

    // IPPROTO_TCP options — TCP_NODELAY is 1 in both ABIs (verified against netinet/tcp.h).
    LINUX_TCP_NODELAY = 1,

    // send/receive flags
    LINUX_MSG_OOB = 0x01, LINUX_MSG_PEEK = 0x02, LINUX_MSG_DONTROUTE = 0x04, LINUX_MSG_CTRUNC = 0x08,
    LINUX_MSG_TRUNC = 0x20, LINUX_MSG_DONTWAIT = 0x40, LINUX_MSG_EOR = 0x80,
    LINUX_MSG_WAITALL = 0x100, LINUX_MSG_NOSIGNAL = 0x4000,

    LINUX_O_NONBLOCK = 0x800,        // newlib's is 0x4000 — never pass one for the other
    LINUX_FIONBIO = 0x5421, LINUX_FIONREAD = 0x541B,

    LINUX_SHUT_READ = 0, LINUX_SHUT_WRITE = 1, LINUX_SHUT_READ_WRITE = 2,   // identical in both ABIs
};

// BSD values that libnx's usable headers do NOT give us. FIONBIO/FIONREAD live in <sys/filio.h>, which
// cannot be included here (see the ioctl conflict above), so the _IOW/_IOR encodings are inlined:
//   FIONBIO = _IOW('f', 126, int) = 0x8004667E,  FIONREAD = _IOR('f', 127, int) = 0x4004667F.
enum { BSD_FIONBIO = 0x8004667E, BSD_FIONREAD = 0x4004667F };

// BSD sockaddr length byte: FreeBSD's `struct sockaddr` leads with {u8 sa_len, u8 sa_family} where
// Linux has a single {u16 sa_family}. Both sockaddr_in (16 B) and sockaddr_in6 (28 B) are otherwise
// byte-identical between the two ABIs, so conversion is a two-byte head fixup, not a struct rebuild.
//
// NB libnx's own `struct sockaddr_in6` is INCONSISTENT with its `struct sockaddr`: it declares
// `sa_family_t sin6_family` first with no sin6_len, leaving byte 1 as implicit padding. Following that
// would put the family in byte 0 and garbage in byte 1, which FreeBSD reads as a length. We therefore
// build the BSD sockaddr as bytes ourselves, per the documented FreeBSD ABI, and never lay libnx's
// sockaddr_in6 over the wire buffer.
enum { NX_SOCKADDR_MAX = 128 };   // sockaddr_storage-sized scratch; larger than any family we route

#define NX_ARRAY_LENGTH(array) ((int)(sizeof(array) / sizeof((array)[0])))

typedef struct { int linux_value; int bsd_value; } nx_value_map;

// Look a Linux value up in a table; returns `on_miss` when absent (callers turn that into ENOPROTOOPT
// rather than guessing, because a wrong option number silently configures the WRONG option).
static int map_linux_to_bsd(const nx_value_map* table, int count, int linux_value, int on_miss) {
    for (int i = 0; i < count; i++) if (table[i].linux_value == linux_value) return table[i].bsd_value;
    return on_miss;
}

// ---- diagnostics ---------------------------------------------------------------------------------

// Horizon Result codes that libnx's _socketParseBsdResult() cannot map become a bare EPIPE (its
// switch has three cases and an EPIPE default), so a service-level failure is indistinguishable from
// a real broken pipe. When KX_NET_LOG is set, print the raw Result alongside each failure so that
// ambiguity is resolvable without a rebuild.
static int net_log_enabled(void) {
    static int enabled = -1;
    if (enabled < 0) enabled = getenv("KX_NET_LOG") ? 1 : 0;
    return enabled;
}

static void net_log(const char* format, ...) {
    if (!net_log_enabled()) return;
    char line[192]; va_list args; va_start(args, format);
    int length = vsnprintf(line, sizeof line, format, args); va_end(args);
    if (length > 0) svcOutputDebugString(line, (size_t)length);
}

// ---- availability --------------------------------------------------------------------------------

enum { NX_SOCKET_DEVICE_NONE = -1 };   // no "soc" devoptab registered => no sockets exist

// KX_NET_SMALLBUF profile — enough for DNS and a few modest TCP streams, well below libnx's default.
enum {
    NX_NET_SMALL_TCP_BUFFER       = 0x8000,    // 32 KiB initial send/receive window per socket
    NX_NET_SMALL_TCP_BUFFER_MAX   = 0x20000,   // 128 KiB ceiling when the stack grows the window
    NX_NET_SMALL_BUFFER_COUNT     = 1,         // buffers per socket (libnx's default is higher)
};

static int g_socket_ready        = 0;                       // bsd:u usable
static int g_network_info_ready  = 0;                       // nifm:u usable (DNS servers + link status)
static int g_socket_device_index = NX_SOCKET_DEVICE_NONE;   // devoptab_list index of libnx's "soc"

int nx_net_available(void)       { return g_socket_ready; }
int nx_net_nifm_available(void)  { return g_network_info_ready; }

// A socket fd is any live newlib handle whose devoptab is libnx's "soc". Asking the handle table is
// exact where a shadow table is only as good as its bookkeeping: newlib releases the handle itself on
// close (and on the accept/socket failure paths), so there is no forget() to forget to call, and no
// fd-number ceiling to overflow. __get_handle() already returns NULL for out-of-range and for
// refcount==0, which is the whole validity check.
int nx_net_is_socket(int fd) {
    if (g_socket_device_index == NX_SOCKET_DEVICE_NONE || fd < 0) return 0;   // fast out when M2.8 is off
    __handle* handle = __get_handle(fd);
    return handle && (int)handle->device == g_socket_device_index;
}

int nx_net_family_is_inet(int linux_domain) {
    return linux_domain == LINUX_AF_INET || linux_domain == LINUX_AF_INET6;
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
    int device_index = FindDevice("soc:");
    if (device_index < 0) {
        // libnx's default socket buffers are backed by a transfer memory block carved out of the SAME
        // heap the guest address space comes from — and on real HW the Wine low-VA path
        // (KX_FORCE_HEAP) is sensitive to what that heap looks like. KX_NET_SMALLBUF trims the buffers
        // to a DNS + modest-TCP profile so the cost of enabling networking can be A/B'd against a Wine
        // run without a rebuild.
        const SocketInitConfig* config = socketGetDefaultInitConfig();
        SocketInitConfig small_config;
        if (getenv("KX_NET_SMALLBUF")) {
            small_config = *config;
            small_config.tcp_tx_buf_size     = small_config.tcp_rx_buf_size     = NX_NET_SMALL_TCP_BUFFER;
            small_config.tcp_tx_buf_max_size = small_config.tcp_rx_buf_max_size = NX_NET_SMALL_TCP_BUFFER_MAX;
            small_config.sb_efficiency       = NX_NET_SMALL_BUFFER_COUNT;
            config = &small_config;
        }
        Result socket_result = socketInitialize(config);
        if (R_FAILED(socket_result)) {
            char line[96];
            int length = snprintf(line, sizeof line,
                                  "nx_net: socketInitialize FAILED rc=0x%x (no bsd:u in NPDM?)", socket_result);
            if (length > 0) nx_result_log(line);
            return;
        }
        device_index = FindDevice("soc:");
    }
    if (device_index < 0) { nx_result_log("nx_net: no 'soc' devoptab after init"); return; }

    g_socket_device_index = device_index;
    g_socket_ready        = 1;

    // nifm supplies the DNS servers for the synthesized /etc/resolv.conf and the link-status
    // pre-flight. Its absence is not fatal — resolv.conf falls back to a public resolver.
    Result nifm_result  = nifmInitialize(NifmServiceType_User);
    g_network_info_ready = R_SUCCEEDED(nifm_result);

    char line[128];
    int length = snprintf(line, sizeof line, "nx_net: ready bsd:u dev=%d nifm=%d",
                          g_socket_device_index, g_network_info_ready);
    if (length > 0) nx_result_log(line);
    net_log("nx_net: init nifm rc=0x%x\n", nifm_result);
}

void nx_net_exit(void) {
    if (g_network_info_ready) { nifmExit(); g_network_info_ready = 0; }
    // socketExit() stays with nx_main's teardown: on the NRO it owns the socket stack (netloader),
    // and calling it here would tear down nxlink's stdio channel out from under it.
    g_socket_ready        = 0;
    g_socket_device_index = NX_SOCKET_DEVICE_NONE;
}

// ---- address translation -------------------------------------------------------------------------

static int family_linux_to_bsd(int linux_family) {
    switch (linux_family) {
        case LINUX_AF_INET:  return AF_INET;    // 2 -> 2
        case LINUX_AF_INET6: return AF_INET6;   // 10 -> 28
        default:             return -1;
    }
}

static int family_bsd_to_linux(int bsd_family) {
    switch (bsd_family) {
        case AF_INET:  return LINUX_AF_INET;
        case AF_INET6: return LINUX_AF_INET6;
        default:       return -1;
    }
}

// The wire length Horizon expects for a family. FreeBSD validates sa_len, and a Linux guest routinely
// passes sizeof(struct sockaddr_storage) (128) as the address length rather than the exact family
// size, so derive the length from the FAMILY instead of trusting the guest's count.
static unsigned sockaddr_wire_length(int bsd_family) {
    switch (bsd_family) {
        case AF_INET:  return sizeof(struct sockaddr_in);    // 16
        case AF_INET6: return sizeof(struct sockaddr_in6);   // 28
        default:       return 0;
    }
}

// Linux sockaddr -> BSD, into `bsd_out` (NX_SOCKADDR_MAX bytes). Returns the BSD wire length, or 0 if
// the family is not one we route. Only bytes 0..1 change: Linux's u16 sa_family becomes BSD's
// {u8 sa_len, u8 sa_family}; every later byte (port, address, scope) is identical in both ABIs.
static unsigned sockaddr_linux_to_bsd(const void* linux_address, unsigned linux_length, uint8_t* bsd_out) {
    if (!linux_address || linux_length < 2) return 0;
    const uint8_t* linux_bytes = (const uint8_t*)linux_address;
    int bsd_family = family_linux_to_bsd(linux_bytes[0] | (linux_bytes[1] << 8));
    if (bsd_family < 0) return 0;
    unsigned wire_length = sockaddr_wire_length(bsd_family);
    if (!wire_length) return 0;
    unsigned copy_length = linux_length < wire_length ? linux_length : wire_length;
    memset(bsd_out, 0, wire_length);
    if (copy_length > 2) memcpy(bsd_out + 2, linux_bytes + 2, copy_length - 2);
    bsd_out[0] = (uint8_t)wire_length;   // sa_len
    bsd_out[1] = (uint8_t)bsd_family;    // sa_family
    return wire_length;
}

// BSD sockaddr -> Linux: writes at most *linux_capacity bytes into linux_address and reports the FULL
// length back in *linux_capacity, which is what Linux getsockname/accept do (a short buffer is
// truncated, and the caller still learns the real size). Returns 0, or -1 with errno on an unroutable
// family.
static int sockaddr_bsd_to_linux(const uint8_t* bsd_address, unsigned bsd_length,
                                 void* linux_address, unsigned* linux_capacity) {
    int linux_family = family_bsd_to_linux(bsd_address[1]);
    if (linux_family < 0) { errno = EAFNOSUPPORT; return -1; }
    if (linux_address && linux_capacity && *linux_capacity) {
        uint8_t converted[NX_SOCKADDR_MAX];
        unsigned length = bsd_length < sizeof converted ? bsd_length : (unsigned)sizeof converted;
        memcpy(converted, bsd_address, length);
        converted[0] = (uint8_t)(linux_family & 0xff);   // Linux u16 sa_family, little-endian
        converted[1] = (uint8_t)(linux_family >> 8);
        unsigned copy_length = *linux_capacity < length ? *linux_capacity : length;
        memcpy(linux_address, converted, copy_length);
    }
    if (linux_capacity) *linux_capacity = bsd_length;
    return 0;
}

// ---- socket creation and connection setup --------------------------------------------------------

// Non-blocking is set through libnx's fcntl, which speaks NEWLIB O_NONBLOCK and rejects any other bit
// with EINVAL — passing the guest's Linux 0x800 straight through would fail. Shared by
// socket(SOCK_NONBLOCK), accept4(SOCK_NONBLOCK), fcntl(F_SETFL) and ioctl(FIONBIO).
enum { NEWLIB_O_NONBLOCK = 0x4000, NEWLIB_F_GETFL = 3, NEWLIB_F_SETFL = 4 };

// libnx's fcntl() cannot be error-checked by its return value. On failure it still runs the -1
// through from_nx(), which tests one bit and yields a POSITIVE O_NONBLOCK — so `result < 0` never
// fires, a failed F_GETFL reads as "non-blocking is set", and a failed F_SETFL reads as success. Its
// success value is not Linux's either: F_SETFL must return 0, but libnx returns whatever the bsd
// F_SETFL returned, mapped through from_nx.
//
// So both accessors clear errno, call, and judge by errno — then normalize the result themselves.
static int bsd_fcntl_checked(int fd, int command, int flags, int* out_result) {
    errno = 0;
    int result = nx_bsd_fcntl(fd, command, flags);
    if (errno) return -1;
    if (out_result) *out_result = result;
    return 0;
}

// The raw bsd descriptor behind a newlib socket fd, obtained the same way libnx's own private
// _socketGetFd() does. Needed to reach bsdIoctl DIRECTLY: libnx's public ioctl() implements FIONBIO by
// delegating to its fcntl(), so when a stack has no fcntl there is no way to set non-blocking through
// the public API at all. Returns -1 if fd is not a socket.
static int bsd_descriptor(int fd) {
    __handle* handle = __get_handle(fd);
    if (!handle || (int)handle->device != g_socket_device_index) return -1;
    return *(int*)handle->fileStruct;
}

// Remembered non-blocking state, consulted only when the stack cannot report it (see below). Indexed
// by newlib fd; entries are reset when a socket is created or accepted, which is the only way an fd
// number can be reused, so a stale entry cannot outlive its socket.
enum { NX_NONBLOCK_TRACK_MAX = 256 };
static uint8_t g_nonblock_shadow[NX_NONBLOCK_TRACK_MAX];

static void nonblock_shadow_set(int fd, int enable) {
    if (fd >= 0 && fd < NX_NONBLOCK_TRACK_MAX) g_nonblock_shadow[fd] = enable ? 1 : 0;
}
static int nonblock_shadow_get(int fd) {
    return (fd >= 0 && fd < NX_NONBLOCK_TRACK_MAX) ? g_nonblock_shadow[fd] : 0;
}

// Two routes, because bsd:u implementations differ in what they support:
//   1. libnx's fcntl(F_GETFL/F_SETFL) — the documented path, and what real Horizon answers;
//   2. bsdIoctl(FIONBIO) on the raw descriptor — reaches the stack directly when it has no fcntl.
//      Ryujinx's HLE bsd is exactly this case: no Fcntl handler at all, so every fcntl fails, and
//      libnx's from_nx(-1) artifact made those failures look like SUCCESS until this was checked
//      properly. Non-blocking is not optional — a non-blocking connect is how both Wine's ws2_32 and
//      glibc's resolver work — so it gets a second route rather than a graceful degradation.
int nx_net_set_nonblock(int fd, int enable) {
    int flags = 0;
    if (bsd_fcntl_checked(fd, NEWLIB_F_GETFL, 0, &flags) == 0) {
        flags = enable ? (flags | NEWLIB_O_NONBLOCK) : (flags & ~NEWLIB_O_NONBLOCK);
        if (bsd_fcntl_checked(fd, NEWLIB_F_SETFL, flags, NULL) == 0) {
            nonblock_shadow_set(fd, enable);
            return 0;   // Linux F_SETFL returns 0, not the flag word
        }
    }
    net_log("nx_net: F_SETFL fd=%d enable=%d failed e=%d rc=0x%x -> FIONBIO fallback\n",
            fd, enable, errno, socketGetLastResult());

    int descriptor = bsd_descriptor(fd);
    if (descriptor < 0) { errno = ENOTSOCK; return -1; }
    int value = enable ? 1 : 0;
    if (bsdIoctl(descriptor, BSD_FIONBIO, &value) < 0) {
        net_log("nx_net: FIONBIO fd=%d enable=%d failed rc=0x%x\n", fd, enable, socketGetLastResult());
        errno = EOPNOTSUPP;
        return -1;
    }
    nonblock_shadow_set(fd, enable);
    return 0;
}

int nx_net_get_nonblock(int fd) {
    int flags = 0;
    if (bsd_fcntl_checked(fd, NEWLIB_F_GETFL, 0, &flags) == 0)
        return (flags & NEWLIB_O_NONBLOCK) ? 1 : 0;
    // The stack cannot tell us, so report what we last successfully set. Reporting an error instead
    // would break the read-back half of Wine's set-then-check pattern on a socket that IS correctly
    // configured.
    return nonblock_shadow_get(fd);
}

int nx_net_socket(int linux_domain, int linux_type, int linux_protocol) {
    if (!g_socket_ready) { errno = EAFNOSUPPORT; return -1; }
    int bsd_family = family_linux_to_bsd(linux_domain);
    if (bsd_family < 0) { errno = EAFNOSUPPORT; return -1; }

    int bsd_type;
    switch (linux_type & 0xff) {
        case LINUX_SOCK_STREAM: bsd_type = SOCK_STREAM; break;   // 1 -> 1
        case LINUX_SOCK_DGRAM:  bsd_type = SOCK_DGRAM;  break;   // 2 -> 2
        case LINUX_SOCK_RAW:    bsd_type = SOCK_RAW;    break;   // 3 -> 3 (bsd:u will likely refuse it)
        default: errno = EPROTONOSUPPORT; return -1;
    }
    // IPPROTO_* are identical in both ABIs (0/6/17/41 — verified against netinet/in.h), so the
    // protocol passes through.
    int fd = nx_bsd_socket(bsd_family, bsd_type, linux_protocol);
    if (fd < 0) {
        net_log("nx_net: socket(af=%d type=%d proto=%d) failed e=%d rc=0x%x\n",
                linux_domain, linux_type, linux_protocol, errno, socketGetLastResult());
        return -1;
    }
    nonblock_shadow_set(fd, 0);   // fresh socket: blocking, and clears any stale entry for this fd
    // SOCK_NONBLOCK/SOCK_CLOEXEC are encoded in the type word on Linux (0x800/0x80000) and
    // differently on BSD (0x20000000/0x10000000). Rather than depend on Horizon's bsd honoring the
    // type-word encoding at all, apply non-blocking afterwards through the fcntl path that is known to
    // work. CLOEXEC is meaningless here — Horizon has no exec.
    if ((linux_type & LINUX_SOCK_NONBLOCK) && nx_net_set_nonblock(fd, 1) < 0) {
        int saved_errno = errno; close(fd); errno = saved_errno; return -1;
    }
    return fd;
}

int nx_net_bind(int fd, const void* linux_address, unsigned linux_length) {
    if (nx_guest_buf_bad(linux_address, linux_length)) { errno = EFAULT; return -1; }
    uint8_t bsd_address[NX_SOCKADDR_MAX];
    unsigned wire_length = sockaddr_linux_to_bsd(linux_address, linux_length, bsd_address);
    if (!wire_length) { errno = EAFNOSUPPORT; return -1; }
    int result = nx_bsd_bind(fd, bsd_address, wire_length);
    if (result < 0) net_log("nx_net: bind fd=%d failed e=%d rc=0x%x\n", fd, errno, socketGetLastResult());
    return result;
}

int nx_net_connect(int fd, const void* linux_address, unsigned linux_length) {
    if (nx_guest_buf_bad(linux_address, linux_length)) { errno = EFAULT; return -1; }
    uint8_t bsd_address[NX_SOCKADDR_MAX];
    unsigned wire_length = sockaddr_linux_to_bsd(linux_address, linux_length, bsd_address);
    if (!wire_length) { errno = EAFNOSUPPORT; return -1; }
    int result = nx_bsd_connect(fd, bsd_address, wire_length);
    // EINPROGRESS on a non-blocking connect is the NORMAL path (it is how both Wine's ws2_32 and
    // glibc's resolver connect), so do not log it as a failure.
    if (result < 0 && errno != EINPROGRESS)
        net_log("nx_net: connect fd=%d failed e=%d rc=0x%x\n", fd, errno, socketGetLastResult());
    return result;
}

int nx_net_listen(int fd, int backlog) {
    return nx_bsd_listen(fd, backlog);
}

int nx_net_accept4(int fd, void* linux_address, unsigned* linux_capacity, int linux_flags) {
    if (linux_capacity && nx_guest_buf_bad(linux_address, *linux_capacity)) { errno = EFAULT; return -1; }
    uint8_t bsd_address[NX_SOCKADDR_MAX];
    unsigned bsd_length = sizeof bsd_address;
    int accepted_fd = nx_bsd_accept(fd, bsd_address, &bsd_length);
    if (accepted_fd < 0) return -1;
    nonblock_shadow_set(accepted_fd, 0);   // accepted sockets start blocking, per POSIX
    if (bsd_length >= 2 &&
        sockaddr_bsd_to_linux(bsd_address, bsd_length, linux_address, linux_capacity) < 0) {
        close(accepted_fd); return -1;
    }
    if ((linux_flags & LINUX_SOCK_NONBLOCK) && nx_net_set_nonblock(accepted_fd, 1) < 0) {
        int saved_errno = errno; close(accepted_fd); errno = saved_errno; return -1;
    }
    return accepted_fd;
}

int nx_net_getsockname(int fd, void* linux_address, unsigned* linux_capacity) {
    if (linux_capacity && nx_guest_buf_bad(linux_address, *linux_capacity)) { errno = EFAULT; return -1; }
    uint8_t bsd_address[NX_SOCKADDR_MAX];
    unsigned bsd_length = sizeof bsd_address;
    if (nx_bsd_getsockname(fd, bsd_address, &bsd_length) < 0) return -1;
    if (bsd_length < 2) { errno = EINVAL; return -1; }
    return sockaddr_bsd_to_linux(bsd_address, bsd_length, linux_address, linux_capacity);
}

// Distinct from getsockname: the M2.5 vfd layer aliased the two (harmless for AF_UNIX, where neither
// end has a meaningful peer address), but for TCP the peer address is the whole point — Wine's
// ws2_32 getpeername and glibc both rely on it.
int nx_net_getpeername(int fd, void* linux_address, unsigned* linux_capacity) {
    if (linux_capacity && nx_guest_buf_bad(linux_address, *linux_capacity)) { errno = EFAULT; return -1; }
    uint8_t bsd_address[NX_SOCKADDR_MAX];
    unsigned bsd_length = sizeof bsd_address;
    if (nx_bsd_getpeername(fd, bsd_address, &bsd_length) < 0) return -1;
    if (bsd_length < 2) { errno = ENOTCONN; return -1; }
    return sockaddr_bsd_to_linux(bsd_address, bsd_length, linux_address, linux_capacity);
}

// ---- send / receive ------------------------------------------------------------------------------

// MSG_* differ in nearly every bit position. Anything not listed is dropped rather than passed
// through: an unrecognized flag reaching FreeBSD as a DIFFERENT flag is worse than not honoring it
// (MSG_NOSIGNAL in particular has no BSD equivalent and is a no-op here — Horizon raises no SIGPIPE).
static int msg_flags_linux_to_bsd(int linux_flags) {
    static const nx_value_map table[] = {
        { LINUX_MSG_OOB,       MSG_OOB       },   // 0x01 -> 0x01
        { LINUX_MSG_PEEK,      MSG_PEEK      },   // 0x02 -> 0x02
        { LINUX_MSG_DONTROUTE, MSG_DONTROUTE },   // 0x04 -> 0x04
        { LINUX_MSG_EOR,       MSG_EOR       },   // 0x80 -> 0x08
        { LINUX_MSG_TRUNC,     MSG_TRUNC     },   // 0x20 -> 0x10
        { LINUX_MSG_CTRUNC,    MSG_CTRUNC    },   // 0x08 -> 0x20
        { LINUX_MSG_WAITALL,   MSG_WAITALL   },   // 0x100 -> 0x40
        { LINUX_MSG_DONTWAIT,  MSG_DONTWAIT  },   // 0x40 -> 0x80
    };
    int bsd_flags = 0;
    for (int i = 0; i < NX_ARRAY_LENGTH(table); i++)
        if (linux_flags & table[i].linux_value) bsd_flags |= table[i].bsd_value;
    return bsd_flags;
}

long nx_net_sendto(int fd, const void* buffer, size_t length, int linux_flags,
                   const void* linux_address, unsigned linux_address_length) {
    if (nx_guest_buf_bad(buffer, length)) { errno = EFAULT; return -1; }
    uint8_t bsd_address[NX_SOCKADDR_MAX];
    unsigned wire_length = 0;
    if (linux_address && linux_address_length) {
        if (nx_guest_buf_bad(linux_address, linux_address_length)) { errno = EFAULT; return -1; }
        wire_length = sockaddr_linux_to_bsd(linux_address, linux_address_length, bsd_address);
        if (!wire_length) { errno = EAFNOSUPPORT; return -1; }
    }
    return (long)nx_bsd_sendto(fd, buffer, length, msg_flags_linux_to_bsd(linux_flags),
                               wire_length ? bsd_address : NULL, wire_length);
}

long nx_net_recvfrom(int fd, void* buffer, size_t length, int linux_flags,
                     void* linux_address, unsigned* linux_capacity) {
    if (nx_guest_buf_bad(buffer, length)) { errno = EFAULT; return -1; }
    uint8_t bsd_address[NX_SOCKADDR_MAX];
    unsigned bsd_length = sizeof bsd_address;
    int want_address = (linux_address && linux_capacity && *linux_capacity);
    if (want_address && nx_guest_buf_bad(linux_address, *linux_capacity)) { errno = EFAULT; return -1; }
    long received = (long)nx_bsd_recvfrom(fd, buffer, length, msg_flags_linux_to_bsd(linux_flags),
                                          want_address ? bsd_address : NULL,
                                          want_address ? &bsd_length : NULL);
    if (received < 0) return -1;
    if (want_address && bsd_length >= 2)
        sockaddr_bsd_to_linux(bsd_address, bsd_length, linux_address, linux_capacity);
    else if (linux_capacity) *linux_capacity = 0;
    return received;
}

// Linux x86-64 layouts, mirroring the declarations in nx_vfd.c (the vfd layer owns the AF_UNIX side of
// these same structs). NOT interchangeable with libnx's: BSD's msghdr is 48 bytes to Linux's 56
// because msg_iovlen and msg_controllen are 32-bit there. Hence field-by-field, never a cast.
typedef struct { void* base; size_t length; } linux_iovec;
typedef struct {
    void*        name;
    unsigned     name_length;
    linux_iovec* iov;
    size_t       iov_count;
    void*        control;
    size_t       control_length;
    int          flags;
} linux_msghdr;

// libnx exposes no devoptab sendmsg/recvmsg, so scatter/gather is done here around sendto/recvfrom.
// A single-iovec message (the overwhelmingly common case, and what glibc's resolver emits) passes
// through with no copy; multi-iovec messages are packed through a bounce buffer, because a datagram
// MUST leave as one packet — looping sendto() per iovec would fragment one message into several.
enum { NX_MSG_BOUNCE_MAX = 64 * 1024 };   // datagram ceiling; larger multi-iov sends report EMSGSIZE

long nx_net_sendmsg(int fd, const void* linux_message, int linux_flags) {
    if (nx_guest_buf_bad(linux_message, sizeof(linux_msghdr))) { errno = EFAULT; return -1; }
    const linux_msghdr* message = (const linux_msghdr*)linux_message;
    // Ancillary data over INET has no meaning here: SCM_RIGHTS is an AF_UNIX concept and the vfd layer
    // owns it. Ignore control rather than fail — Linux ignores unknown cmsgs on INET too.
    if (message->iov_count == 0)
        return (long)nx_bsd_sendto(fd, "", 0, msg_flags_linux_to_bsd(linux_flags), NULL, 0);
    if (message->iov_count == 1)
        return nx_net_sendto(fd, message->iov[0].base, message->iov[0].length, linux_flags,
                             message->name, message->name_length);

    size_t total = 0;
    for (size_t i = 0; i < message->iov_count; i++) total += message->iov[i].length;
    if (total > NX_MSG_BOUNCE_MAX) { errno = EMSGSIZE; return -1; }
    uint8_t* packed = (uint8_t*)malloc(total ? total : 1);
    if (!packed) { errno = ENOMEM; return -1; }
    size_t offset = 0;
    for (size_t i = 0; i < message->iov_count; i++) {
        if (nx_guest_buf_bad(message->iov[i].base, message->iov[i].length)) {
            free(packed); errno = EFAULT; return -1;
        }
        memcpy(packed + offset, message->iov[i].base, message->iov[i].length);
        offset += message->iov[i].length;
    }
    long sent = nx_net_sendto(fd, packed, total, linux_flags, message->name, message->name_length);
    int saved_errno = errno;
    free(packed);
    errno = saved_errno;
    return sent;
}

long nx_net_recvmsg(int fd, void* linux_message, int linux_flags) {
    if (nx_guest_buf_bad(linux_message, sizeof(linux_msghdr))) { errno = EFAULT; return -1; }
    linux_msghdr* message = (linux_msghdr*)linux_message;
    message->control_length = 0;   // no ancillary data is ever produced on an INET socket
    if (message->iov_count == 0) { message->flags = 0; return 0; }
    if (message->iov_count == 1) {
        unsigned name_capacity = message->name_length;
        long received = nx_net_recvfrom(fd, message->iov[0].base, message->iov[0].length, linux_flags,
                                        message->name, message->name ? &name_capacity : NULL);
        if (received >= 0) {
            message->name_length = message->name ? name_capacity : 0;
            message->flags = 0;
        }
        return received;
    }
    // Multi-iovec: receive the whole datagram once into a bounce buffer, then scatter. Reading per
    // iovec would consume one datagram per call and drop the remainder of each.
    size_t total = 0;
    for (size_t i = 0; i < message->iov_count; i++) total += message->iov[i].length;
    if (total > NX_MSG_BOUNCE_MAX) total = NX_MSG_BOUNCE_MAX;
    uint8_t* packed = (uint8_t*)malloc(total ? total : 1);
    if (!packed) { errno = ENOMEM; return -1; }
    unsigned name_capacity = message->name_length;
    long received = nx_net_recvfrom(fd, packed, total, linux_flags,
                                    message->name, message->name ? &name_capacity : NULL);
    if (received < 0) { int saved_errno = errno; free(packed); errno = saved_errno; return -1; }
    size_t offset = 0;
    for (size_t i = 0; i < message->iov_count && offset < (size_t)received; i++) {
        size_t chunk = message->iov[i].length;
        if (chunk > (size_t)received - offset) chunk = (size_t)received - offset;
        if (nx_guest_buf_bad(message->iov[i].base, chunk)) { free(packed); errno = EFAULT; return -1; }
        memcpy(message->iov[i].base, packed + offset, chunk);
        offset += chunk;
    }
    free(packed);
    message->name_length = message->name ? name_capacity : 0;
    message->flags       = 0;
    return received;
}

// ---- socket options ------------------------------------------------------------------------------

static const nx_value_map g_socket_option_map[] = {          // SOL_SOCKET (Linux 1 -> BSD 0xffff)
    { LINUX_SO_DEBUG,      SO_DEBUG      },   { LINUX_SO_REUSEADDR, SO_REUSEADDR },
    { LINUX_SO_TYPE,       SO_TYPE       },   { LINUX_SO_ERROR,     SO_ERROR     },
    { LINUX_SO_DONTROUTE,  SO_DONTROUTE  },   { LINUX_SO_BROADCAST, SO_BROADCAST },
    { LINUX_SO_SNDBUF,     SO_SNDBUF     },   { LINUX_SO_RCVBUF,    SO_RCVBUF    },
    { LINUX_SO_KEEPALIVE,  SO_KEEPALIVE  },   { LINUX_SO_OOBINLINE, SO_OOBINLINE },
    { LINUX_SO_LINGER,     SO_LINGER     },   { LINUX_SO_REUSEPORT, SO_REUSEPORT },
    { LINUX_SO_RCVLOWAT,   SO_RCVLOWAT   },   { LINUX_SO_SNDLOWAT,  SO_SNDLOWAT  },
    { LINUX_SO_RCVTIMEO,   SO_RCVTIMEO   },   { LINUX_SO_SNDTIMEO,  SO_SNDTIMEO  },
    { LINUX_SO_ACCEPTCONN, SO_ACCEPTCONN },
};

static const nx_value_map g_ip_option_map[] = {              // IPPROTO_IP (0 in both)
    { LINUX_IP_TOS,             IP_TOS             }, { LINUX_IP_TTL,            IP_TTL            },
    { LINUX_IP_HDRINCL,         IP_HDRINCL         }, { LINUX_IP_OPTIONS,        IP_OPTIONS        },
    { LINUX_IP_MULTICAST_IF,    IP_MULTICAST_IF    }, { LINUX_IP_MULTICAST_TTL,  IP_MULTICAST_TTL  },
    { LINUX_IP_MULTICAST_LOOP,  IP_MULTICAST_LOOP  }, { LINUX_IP_ADD_MEMBERSHIP, IP_ADD_MEMBERSHIP },
    { LINUX_IP_DROP_MEMBERSHIP, IP_DROP_MEMBERSHIP },
};

static const nx_value_map g_ipv6_option_map[] = {            // IPPROTO_IPV6 (41 in both)
    { LINUX_IPV6_UNICAST_HOPS,   IPV6_UNICAST_HOPS   },
    { LINUX_IPV6_MULTICAST_IF,   IPV6_MULTICAST_IF   },
    { LINUX_IPV6_MULTICAST_HOPS, IPV6_MULTICAST_HOPS },
    { LINUX_IPV6_MULTICAST_LOOP, IPV6_MULTICAST_LOOP },
    { LINUX_IPV6_JOIN_GROUP,     IPV6_JOIN_GROUP     },
    { LINUX_IPV6_LEAVE_GROUP,    IPV6_LEAVE_GROUP    },
    { LINUX_IPV6_V6ONLY,         IPV6_V6ONLY         },
};

// Resolve a (level, option) pair. Returns 0 on success. An UNKNOWN option is refused with ENOPROTOOPT
// rather than passed through: the two ABIs reuse each other's numbers for different options, so a
// pass-through would silently configure the wrong one.
static int sockopt_linux_to_bsd(int linux_level, int linux_option,
                                int* bsd_level, int* bsd_option) {
    const nx_value_map* table; int count;
    switch (linux_level) {
        case LINUX_SOL_SOCKET:
            *bsd_level = SOL_SOCKET;   table = g_socket_option_map; count = NX_ARRAY_LENGTH(g_socket_option_map); break;
        case LINUX_IPPROTO_IP:
            *bsd_level = IPPROTO_IP;   table = g_ip_option_map;     count = NX_ARRAY_LENGTH(g_ip_option_map);     break;
        case LINUX_IPPROTO_IPV6:
            *bsd_level = IPPROTO_IPV6; table = g_ipv6_option_map;   count = NX_ARRAY_LENGTH(g_ipv6_option_map);   break;
        case LINUX_IPPROTO_TCP:
            *bsd_level = IPPROTO_TCP;                             // TCP_NODELAY is 1 either way
            if (linux_option != LINUX_TCP_NODELAY) { errno = ENOPROTOOPT; return -1; }
            *bsd_option = linux_option;
            return 0;
        default: errno = ENOPROTOOPT; return -1;
    }
    int mapped = map_linux_to_bsd(table, count, linux_option, -1);
    if (mapped < 0) { errno = ENOPROTOOPT; return -1; }
    *bsd_option = mapped;
    return 0;
}

// Linux struct timeval is {long tv_sec; long tv_usec} — same as BSD's on 64-bit, so SO_*TIMEO payloads
// pass through. SO_LINGER is {int l_onoff; int l_linger} in both. The only payload that could need
// renumbering is SO_ERROR, and it does not: libnx's own source notes that Nintendo built their FreeBSD
// stack with LINUX errno values, so the errno SO_ERROR reports is already what the guest expects.
// (Flagged as an open risk — the net.c gate's non-blocking-connect section checks it.)
int nx_net_getsockopt(int fd, int linux_level, int linux_option, void* value, unsigned* value_length) {
    if (value_length && nx_guest_buf_bad(value, *value_length)) { errno = EFAULT; return -1; }
    int bsd_level, bsd_option;
    if (sockopt_linux_to_bsd(linux_level, linux_option, &bsd_level, &bsd_option) < 0) return -1;
    int result = nx_bsd_getsockopt(fd, bsd_level, bsd_option, value, value_length);
    // SO_TYPE reports a socket type, which IS renumbered between the ABIs for anything but
    // STREAM/DGRAM/RAW (1/2/3 are identical), so the common cases need no fixup.
    if (result < 0) net_log("nx_net: getsockopt fd=%d level=%d option=%d failed e=%d rc=0x%x\n",
                            fd, linux_level, linux_option, errno, socketGetLastResult());
    return result;
}

int nx_net_setsockopt(int fd, int linux_level, int linux_option, const void* value, unsigned value_length) {
    if (nx_guest_buf_bad(value, value_length)) { errno = EFAULT; return -1; }
    int bsd_level, bsd_option;
    if (sockopt_linux_to_bsd(linux_level, linux_option, &bsd_level, &bsd_option) < 0) return -1;
    int result = nx_bsd_setsockopt(fd, bsd_level, bsd_option, value, value_length);
    if (result < 0) net_log("nx_net: setsockopt fd=%d level=%d option=%d failed e=%d rc=0x%x\n",
                            fd, linux_level, linux_option, errno, socketGetLastResult());
    return result;
}

// ---- ioctl / fcntl / shutdown --------------------------------------------------------------------

// SHUT_RD/WR/RDWR are 0/1/2 in both ABIs. This replaces the vfd layer's "return 0 for any real fd",
// which would have silently no-op'd a TCP half-close.
int nx_net_shutdown(int fd, int how) {
    return nx_bsd_shutdown(fd, how);
}

// Scratch size for the MSG_PEEK fallback when bsd:u has no FIONREAD ioctl. Thread-local rather than
// stack-allocated: FIONREAD can be called from any guest thread and 64 KiB is far too much stack.
enum { NX_FIONREAD_PEEK_MAX = 64 * 1024 };

// How many bytes can be read right now. Three routes, in decreasing order of fidelity, because bsd:u
// implementations differ in what they support:
//   1. the FIONREAD ioctl — exact, and what a real FreeBSD stack answers;
//   2. a non-blocking MSG_PEEK — the same question asked a different way. Semantics stay close to
//      Linux: on UDP a peek reports the first datagram's size, which is what Linux FIONREAD returns
//      too; on TCP the answer is capped at the scratch buffer, so a caller sizing a read gets a valid
//      if conservative number;
//   3. report ZERO. Reached only when the stack supports NEITHER (Ryujinx's HLE bsd rejects the ioctl
//      with "Unsupported Ioctl Cmd" AND has no MSG_PEEK). Zero is the conservative truth — "no bytes
//      are known to be queued" — and a caller then polls or reads as it would anyway. This does NOT
//      violate the never-fake-an-ioctl rule from nx_vfd.c: that rule is about UNKNOWN ioctls used by
//      Wine to CLASSIFY an fd, where a faked success causes misclassification. FIONREAD is a known,
//      supported operation on a socket and is a data-availability query, so failing it outright is
//      the worse answer.
static int fionread_bytes_available(int fd, int* out_bytes) {
    if (nx_bsd_ioctl(fd, BSD_FIONREAD, out_bytes) == 0) return 0;
    net_log("nx_net: FIONREAD ioctl fd=%d e=%d rc=0x%x -> MSG_PEEK fallback\n",
            fd, errno, socketGetLastResult());
    if (errno != EOPNOTSUPP && errno != ENOSYS && errno != EINVAL) return -1;

    static __thread uint8_t peek_buffer[NX_FIONREAD_PEEK_MAX];
    uint8_t bsd_address[NX_SOCKADDR_MAX];
    unsigned bsd_length = sizeof bsd_address;
    // recvfrom, NOT recv: an UNCONNECTED socket (a fresh TCP fd, or a UDP fd that was only bound)
    // rejects recv() with ENOTCONN on any POSIX stack. recvfrom works on both.
    ssize_t peeked = nx_bsd_recvfrom(fd, peek_buffer, sizeof peek_buffer,
                                     MSG_PEEK | MSG_DONTWAIT, bsd_address, &bsd_length);
    if (peeked >= 0) { *out_bytes = (int)peeked; return 0; }

    net_log("nx_net: FIONREAD peek fd=%d e=%d rc=0x%x\n", fd, errno, socketGetLastResult());
    // Nothing queued (EAGAIN) and not-yet-connected (ENOTCONN) both mean zero readable bytes, which is
    // exactly what Linux FIONREAD reports for those states. EOPNOTSUPP means the stack has no
    // MSG_PEEK either — route 3.
    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOTCONN ||
        errno == EOPNOTSUPP || errno == ENOSYS) { *out_bytes = 0; return 0; }
    return -1;
}

// Only the two ioctls that mean something on a socket are honored. Everything else returns ENOTTY,
// per the standing rule (nx_vfd.c): Wine PROBES fds with terminal/ext-flag/readdir ioctls and a faked
// success either livelocks it or makes it misclassify the fd as a console.
int nx_net_ioctl(int fd, unsigned long linux_request, void* argument) {
    switch (linux_request) {
        case LINUX_FIONBIO:
            if (nx_guest_buf_bad(argument, sizeof(int))) { errno = EFAULT; return -1; }
            return nx_net_set_nonblock(fd, *(const int*)argument != 0);
        case LINUX_FIONREAD:
            if (nx_guest_buf_bad(argument, sizeof(int))) { errno = EFAULT; return -1; }
            return fionread_bytes_available(fd, (int*)argument);
        default:
            errno = ENOTTY;
            return -1;
    }
}

// fcntl on a socket: Horizon's bsd supports exactly O_NONBLOCK, so the flag word is rebuilt in LINUX
// numbering rather than forwarded. An unknown command must not be forwarded either — libnx's fcntl
// returns a POSITIVE EOPNOTSUPP (not -1) for those, which a caller checking `< 0` reads as success.
enum { LINUX_F_GETFD = 1, LINUX_F_SETFD = 2, LINUX_F_GETFL = 3, LINUX_F_SETFL = 4 };

long nx_net_fcntl(int fd, int command, long argument) {
    switch (command) {
        case LINUX_F_GETFD: return 0;
        case LINUX_F_SETFD: return 0;                      // FD_CLOEXEC — no exec on Horizon
        case LINUX_F_GETFL: {
            int nonblocking = nx_net_get_nonblock(fd);
            if (nonblocking < 0) return -1;
            return 2 /*O_RDWR*/ | (nonblocking ? LINUX_O_NONBLOCK : 0);
        }
        case LINUX_F_SETFL:
            return nx_net_set_nonblock(fd, (argument & LINUX_O_NONBLOCK) ? 1 : 0);
        default:
            errno = EINVAL;
            return -1;
    }
}

// ---- DNS configuration ---------------------------------------------------------------------------

// Fallback nameserver when nifm has none to offer (no link, or nifm itself unavailable). A wrong
// answer here is harmless — the resolver simply times out — whereas an EMPTY resolv.conf makes glibc
// fall back to 127.0.0.1:53, where nothing is listening, and the failure looks like a socket bug.
#define NX_NET_FALLBACK_NAMESERVER "8.8.8.8"

int nx_net_link_up(void) {
    if (!g_network_info_ready) return 0;
    NifmInternetConnectionType connection_type = 0;
    NifmInternetConnectionStatus connection_status = 0;
    u32 wifi_strength = 0;
    if (R_FAILED(nifmGetInternetConnectionStatus(&connection_type, &wifi_strength, &connection_status)))
        return 0;
    return connection_status == NifmInternetConnectionStatus_Connected;
}

// Render /etc/resolv.conf into `buffer`; returns the byte count written.
//
// `options single-request` matters: without it glibc's resolver sends the A and AAAA queries in
// PARALLEL on one socket, and modern glibc reaches for sendmmsg(2) to do it — which box64-nx does not
// route (it is in neither the scwrap table nor nx_x64_precase, so it ENOSYSes). single-request makes
// the resolver issue them sequentially with ordinary sendto/recvfrom, which is exactly the path this
// module implements.
int nx_net_resolv_conf(char* buffer, size_t capacity) {
    u32 host_address = 0, subnet_mask = 0, gateway = 0, primary_nameserver = 0, secondary_nameserver = 0;
    int have_config = 0;
    if (g_network_info_ready &&
        R_SUCCEEDED(nifmGetCurrentIpConfigInfo(&host_address, &subnet_mask, &gateway,
                                               &primary_nameserver, &secondary_nameserver)))
        have_config = 1;

    int written = 0;
    // nifm hands these back NETWORK-ORDER-in-a-u32: the FIRST dotted octet is the LOW byte, not the
    // high one. HW-verified 2026-07-27 — reading them the other way printed the router 192.168.8.1 as
    // "1.8.168.192". Printed octet-wise rather than via inet_ntoa, which would pull in another libnx
    // symbol for no benefit.
    #define NX_ADDRESS_OCTETS(address) (unsigned)( (address)        & 0xff), \
                                       (unsigned)(((address) >>  8) & 0xff), \
                                       (unsigned)(((address) >> 16) & 0xff), \
                                       (unsigned)(((address) >> 24) & 0xff)
    if (have_config && primary_nameserver)
        written += snprintf(buffer + written, capacity - (size_t)written,
                            "nameserver %u.%u.%u.%u\n", NX_ADDRESS_OCTETS(primary_nameserver));
    if (have_config && secondary_nameserver)
        written += snprintf(buffer + written, capacity - (size_t)written,
                            "nameserver %u.%u.%u.%u\n", NX_ADDRESS_OCTETS(secondary_nameserver));
    if (!written)
        written += snprintf(buffer + written, capacity - (size_t)written,
                            "nameserver " NX_NET_FALLBACK_NAMESERVER "\n");
    written += snprintf(buffer + written, capacity - (size_t)written,
                        "options single-request timeout:5 attempts:2\n");
    #undef NX_ADDRESS_OCTETS
    net_log("nx_net: resolv.conf nifm=%d dns1=0x%x dns2=0x%x\n",
            g_network_info_ready, primary_nameserver, secondary_nameserver);
    return written;
}

// ---- poll ----------------------------------------------------------------------------------------

// Poll bits. Eight of the ten are numerically identical in both ABIs (IN/PRI/OUT/ERR/HUP/NVAL/RDNORM/
// RDBAND = 0x001..0x080); the top two collide dangerously and must never pass through:
//   Linux POLLWRNORM 0x100 == BSD POLLWRBAND 0x100     (asking to write would request out-of-band!)
//   Linux POLLWRBAND 0x200 == nothing in BSD
// BSD has no separate POLLWRNORM at all — it is an alias of POLLOUT.
enum {
    NX_POLL_SHARED_BITS = 0x0FF,   // IN|PRI|OUT|ERR|HUP|NVAL|RDNORM|RDBAND — same value both sides
    LINUX_POLLOUT       = 0x004,
    LINUX_POLLNVAL      = 0x020,
    LINUX_POLLWRNORM    = 0x100,
    LINUX_POLLWRBAND    = 0x200,
    BSD_POLLOUT         = 0x004,
    BSD_POLLWRBAND      = 0x100,
};

typedef struct { int fd; short events; short revents; } nx_pollfd;   // identical layout in both ABIs

static short poll_events_linux_to_bsd(short linux_events) {
    short bsd_events = (short)(linux_events & NX_POLL_SHARED_BITS);
    if (linux_events & LINUX_POLLWRNORM) bsd_events |= BSD_POLLOUT;   // NOT a pass-through: 0x100
    if (linux_events & LINUX_POLLWRBAND) bsd_events |= BSD_POLLWRBAND;   //  means WRBAND to BSD
    return bsd_events;
}

static short poll_revents_bsd_to_linux(short bsd_revents, short linux_events) {
    short linux_revents = (short)(bsd_revents & NX_POLL_SHARED_BITS);
    if (bsd_revents & BSD_POLLWRBAND) linux_revents |= LINUX_POLLWRBAND;
    // Linux reports POLLWRNORM alongside POLLOUT on a writable socket; mirror it only when the caller
    // asked, so revents stays a subset of events (plus the always-reported ERR/HUP/NVAL).
    if ((bsd_revents & BSD_POLLOUT) && (linux_events & LINUX_POLLWRNORM))
        linux_revents |= LINUX_POLLWRNORM;
    return linux_revents;
}

enum { NX_POLL_STACK_FDS = 64 };   // sockets polled without a heap allocation; beyond this, malloc

// Score the SOCKET entries of a Linux pollfd array via libnx, leaving every other entry untouched.
// Returns the number of socket entries with a non-zero revents, and sets *out_has_socket.
//
// libnx's poll() cannot be handed the guest's array directly for two reasons: it hard-FAILS the whole
// call with ENOTSOCK on the first non-socket fd it sees (so a mixed set must be compacted to sockets
// only), and its pollfd bit values differ from the guest's (above). A compact sub-array plus an index
// map solves both.
int nx_net_poll(void* linux_pollfds, unsigned long count, int timeout_ms, int* out_has_socket) {
    nx_pollfd* guest_fds = (nx_pollfd*)linux_pollfds;
    if (out_has_socket) *out_has_socket = 0;
    if (!g_socket_ready || !guest_fds || !count) return 0;

    int        stack_index_map[NX_POLL_STACK_FDS];
    nx_pollfd  stack_socket_fds[NX_POLL_STACK_FDS];
    int*       index_map      = stack_index_map;
    nx_pollfd* socket_fds     = stack_socket_fds;
    int*       heap_index_map = NULL;
    nx_pollfd* heap_socket_fds = NULL;
    if (count > NX_POLL_STACK_FDS) {
        heap_index_map  = (int*)malloc(count * sizeof *heap_index_map);
        heap_socket_fds = (nx_pollfd*)malloc(count * sizeof *heap_socket_fds);
        if (!heap_index_map || !heap_socket_fds) {
            free(heap_index_map); free(heap_socket_fds); errno = ENOMEM; return -1;
        }
        index_map = heap_index_map; socket_fds = heap_socket_fds;
    }

    unsigned socket_count = 0;
    for (unsigned long i = 0; i < count; i++) {
        if (guest_fds[i].fd < 0 || !nx_net_is_socket(guest_fds[i].fd)) continue;
        index_map[socket_count]           = (int)i;
        socket_fds[socket_count].fd       = guest_fds[i].fd;
        socket_fds[socket_count].events   = poll_events_linux_to_bsd(guest_fds[i].events);
        socket_fds[socket_count].revents  = 0;
        socket_count++;
    }
    if (out_has_socket) *out_has_socket = socket_count != 0;

    int ready_count = 0;
    if (socket_count) {
        int result = nx_bsd_poll(socket_fds, socket_count, timeout_ms);
        if (result < 0) {
            // A failed poll must not look like "nothing ready forever" — mark the sockets POLLNVAL so
            // the caller's loop terminates instead of spinning on a set it can never satisfy.
            net_log("nx_net: poll(count=%u) failed e=%d rc=0x%x\n",
                    socket_count, errno, socketGetLastResult());
            for (unsigned k = 0; k < socket_count; k++) {
                guest_fds[index_map[k]].revents = LINUX_POLLNVAL;
                ready_count++;
            }
        } else {
            for (unsigned k = 0; k < socket_count; k++) {
                short linux_revents = poll_revents_bsd_to_linux(socket_fds[k].revents,
                                                                guest_fds[index_map[k]].events);
                guest_fds[index_map[k]].revents = linux_revents;
                if (linux_revents) ready_count++;
            }
        }
    }
    free(heap_index_map); free(heap_socket_fds);
    return ready_count;
}

#endif // __SWITCH__
