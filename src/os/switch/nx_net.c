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
#include <sys/iosupport.h>   // __get_handle / devoptab_list / FindDevice — socket-fd identification

#include "nx_net.h"

extern void nx_result_log(const char*);   // nx_main.c — heap-free SD result line (the real-HW channel)

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

#endif // __SWITCH__
