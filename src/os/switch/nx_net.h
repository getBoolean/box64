// nx_net.h — guest AF_INET/AF_INET6 sockets over Horizon's bsd:u (box64-nx). See nx_net.c.
//
// M2.5 gave the guest AF_UNIX sockets as pure in-process vfds (nx_vfd.c). INET sockets are the
// opposite: Horizon already HAS a full FreeBSD-derived stack behind bsd:u, and libnx's socket.o —
// already linked in and initialized by nx_main.c — exposes it as ordinary newlib fds (devoptab "soc"),
// so read/write/close work on them unmodified. What is missing is only the guest syscall seam: every
// AF_INET socket() is rejected by nx_socket() before it ever reaches libnx.
//
// So this module is a TRANSLATOR, not a socket implementation. Horizon's ABI is FreeBSD's and the
// guest's is Linux's; they disagree on sockaddr headers, SOL_SOCKET, every SO_*/IP_*, the MSG_* bits,
// AF_INET6, SOCK_NONBLOCK, and the ioctl request numbers. Every function here takes and returns
// LINUX values and speaks BSD to libnx. errno is left as the HOST (newlib) value — libnx's wrappers
// already convert bsd errno to newlib via _convert_errno(), and box64's existing x64syscall return
// seams (nx_errno_h2l) translate newlib -> Linux exactly as they do for file syscalls.
#pragma once
#ifdef __SWITCH__

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// ---- lifecycle -----------------------------------------------------------------------------------

// Bring up bsd:u + nifm:u. Called from nx_main AFTER load_env_file() so the KX_NET gate is readable.
// Never fatal: a title whose NPDM lacks the services records unavailable and every socket() then
// returns EAFNOSUPPORT exactly as before M2.8.
void nx_net_init(void);
void nx_net_exit(void);

// 1 iff sockets are usable (KX_NET set AND the services came up). Every dispatch branch tests this
// first, so with KX_NET unset box64 behaves byte-for-byte as it did before M2.8.
int  nx_net_available(void);

// ---- identification ------------------------------------------------------------------------------

// 1 iff fd is a live libnx bsd socket. Authoritative (it asks newlib's handle table for the fd's
// devoptab, rather than trusting a shadow table to have seen every open and close), and cheap enough
// for the hot I/O paths: a bounds check, a refcount check and one integer compare.
//
// This is what keeps a socket OUT of the SD I/O funnel. A libnx socket fd is a plain newlib fd > 2,
// so it passes nx_fs_real_file()'s other tests; without this a blocking guest recv() would be
// dispatched onto the single fsdev worker thread and freeze ALL guest file I/O until data arrived.
int  nx_net_is_socket(int fd);

// Is this Linux address family one we route to bsd:u? (AF_INET / AF_INET6 — AF_UNIX stays on the
// M2.5 vfd layer, everything else is refused.)
int  nx_net_family_is_inet(int l_domain);

#ifdef __cplusplus
}
#endif

#endif // __SWITCH__
