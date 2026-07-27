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

// 1 iff nifm:u came up (the DNS-server source for the synthesized /etc/resolv.conf).
int  nx_net_nifm_available(void);

// 1 iff nifm reports the console actually has an internet connection. Lets a caller (and the M2.8
// gate test) tell "offline console" apart from "broken shim".
int  nx_net_link_up(void);

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
int  nx_net_family_is_inet(int linux_domain);

// ---- syscall bodies ------------------------------------------------------------------------------
//
// Every argument and result below is a LINUX value: Linux AF_*/SOCK_*/SOL_*/SO_*/MSG_*/ioctl numbers,
// and Linux-layout sockaddrs ({u16 sa_family} heads, not BSD's {u8 sa_len, u8 sa_family}). errno is
// left in HOST (newlib) numbering for the x64syscall return seams to translate, exactly as the file
// syscalls do.
//
// `linux_capacity` is in/out wherever it appears: in = the guest's buffer size, out = the FULL address
// length, which is how Linux reports a truncated result.

int  nx_net_socket(int linux_domain, int linux_type, int linux_protocol);
int  nx_net_bind(int fd, const void* linux_address, unsigned linux_length);
int  nx_net_connect(int fd, const void* linux_address, unsigned linux_length);
int  nx_net_listen(int fd, int backlog);
int  nx_net_accept4(int fd, void* linux_address, unsigned* linux_capacity, int linux_flags);
int  nx_net_getsockname(int fd, void* linux_address, unsigned* linux_capacity);
int  nx_net_getpeername(int fd, void* linux_address, unsigned* linux_capacity);

long nx_net_sendto(int fd, const void* buffer, size_t length, int linux_flags,
                   const void* linux_address, unsigned linux_address_length);
long nx_net_recvfrom(int fd, void* buffer, size_t length, int linux_flags,
                     void* linux_address, unsigned* linux_capacity);
long nx_net_sendmsg(int fd, const void* linux_message, int linux_flags);
long nx_net_recvmsg(int fd, void* linux_message, int linux_flags);

int  nx_net_getsockopt(int fd, int linux_level, int linux_option, void* value, unsigned* value_length);
int  nx_net_setsockopt(int fd, int linux_level, int linux_option, const void* value, unsigned value_length);
int  nx_net_shutdown(int fd, int how);
int  nx_net_ioctl(int fd, unsigned long linux_request, void* argument);
long nx_net_fcntl(int fd, int command, long argument);

// O_NONBLOCK is the one fcntl flag Horizon's bsd supports, and it is spelled differently in all three
// ABIs involved (Linux 0x800, newlib 0x4000, BSD 0x20000000) — so it gets dedicated accessors that
// every entry point (socket/accept4 type flags, fcntl F_SETFL, ioctl FIONBIO) funnels through.
int  nx_net_set_nonblock(int fd, int enable);
int  nx_net_get_nonblock(int fd);

// Score ONLY the socket entries of a Linux pollfd array, leaving the rest untouched, and report
// whether the set contained any. Returns the number of socket entries that came back ready.
// nx_poll() (nx_vfd.c) calls this for the socket half of a mixed vfd/file/socket set.
int  nx_net_poll(void* linux_pollfds, unsigned long count, int timeout_ms, int* out_has_socket);

// ---- DNS configuration ---------------------------------------------------------------------------

// Render /etc/resolv.conf from nifm's current DNS servers; returns bytes written. Called per open()
// from the VFS, so a network change is picked up without a restart.
int  nx_net_resolv_conf(char* buffer, size_t capacity);

#ifdef __cplusplus
}
#endif

#endif // __SWITCH__
