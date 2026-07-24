// box64-nx — "kuro-posix": libnx-backed host primitives for the box64 Horizon port.
//
// box64's os_switch.c calls these for the handful of host-OS operations newlib/libnx don't
// provide Linux-style. Kept small; grows as box64's needs surface during M1 bring-up.
#pragma once
#ifdef __SWITCH__

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

// Memory. M1.0/M1.1 (interpreter): anonymous RW via the heap; MAP_FIXED/exec handled later
// (exec arenas move to the libnx jit dual-alias in M1.2).
void *nx_mmap(void *addr, unsigned long length, int prot, int flags, int fd, ssize_t offset);
int   nx_munmap(void *addr, unsigned long length);
int   nx_vm_protect(void *addr, size_t len, int prot);   // real mprotect (none/R/RW); nx_virtmem.c
// Startup diagnostic: 1 = real svcMapPhysicalMemory arena (NSP), -1 = heap fallback (NRO). Forces
// arena init; fills the arena span and process SystemResourceSize. See nx_main.c.
int   nx_vm_status(uintptr_t *base, size_t *size, unsigned long long *sysres);

// Thread / scheduling.
int nx_gettid(void);
int nx_sched_yield(void);

// M2.3: translate a host (newlib) errno number to the Linux errno the guest glibc expects. Applied
// at the syscall-return seam (emu/x64syscall.c). Identity for values that already match Linux.
int nx_errno_h2l(int host_errno);

// M2.4: rootfs VFS. Translate a guest Linux path to a Horizon (sdmc:) path or a materialized
// pseudo-file. Guest "/" is rooted at sdmc:/box64/rootfs/, with a flat sdmc:/box64/lib/<basename>
// fallback and synthetic /proc,/dev entries. out[outn] receives the Horizon path. 0 ok, -1 (ENOENT).
int nx_translate_path(const char *guest_path, char *out, size_t outn);
// Phase 1/2 (2026-07-23): resolution-cache-aware translate that also hands back the probe result so the
// caller (openat) needn't re-stat. *exists (nullable) is set 1 ONLY on a probe hit, when *out_st
// (nullable) receives that stat; the 3-arg nx_translate_path is a wrapper passing NULL,NULL. See the
// "Fewer FS-service IPCs per guest file op" block in nx_posix.c.
struct stat;
int nx_translate_path_ex(const char *guest_path, char *out, size_t outn, int *exists, struct stat *out_st);
// Drop a cached guest-path->host resolution after a successful mutation at that path (mkdir/unlink/rmdir/
// rename/O_CREAT). Takes a RAW guest path; normalized internally to match the cache key. No-op when the
// cache is disabled (KX_NO_PATHCACHE). Companion nx_pc_flush()/nx_ipc_stats_dump() use local externs.
void nx_pc_invalidate(const char *raw_guest_path);
// Convert Linux open()/openat() flags (what the guest passes) to newlib/host <fcntl.h> flags.
int nx_oflags_l2h(int linux_flags);

#ifdef __cplusplus
}
#endif

#endif // __SWITCH__
