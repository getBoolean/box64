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

#ifdef __cplusplus
}
#endif

#endif // __SWITCH__
