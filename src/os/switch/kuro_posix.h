// KurokoNX — "kuro-posix": libnx-backed host primitives for the box64 Horizon port.
//
// box64's os_switch.c calls these for the handful of host-OS operations newlib/libnx don't
// provide Linux-style. Kept small; grows as box64's needs surface during M1 bring-up.
#pragma once
#ifdef __SWITCH__

#include <stddef.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

// Memory. M1.0/M1.1 (interpreter): anonymous RW via the heap; MAP_FIXED/exec handled later
// (exec arenas move to the libnx jit dual-alias in M1.2).
void *kuro_mmap(void *addr, unsigned long length, int prot, int flags, int fd, ssize_t offset);
int   kuro_munmap(void *addr, unsigned long length);

// Thread / scheduling.
int kuro_gettid(void);
int kuro_sched_yield(void);

#ifdef __cplusplus
}
#endif

#endif // __SWITCH__
