#include "freq.h"

// TODO: box64_rdtsc?

uint64_t ReadTSC(x64emu_t* emu) {
    uint64_t val;
#ifdef __SWITCH__
    // KurokoNX: Horizon traps EL0 reads of the VIRTUAL counter (CNTVCT_EL0) — CNTKCTL_EL1.EL0VCTEN=0 on
    // the Switch — so `mrs cntvct_el0` from userland faults (a hard Data Abort on real HW; Ryujinx
    // emulates it, which is why it only broke on hardware). glibc's _dl_start issues rdtsc almost
    // immediately, so every guest died here. Use the PHYSICAL counter (CNTPCT_EL0) instead — the one
    // Horizon leaves EL0-readable, and exactly what libnx armGetSystemTick() reads. Both tick at the
    // Switch's fixed 19.2 MHz, so it stays consistent with ReadTSCFrequency (CNTFRQ_EL0, EL0-readable).
    asm volatile("mrs %0, cntpct_el0"
                 : "=r"(val));
#else
    asm volatile("mrs %0, cntvct_el0"
                 : "=r"(val));
#endif
    return val;
}

uint64_t ReadTSCFrequency(x64emu_t* emu) {
    uint64_t val;
    asm volatile("mrs %0, cntfrq_el0"
                 : "=r"(val));
    return val;
}