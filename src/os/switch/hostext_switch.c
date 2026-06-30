// box64 Horizon port — host CPU feature detection (KurokoNX).
// Switch = Tegra X1, Cortex-A57, ARMv8.0-A: NEON + crypto (AES/SHA1/SHA2/PMULL) + CRC32.
// No ARMv8.1+ extensions (atomics/flagm/rndr/...). Hardcoded (the interpreter doesn't depend on
// this; the dynarec will, M1.2).
#ifdef __SWITCH__

#include "debug.h"   // extern cpu_ext_t cpuext;

int DetectHostCpuFeatures(void) {
#ifdef DYNAREC   // cpuext only exists in dynarec builds; the interpreter doesn't need features
    cpuext.asimd = 1;
    cpuext.crc32 = 1;
    cpuext.aes = cpuext.sha1 = cpuext.sha2 = cpuext.pmull = 1;
#endif
    return 1;
}

#endif // __SWITCH__
