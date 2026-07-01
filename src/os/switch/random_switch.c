// box64 Horizon port — randomness (box64-nx), via libnx randomGet64 (seeded from csrng).
#ifdef __SWITCH__

#include <stdint.h>
#include <switch.h>
#include "random.h"

uint32_t get_random32(void) { return (uint32_t)randomGet64(); }
uint64_t get_random64(void) { return randomGet64(); }

#endif // __SWITCH__
