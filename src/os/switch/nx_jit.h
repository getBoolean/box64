// box64-nx — libnx jit-backed W^X code memory for the ARM64 dynarec (M1.2).
//
// Horizon enforces W^X: no page is writable and executable at once. box64's dynarec assumes a
// single RWX arena. libnx `jit` instead gives two aliases of the same physical pages — a writable
// `rw` alias and an executable `rx` alias. The M1.2 Phase-0 spike (tests/m1/jitprobe) proved these
// aliases COEXIST on Horizon (write via `rw` while executing via `rx`, no per-block transition),
// so box64's lazy-compile-while-running model maps on directly.
//
// Design (see docs/porting-log.md M1.2 Phase 0): the WRITABLE (`rw`) address is canonical — box64's
// block allocator (custommem) and all instruction emission operate on it UNCHANGED. Only the
// handful of *execution* sites (jump-table installs, the dispatcher, the I-cache flush) translate a
// canonical `rw` pointer to its `rx` alias by subtracting a fixed per-chunk bias.
#pragma once

#include <stddef.h>
#include <stdint.h>

// Allocate one executable code-cache chunk of at least `size` bytes (rounded up to a page) via
// libnx `jitCreate` + one `jitTransitionToExecutable`. Returns the chunk's WRITABLE (`rw`) base
// (what box64 treats as the chunk pointer), or NULL on failure. On success, `*out_rw_bias` receives
// `rw_base - rx_base`: subtract it from any `rw` pointer inside this chunk to get the executable
// (`rx`) alias of the same location. The backing `Jit` object is retained until process exit
// (no free during a run — matches the M1 static-guest scope).
//
// Cache coherence between the write and execute aliases is handled by box64's own `ClearCache`
// (dynarec_native.c), which on Switch cleans the D-cache on the `rw` alias and invalidates the
// I-cache on the `rx` alias after each block is emitted — so there is no separate sync entry point.
void* nx_jit_alloc(size_t size, int64_t* out_rw_bias);

// box64-nx (M2.2c2): translate an EXECUTABLE (`rx`) address inside a JIT chunk to its WRITABLE (`rw`)
// alias (rw = rx + rw_bias). Used by the Horizon CPU-exception handler to map a faulting native PC to
// the rw alias that the dynablock index and getX64Address expect. Returns NULL if `rx` is not JIT code.
void* nx_jit_rx_to_rw(void* rx);
