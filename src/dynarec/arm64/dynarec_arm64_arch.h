#ifndef __DYNAREC_ARM_ARCH_H__
#define __DYNAREC_ARM_ARCH_H__

#include <stddef.h>

#include "x64emu.h"
#include "box64context.h"
#include "box64cpu.h"
#include "dynarec_arm64_private.h"

// get size of arch specific info (can be 0)
size_t get_size_arch(dynarec_arm_t* dyn);
//populate the array
void* populate_arch(dynarec_arm_t* dyn, void* p, size_t sz);
#if !defined(_WIN32)
// box64-nx (M2.2c2): re-enabled on Horizon. <ucontext.h> resolves to the Switch shim
// (src/os/switch/shim/ucontext.h), which provides the Linux-aarch64 sigcontext + fpsimd_context /
// FPSIMD_MAGIC this reads; the CPU-exception handler (nx_exception.c) populates uc_mcontext.pstate +
// an FPSIMD record in __reserved[] from the ThreadExceptionDump so this reconstructs EFLAGS/SSE/x87.
#include <ucontext.h>
//adjust flags and more
void adjust_arch(dynablock_t* db, x64emu_t* emu, ucontext_t* p, uintptr_t x64pc);
#else
// _WIN32 has no signal-context fault reconstruction — no-op.
#define adjust_arch(db, emu, p, x64pc)
#endif
// get if instruction can be regenerated for unaligned access
int arch_unaligned(dynablock_t* db, uintptr_t x64pc);
#endif // __DYNAREC_ARM_ARCH_H__
