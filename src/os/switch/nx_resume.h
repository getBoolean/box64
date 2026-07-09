// box64-nx — native "restore registers and branch" trampoline (M2.2c2 Stage 4).
//
// Horizon has NO kernel sigreturn from a CPU exception: by the time libnx dispatches to
// __libnx_exception_handler, the kernel already consumed the live exception frame (phase-1
// svcReturnFromException) and RETURNING from the handler unconditionally svcBreak()s the process.
// The c2 gate resumes via siglongjmp(emu->jmpbuf) — but that only lands at the setjmp site inside
// EmuRun (block granularity). The Stage-4 in-place fixups (unaligned sigbus_specialcases, callret
// clean-block NOP-patch) must instead resume MID-BLOCK at native pc+4 with full register state, which
// siglongjmp cannot express. nx_resume_native() does exactly that: it reloads v0..v31, NZCV, SP, and
// x0..x30 from the (fixed-up) context and `br`s to ctx->pc, never returning.
//
// The branch is possible because box64's arm64 model (arm64_mapping.h) only ever allocates x0..x7
// (emu ptr + scratch) and x10..x28 (x86 state); x8/x9/x16/x17/x18 are OUTSIDE its register file and
// therefore dead at every emitted-block boundary. The trampoline uses x16 as the ctx base pointer and
// x17 as the final branch vehicle, discarding those two regs' (unused) "guest" values.
//
// The resume `pc` MUST be the rx (executable) alias (fault PC + 4), never the rw alias used for
// dynablock lookups — rw is non-executable under W^X.
#ifndef __NX_RESUME_H__
#define __NX_RESUME_H__

// Byte offsets into nx_resume_ctx_t, shared with nx_resume.S (which #includes this through cpp).
#define NX_RC_X     0x000   // x[0]..x[30]  (31 * 8 = 0xF8 bytes)
#define NX_RC_SP    0x0F8   // uint64_t sp
#define NX_RC_PC    0x100   // uint64_t pc   (rx alias + delta — the executable resume target)
#define NX_RC_NZCV  0x108   // uint64_t nzcv (pstate; only bits [31:28] applied via msr nzcv)
#define NX_RC_V     0x110   // __uint128_t v[32]  (16-byte aligned)

#ifndef __ASSEMBLER__

#include <stdint.h>
#include <stddef.h>

typedef struct nx_resume_ctx_s {
    uint64_t    x[31];      // x0..x30
    uint64_t    sp;
    uint64_t    pc;         // executable (rx) resume address
    uint64_t    nzcv;       // pstate; msr nzcv applies bits [31:28]
    __uint128_t v[32];      // v0..v31
} nx_resume_ctx_t;

_Static_assert(offsetof(nx_resume_ctx_t, x)    == NX_RC_X,    "nx_resume_ctx_t.x offset");
_Static_assert(offsetof(nx_resume_ctx_t, sp)   == NX_RC_SP,   "nx_resume_ctx_t.sp offset");
_Static_assert(offsetof(nx_resume_ctx_t, pc)   == NX_RC_PC,   "nx_resume_ctx_t.pc offset");
_Static_assert(offsetof(nx_resume_ctx_t, nzcv) == NX_RC_NZCV, "nx_resume_ctx_t.nzcv offset");
_Static_assert(offsetof(nx_resume_ctx_t, v)    == NX_RC_V,    "nx_resume_ctx_t.v offset");

// Restore the full guest machine state from *c and branch to c->pc. Never returns.
void nx_resume_native(const nx_resume_ctx_t* c) __attribute__((noreturn));

#endif // !__ASSEMBLER__
#endif // __NX_RESUME_H__
