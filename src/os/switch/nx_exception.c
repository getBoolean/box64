// box64-nx — Horizon userspace CPU-exception handler (M2.2c2): async guest-signal delivery.
//
// A real bad guest dereference / bad jump / self-modifying-code write faults as an ARM64 CPU exception
// INSIDE dynarec-generated code. Horizon delivers such exceptions to a per-process userspace entry;
// our STRONG __libnx_exception_entry (nx_exception_entry.S) replaces libnx's single-global-dump/-stack
// entry with a per-fault {dump, stack} slot pool (M2.6 — concurrent faults from 32 guest threads no
// longer corrupt each other), then hands the slot's dump to this C handler on the slot's stack.
// NOTE: only real hardware delivers here — Ryujinx uses its own InvalidAccessHandler and never calls us.
//
// We reconstruct a Linux-aarch64 ucontext from the ThreadExceptionDump, classify the fault into an x86
// signal, and hand it to box64's existing SYNCHRONOUS delivery core (my_sigactionhandler_oldcode) — the
// same one the emit_signal_switch.c emitters use, but with a NON-NULL ucontext. The core lifts the guest
// regs (copyUCTXreg2Emu), runs the guest handler (RunFunctionHandler -> DynaCall), and resumes the guest
// via siglongjmp(emu->jmpbuf) — the SAME jmpbuf armed by EmuRun on the faulting thread's own stack. We
// therefore NEVER return here on successful delivery (returning -> libnx -> svcBreak -> crash report,
// which is what we want ONLY for an unhandled / SIG_DFL fault).
//
// STAGE 1 (this file, for now): genuine SIGSEGV/SIGBUS/SIGILL delivery to a guest handler + siglongjmp
// resume — the c2 gate (signals.c bad-deref -> handler recovers). The SMC-write, unaligned-fixup, and
// callret paths (which additionally need a real page-protect backend and a native restore-and-branch
// trampoline) are layered in later stages; here they fall through to classification-as-SIGSEGV/BUS/ILL.
#ifdef __SWITCH__

#include <switch.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ucontext.h>   // shim: Linux-aarch64 sigcontext/ucontext_t + fpsimd_context / FPSIMD_MAGIC

#include "x64_signals.h"
#include "box64context.h"
#include "box64cpu.h"
#include "x64emu.h"
#include "emu/x64emu_private.h"
#include "custommem.h"
#include "signals.h"     // my_sigactionhandler_oldcode proto + x64_siginfo_t (via the shim)
#include "sigtools.h"
#include "nx_jit.h"
#include "nx_resume.h"   // Stage 4: register-restore-and-branch trampoline for mid-block in-place resume
#ifdef DYNAREC
#include "dynablock.h"
#include "dynarec/dynablock_private.h"
#include "dynarec_native.h"
#include "emu/x64run_private.h"      // rex_t — dynarec_arch.h's arm64 functions header depends on it
#include "dynarec/dynarec_arch.h"    // ARCH_ADJUST (adjust_arch) for the SMC re-run path
#endif

extern void nx_result_log(const char*);   // nx_main.c: heap-free SD result line — the ONLY HW-visible channel
// The delivery core/wrapper are defined in nx_signals.c; signals.h doesn't prototype them (nx_signals.c
// declares them locally too), so mirror that declaration here.
void my_sigactionhandler_oldcode(x64emu_t* emu, int32_t sig, int simple, x64_siginfo_t* info, void* ucntx, int* old_code, void* cur_db, uintptr_t x64pc);

// x86-64 si_code values the guest expects (newlib's may differ — pin them like nx_signals.c does).
#define X64_SEGV_MAPERR  1
#define X64_SEGV_ACCERR  2
#define X64_BUS_ADRALN   1
#define X64_ILL_ILLOPC   1

// ---- M2.6 per-fault {dump, stack} slot pool -----------------------------------------------------
// nx_exception_entry.S (our STRONG __libnx_exception_entry — with it linked, libnx exception.o and
// its single global __nx_exceptiondump/__nx_exception_stack drop out of the link entirely) claims one
// slot per in-flight fault, so 32 threads can take SMC faults simultaneously (stress -DSTRESS_SMC).
// Storage is non-static so the .S reaches it PC-relative. kx_exc_single = the KX_EXC_SINGLE legacy
// A/B gate (nx_main.c sets it from box64.env): slot 0 unconditionally, no claim/release bookkeeping.
#include "nx_exc_pool.h"
uint32_t kx_exc_single = 0;
// Bumped by the delivery core (nx_signals.c) whenever the guest handler CHANGES the context (a
// recovery/progress: syscall-status recovery, KiUserExceptionDispatcher, or a longjmp). The same-fault
// loop guard resets on it, so a finite guest loop of recovered syscall-boundary faults isn't mistaken
// for a stuck box64 delivery. Per-thread (the guard is per-thread).
__thread uint32_t kx_recov_seq = 0;
uint32_t kx_exc_owner[KX_EXC_NSLOTS];                 // 0=free, 1=claimed (entry asm ldaxr/stlxr)
typedef struct { ThreadExceptionDump d; } __attribute__((aligned(16))) kx_exc_dump_t;
_Static_assert(sizeof(kx_exc_dump_t) == KX_EXC_DUMPSZ, "KX_EXC_DUMPSZ != sizeof(ThreadExceptionDump) rounded to 16");
kx_exc_dump_t kx_exc_dumps[KX_EXC_NSLOTS];
__attribute__((aligned(16))) uint8_t kx_exc_stacks[KX_EXC_NSLOTS][KX_EXC_STKSZ];

// Slot-release invariant (NEVER add a release before a siglongjmp: the longjmp tail still executes on
// the slot's stack, and a concurrent claimant would write handler frames over the live frames). A
// thread's claimed slots form a per-thread chain (nesting: a guest signal handler run by DynaCall ON
// a slot stack can itself fault). Releases happen ONLY at three sites:
//   1. handler entry (the SP-chain prune below): slots ABOVE the deepest chain stack the interrupted
//      SP still lives on are provably abandoned (the only exits from a slot stack are siglongjmp —
//      which abandons everything above the jmpbuf's frame — or nx_resume_native, which pops itself).
//      NB a nested fault's siglongjmp can land in a DynaCall setjmp frame on a PARENT slot stack, so
//      the prune must scan the whole chain for the SP, not just the top.
//   2. the nx_resume.S tail (rc.release): a single stlr AFTER the last ctx read, right before `br`.
//   3. nx_exc_thread_exit() (nx_posix.c clone trampoline): the exiting thread is off every slot stack.
// A missed release only leaks a slot -> worst case pool exhaustion -> 0xf801 -> creport, never a hang.
static __thread uint8_t exc_chain[KX_EXC_MAXDEPTH];
static __thread int     exc_depth = 0;

static int nx_exc_slot_of(ThreadExceptionDump* ctx) {
    uintptr_t off = (uintptr_t)ctx - (uintptr_t)&kx_exc_dumps[0].d;
    if (off % KX_EXC_DUMPSZ) return -1;
    uintptr_t idx = off / KX_EXC_DUMPSZ;
    return (idx < KX_EXC_NSLOTS) ? (int)idx : -1;
}
static int nx_exc_sp_in_slot(uintptr_t sp, int idx) {
    uintptr_t base = (uintptr_t)kx_exc_stacks[idx];
    return sp > base && sp <= base + KX_EXC_STKSZ;    // top==base+STKSZ is this slot's empty stack
}
static void nx_exc_release(int idx) {
    __atomic_store_n(&kx_exc_owner[idx], 0, __ATOMIC_RELEASE);
}
// Called from nx_clone_trampoline after the guest thread's fn returns: off every slot stack by then.
void nx_exc_thread_exit(void) {
    if (kx_exc_single) return;
    for (int i = 0; i < exc_depth; ++i) nx_exc_release(exc_chain[i]);
    exc_depth = 0;
}
// Release site 2 setup: pop this fault's slot (the chain top — the entry prune pushed it) and hand
// its owner-word address to the nx_resume.S tail, which stlr's it AFTER its last ctx read. 0 = none.
static uint64_t nx_exc_pop_release(void) {
    if (kx_exc_single || exc_depth <= 0) return 0;
    int idx = exc_chain[--exc_depth];
    return (uint64_t)(uintptr_t)&kx_exc_owner[idx];
}

// Per-fault SD-log throttle: every rlog line commits the SD filesystem — 6400 concurrent stress
// faults would grind through fsdev and serialize the run. Full detail for the first 8 faults and
// every 1024th after; KX_EXC_LOG=1 restores full logging. The UNHANDLED tail always logs.
static uint32_t g_exc_total = 0;   // __atomic_fetch_add'd at handler entry
static int nx_exc_log_all(void) {
    static int e = -1;
    if (e < 0) e = getenv("KX_EXC_LOG") ? 1 : 0;
    return e;
}

// ---- KX_DIAG-CASC (temporary): nested-fault CASCADE ring buffer -----------------------------------
// The om/exception crash is an intermittent NESTED-FAULT CASCADE: a 2nd CPU fault taken WHILE box64 is
// mid-delivery of a 1st fault, i.e. while the handler runs ON a slot stack. We need to see WHERE each
// nested level re-faults (native PC + is-SP-on-a-slot-stack + chain depth) — but per-fault rlog commits
// the SD filesystem and PERTURBS the timing (the Heisenbug: a no-log run trips the depth cap at ~fault
// 8, a KX_EXC_LOG run reaches ~50 then corrupts). So capture EVERY fault into a per-thread in-memory
// ring (a cheap struct store, NO I/O) and flush it to box64-result.txt ONLY at a give-up/crash tail.
// Native TLS (__thread / TPIDR_EL0) IS valid in the Horizon exception context (exc_chain/exc_depth/uctx
// already rely on it) — only the pthread key layer (pthread_getspecific) is not. Symbolize each pc
// field offline against box64.elf (aarch64-none-elf-addr2line); expect the cascade levels to land in
// nx_jit_rx_to_rw / FindDynablockFromNativeAddress (the unlocked dynablock/JIT walk).
void __libnx_exception_handler(ThreadExceptionDump* ctx);   // fwd decl (for &anchor below; defined later)
#define NX_CASC_N 32
struct nx_casc_rec { uint32_t nfault; int dpre, dpost, slot, spslot;
                     uint64_t sp, pc, far, lr, x64pc; };
static __thread struct nx_casc_rec g_casc[NX_CASC_N];
static __thread uint32_t g_casc_w = 0;   // monotonic write count (index = w % NX_CASC_N)
// Which slot-pool stack (if any) the interrupted SP lives on. >=0 => the fault interrupted box64's own
// handler/delivery code running on a slot stack (a nested fault); <0 => the guest/JIT stack (a 1st-level
// fault, the common case). Pure arithmetic over the contiguous kx_exc_stacks[][] — deref-free.
static int nx_exc_sp_slot(uintptr_t sp) {
    uintptr_t base = (uintptr_t)&kx_exc_stacks[0][0];
    uintptr_t end  = base + (uintptr_t)KX_EXC_NSLOTS * KX_EXC_STKSZ;
    if (sp <= base || sp > end) return -1;
    return (int)((sp - 1 - base) / KX_EXC_STKSZ);
}
static void nx_casc_push(uint32_t nfault, int dpre, int dpost, int slot, int spslot, ThreadExceptionDump* ctx) {
    struct nx_casc_rec* r = &g_casc[g_casc_w % NX_CASC_N];
    r->nfault = nfault; r->dpre = dpre; r->dpost = dpost; r->slot = slot; r->spslot = spslot;
    r->sp = ctx->sp.x; r->pc = ctx->pc.x; r->far = ctx->far.x; r->lr = ctx->lr.x;
    r->x64pc = ctx->cpu_gprs[27].x;
    g_casc_w++;
}
// Flush this thread's ring newest-first at a give-up/crash site (one-time, so the fsdev commits are fine).
static void nx_casc_flush(const char* why) {
    if (!g_casc_w) return;
    { char b[112]; int n = snprintf(b, sizeof b, "nx_casc: FLUSH %s total=%u anchor=%p",
        why, g_casc_w, (void*)&__libnx_exception_handler); if (n > 0) nx_result_log(b); }
    uint32_t n = g_casc_w < NX_CASC_N ? g_casc_w : NX_CASC_N;
    for (uint32_t k = 0; k < n; ++k) {
        struct nx_casc_rec* r = &g_casc[(g_casc_w - 1 - k) % NX_CASC_N];   // newest first
        char b[208];
        int m = snprintf(b, sizeof b,
            "nx_casc[%u]: #%u dpre=%d dpost=%d slot=%d spslot=%d sp=0x%llx pc=0x%llx far=0x%llx lr=0x%llx x64pc=0x%llx",
            k, r->nfault, r->dpre, r->dpost, r->slot, r->spslot, (unsigned long long)r->sp,
            (unsigned long long)r->pc, (unsigned long long)r->far, (unsigned long long)r->lr,
            (unsigned long long)r->x64pc);
        if (m > 0) nx_result_log(b);
    }
}

// Unhandled-fault tail (+-exit guarantee): both give-up paths route here before returning to the
// trampoline (-> svcBreak -> creport -> the am error dialog, A drops to HOME). When the fault PC is
// in guest/JIT code (rw!=rx or a dynablock matched) the faulting thread cannot hold box64's console/
// stdio locks, so on the MAIN thread it's safe to run the + hold first — the on-screen state stays
// readable before the creport wipes it. nx_wait_for_exit_button self-gates (KX_WAIT_EXIT +
// detectMesosphere + main thread only + once), so on a secondary thread / without the env it's a
// no-op and we go straight to the crash report. A main-thread fault inside box64 C code skips the
// hold (it may hold the very locks consoleUpdate needs — the dialog is still a user-driven exit).
static void nx_exc_unhandled_tail(ThreadExceptionDump* ctx, void* cur_db, void* rx, void* rw,
                                  int sig, int si_code, uintptr_t x64pc) {
    {
        char b[160];
        int n = snprintf(b, sizeof b,
            "nx_exc: UNHANDLED sig=%d code=%d addr=0x%llx db=%p x64pc=0x%llx -> crash report",
            sig, si_code, (unsigned long long)ctx->far.x, cur_db, (unsigned long long)x64pc);
        if (n > 0) nx_result_log(b);
    }
    nx_casc_flush("unhandled");   // KX_DIAG-CASC: dump the nested-fault history behind this crash
    if (rw != rx || cur_db) {
        extern void nx_wait_for_exit_button(void);
        nx_wait_for_exit_button();
    }
}

// box64 arm64 register map (see CLAUDE.md crash-triage): cpu_gprs[0]=xEmu (emu ptr), [10..25]=RAX..R15,
// [26]=xFlags, [27]=guest RIP (block-start). cpu_gprs[0..28] map 1:1 onto the Linux sigcontext regs[0..28].
void __libnx_exception_handler(ThreadExceptionDump* ctx)
{
    // Log throttle (see nx_exc_log_all above): verbose for the first 8 faults + every 1024th after.
    uint32_t nfault = __atomic_fetch_add(&g_exc_total, 1, __ATOMIC_RELAXED);
    int verbose = nx_exc_log_all() || nfault < 8 || (nfault & 1023) == 0;

    // Result-file breadcrumb FIRST (the only HW-visible channel) so even a crash mid-handler leaves a trace.
    if (verbose) {
        char b[192];
        int n = snprintf(b, sizeof b,
            "nx_exc: #%u desc=0x%x esr=0x%x far=0x%llx pc=0x%llx pstate=0x%x gRIP(x27)=0x%llx xFlags(x26)=0x%llx",
            nfault, ctx->error_desc, ctx->esr, (unsigned long long)ctx->far.x, (unsigned long long)ctx->pc.x,
            ctx->pstate, (unsigned long long)ctx->cpu_gprs[27].x, (unsigned long long)ctx->cpu_gprs[26].x);
        if (n > 0) nx_result_log(b);
    }

    // SP-chain prune (release site 1 — see the invariant at the pool definition): every chain slot
    // ABOVE the deepest slot stack the interrupted SP still lives on is provably abandoned. SP on the
    // guest/host stack (the common, non-nested case) -> the whole chain is abandoned. Then push this
    // fault's slot. Depth overflow (8 nested faults = pathological) -> give up to the crash report;
    // the current slot stays claimed, which is fine — we're dying.
    if (!kx_exc_single) {
        int slot = nx_exc_slot_of(ctx);
        if (slot >= 0) {
            int dpre   = exc_depth;                       // KX_DIAG-CASC: chain depth BEFORE the prune
            int spslot = nx_exc_sp_slot(ctx->sp.x);       // KX_DIAG-CASC: SP on a slot stack? (>=0 => nested)
            int keep = 0;
            for (int i = exc_depth - 1; i >= 0; --i)
                if (nx_exc_sp_in_slot(ctx->sp.x, exc_chain[i])) { keep = i + 1; break; }
            for (int i = keep; i < exc_depth; ++i) nx_exc_release(exc_chain[i]);
            exc_depth = keep;
            nx_casc_push(nfault, dpre, exc_depth, slot, spslot, ctx);   // dpost = post-prune (pre-push)
            if (exc_depth >= KX_EXC_MAXDEPTH) {
                nx_result_log("nx_exc: nested-fault depth cap hit — giving up to crash report");
                nx_casc_flush("depthcap");
                return;
            }
            exc_chain[exc_depth++] = (uint8_t)slot;
        }
        // KX_DIAG-S (temporary): log the claimed slot + post-prune depth. Monotonic slot with a
        // growing/stuck depth => the syscall-recovery siglongjmp leaks a slot per fault (pool exhausts
        // at NSLOTS => the ~fault-48 corruption). Cycling slot + depth==1 => no leak.
        if (verbose) { char b[80];
            int n = snprintf(b, sizeof b, "nx_slot: idx=%d depth=%d sp=0x%llx",
                slot, exc_depth, (unsigned long long)ctx->sp.x);
            if (n > 0) nx_result_log(b); }
    }

    // KX_EXC_MAX storm guard (default OFF — stress legitimately takes 6400 faults, Wine SMC loads
    // millions; this is a soak/debug knob, not a limiter): total faults past the cap -> crash report.
    {
        static int cap = -1;
        if (cap < 0) { const char* s = getenv("KX_EXC_MAX"); cap = s ? atoi(s) : 0; }
        if (cap > 0 && nfault >= (uint32_t)cap) {
            nx_result_log("nx_exc: KX_EXC_MAX fault cap exceeded — giving up to crash report");
            nx_casc_flush("kxexcmax");
            return;
        }
    }

    // KX_DIAG-A (temporary, DEREF-FREE): box64 .text anchor (symbolize the host fault PC of a nested crash)
    // + the live xEmu register (cpu_gprs[0]). Emitted BEFORE any structure walk (thread_get_emu / dynablock
    // lookup) so it survives even if THOSE nest-crash. Only channel that survives a 2nd fault.
    if (verbose) {
        char b[192];
        int n = snprintf(b, sizeof b,
            "nx_exc2a: anchor=%p rx=0x%llx far=0x%llx x0=0x%llx lr(x30)=0x%llx sp=0x%llx fp(x29)=0x%llx",
            (void*)&__libnx_exception_handler, (unsigned long long)ctx->pc.x,
            (unsigned long long)ctx->far.x, (unsigned long long)ctx->cpu_gprs[0].x,
            (unsigned long long)ctx->lr.x, (unsigned long long)ctx->sp.x, (unsigned long long)ctx->fp.x);
        if (n > 0) nx_result_log(b);
        n = snprintf(b, sizeof b, "nx_exc2a: x1..x9=%llx %llx %llx %llx %llx %llx %llx %llx %llx",
            (unsigned long long)ctx->cpu_gprs[1].x, (unsigned long long)ctx->cpu_gprs[2].x,
            (unsigned long long)ctx->cpu_gprs[3].x, (unsigned long long)ctx->cpu_gprs[4].x,
            (unsigned long long)ctx->cpu_gprs[5].x, (unsigned long long)ctx->cpu_gprs[6].x,
            (unsigned long long)ctx->cpu_gprs[7].x, (unsigned long long)ctx->cpu_gprs[8].x,
            (unsigned long long)ctx->cpu_gprs[9].x);
        if (n > 0) nx_result_log(b);
        // x10..x25 = guest RAX,RCX,RDX,RBX,RSP,RBP,RSI,RDI,R8..R15 (box64 arm64 map). x28 scratch.
        n = snprintf(b, sizeof b, "nx_exc2a: gRAX=%llx gRSP(x14)=%llx gRBP(x15)=%llx gRDI(x17)=%llx x28=%llx",
            (unsigned long long)ctx->cpu_gprs[10].x, (unsigned long long)ctx->cpu_gprs[14].x,
            (unsigned long long)ctx->cpu_gprs[15].x, (unsigned long long)ctx->cpu_gprs[17].x,
            (unsigned long long)ctx->cpu_gprs[28].x);
        if (n > 0) nx_result_log(b);
    }

    // Recover the faulting thread's emu. In the Horizon exception context pthread TLS is NOT valid
    // (pthread_getspecific -> NULL), so plain thread_get_emu()'s "this should not happen" CREATE path runs
    // and NEST-CRASHES (NewX64Emu/setProtection_stack -> rb_set_64 on a NULL tree, far=0x0). NEVER create
    // here: prefer the live xEmu register (x0 == cpu_gprs[0]), which box64 keeps as emu throughout dynarec,
    // and fall back to the per-thread key WITHOUT creating. If neither yields a valid emu (e.g. x0 was
    // clobbered — a corrupt xEmu is itself the bug we're diagnosing) emu stays NULL: we then still compute
    // the precise faulting RIP and log a clean UNHANDLED diagnostic instead of a second fault.
    x64emu_t* emu = (x64emu_t*)ctx->cpu_gprs[0].x;
    if ((uintptr_t)emu < 0x10000 || ((uintptr_t)emu & 7))   // 0x190 etc. are not valid emu pointers
        emu = thread_get_emu_no_create();

    // 1) Synthesize a Linux-aarch64 ucontext (shim layout) from the dump. Thread-local, and since M2.6
    //    each concurrent fault also runs on its OWN pool slot's dump+stack (nx_exception_entry.S), so
    //    32-way concurrent faults no longer clobber each other.
    static __thread ucontext_t uctx;
    memset(&uctx, 0, sizeof(uctx));
    for (int i = 0; i < 29; ++i) uctx.uc_mcontext.regs[i] = ctx->cpu_gprs[i].x;  // x0..x28
    uctx.uc_mcontext.regs[29]     = ctx->fp.x;   // x29
    uctx.uc_mcontext.regs[30]     = ctx->lr.x;   // x30
    uctx.uc_mcontext.sp           = ctx->sp.x;
    uctx.uc_mcontext.pstate       = ctx->pstate;
    uctx.uc_mcontext.fault_address = ctx->far.x;
    // Build one FPSIMD_MAGIC record in __reserved[] so adjust_arch / sigbus_specialcases can read guest SIMD.
    {
        struct fpsimd_context* fp = (struct fpsimd_context*)uctx.uc_mcontext.__reserved;
        fp->head.magic = FPSIMD_MAGIC;
        fp->head.size  = sizeof(struct fpsimd_context);
        // (ThreadExceptionDump carries no fpsr/fpcr — only the register file; fpsr/fpcr stay 0, which is
        //  fine: adjust_arch reads only fpsimd->vregs[], not the status/control words.)
        for (int i = 0; i < 32; ++i) fp->vregs[i] = ctx->fpu_gprs[i].v;
        struct _aarch64_ctx* term = (struct _aarch64_ctx*)((uintptr_t)fp + sizeof(*fp));
        term->magic = 0; term->size = 0;   // null terminator ends the __reserved record list
    }

    // 2) rx->rw translate the faulting native PC, then locate the dynablock + precise guest RIP.
    void* rx = (void*)ctx->pc.x;
    void* rw = nx_jit_rx_to_rw(rx);
    if (!rw) rw = rx;                            // fault outside JIT (box64 helper / guest data) — keep as-is
    uctx.uc_mcontext.pc = (uintptr_t)rw;         // CONTEXT_PC(p) feeds adjustregs + logging
    uintptr_t x64pc = ctx->cpu_gprs[27].x;       // fallback: block-start guest RIP (x27)
    void* cur_db = NULL;
#ifdef DYNAREC
    // Walk box64's GLOBAL dynablock rbtree when we have an emu to deliver to. Prefer to hold
    // mutex_dyndump (the lock every rbt_dynmem mutation — AllocDynarecMap/FreeDynarecMap via
    // FillBlock/CancelBlock64 — takes): a locked walk can't race a concurrent rebalance into a NULL
    // node (the far=0x20 nest-crash class). But a SINGLE non-blocking trylock only: a blocking lock
    // risks self-deadlock+wedge (a box64 bug faulting inside a mutex_dyndump section would never
    // release it), which would break the +-exit guarantee, and a long retry loop starves the SMC
    // path under 32-way churn. On trylock failure we MUST still populate cur_db — an SMC write fault
    // whose block we can't find becomes a fatal unhandled SIGSEGV — so degrade to the UNLOCKED walk
    // (box64's long-standing behavior for emu!=NULL; the executing block is pinned by its in_used
    // refcount and invalidation frees are zombie-deferred, so the race is narrow and non-fatal).
    if (emu && my_context) {
        int locked = (mutex_trylock(&my_context->mutex_dyndump) == 0);
        dynablock_t* db = FindDynablockFromNativeAddress(rw);
        if (db) {
            cur_db = db;
            uintptr_t gx = getX64Address(db, (uintptr_t)rw);
            if (gx) x64pc = gx;                  // precise faulting-instruction RIP
        }
        if (locked) mutex_unlock(&my_context->mutex_dyndump);
    }
#endif

    // KX_DIAG-B (temporary): the PRECISE guest RIP (getX64Address) + rw + db. If DIAG-A logged but DIAG-B
    // does not, the nest-crash is in the FindDynablock/getX64Address lookup (lines above).
    if (verbose) {
        char b[160];
        int n = snprintf(b, sizeof b, "nx_exc2b: x64pc=0x%llx rw=%p db=%p",
            (unsigned long long)x64pc, rw, cur_db);
        if (n > 0) nx_result_log(b);
    }
    // KX_DIAG-INSN (temporary): dump the guest instruction bytes at the faulting RIP so a repeating
    // fault (e.g. the om.c:149 write loop at a non-ntdll module) can be decoded — read vs SSE store,
    // which base register. getProtection-guarded so a bad x64pc doesn't nest-fault.
    if (verbose && getProtection((uintptr_t)x64pc)) {
        const uint8_t* ib = (const uint8_t*)x64pc;
        char b[128];
        int n = snprintf(b, sizeof b,
            "nx_insn: rip=0x%llx b=%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
            (unsigned long long)x64pc, ib[0],ib[1],ib[2],ib[3],ib[4],ib[5],ib[6],ib[7],ib[8],ib[9],ib[10],ib[11]);
        if (n > 0) nx_result_log(b);
    }

    // 3) Classify the ARM64 exception into an x86 signal + siginfo.
    //    ESR: EC = esr>>26, DFSC = esr&0x3f, WnR = (esr>>6)&1.
    uint32_t esr  = ctx->esr;
    uint32_t ec   = esr >> 26;
    uint32_t dfsc = esr & 0x3f;
    int sig, si_code;
    int is_unaligned = 0;   // Stage 4: data-abort alignment fault -> try box64's in-place unaligned fixup
    switch (ctx->error_desc) {
        case ThreadExceptionDesc_MisalignedPC:
        case ThreadExceptionDesc_MisalignedSP:
            sig = X64_SIGBUS;  si_code = X64_BUS_ADRALN;  break;
        case ThreadExceptionDesc_InstructionAbort:
            sig = X64_SIGSEGV; si_code = X64_SEGV_MAPERR; break;  // bad jump / non-executable target
        default:   // ThreadExceptionDesc_Other (0x101): data abort, undef instruction, alignment, ...
            if (ec == 0x22) {                 // EC=0b100010 PC alignment fault
                sig = X64_SIGBUS;  si_code = X64_BUS_ADRALN;
            } else if (ec == 0) {             // EC=0 undefined instruction
                sig = X64_SIGILL;  si_code = X64_ILL_ILLOPC;
            } else if ((ec == 0x24 || ec == 0x25) && dfsc == 0x21) {
                // DFSC 0b100001 = alignment fault on a data access: box64's dynarec emitted an
                // alignment-requiring ARM64 op (unaligned atomic LDAXR/STLXR, some vector ld/st) on an
                // unaligned x86 address. Classify as SIGBUS but try the in-place fixup first (below).
                sig = X64_SIGBUS; si_code = X64_BUS_ADRALN; is_unaligned = 1;
            } else {                          // EC 0x24/0x25 data abort (the common bad-deref)
                sig = X64_SIGSEGV;
                // DFSC 0b0011xx (0x0C..0x0F) = permission fault -> ACCERR; translation/etc -> MAPERR.
                si_code = ((dfsc & 0x3c) == 0x0c) ? X64_SEGV_ACCERR : X64_SEGV_MAPERR;
            }
            break;
    }

    x64_siginfo_t info;
    memset(&info, 0, sizeof(info));
    info.si_signo = sig;
    info.si_code  = si_code;
    info.si_addr  = (void*)ctx->far.x;

    // KX_DIAG (temporary): log the PRECISE guest RIP (getX64Address) + a box64 .text anchor (to symbolize
    // the nested-handler fault PC) + emu/db + the (process-GLOBAL) guest handler for this signal, BEFORE
    // the delivery path (which nest-crashes on real HW). This is the only channel that survives a 2nd fault.
    if (verbose) {
        char b[192];
        uintptr_t hh = my_context ? (uintptr_t)my_context->signals[sig] : 0;
        int n = snprintf(b, sizeof b,
            "nx_exc2: anchor=%p x64pc=0x%llx emu=%p db=%p sig=%d h=0x%llx rw=%p",
            (void*)&__libnx_exception_handler, (unsigned long long)x64pc,
            (void*)emu, cur_db, sig, (unsigned long long)hh, rw);
        if (n > 0) nx_result_log(b);
    }
    // KX_DIAG-C (temporary, DEREF-FREE): the guest TLS bases (%fs=TEB / %gs) + guest pid. If Wine's
    // dispatcher re-faults reading NtCurrentTeb()->ExceptionList, a WRONG fs/gs base is the smoking gun
    // (box64 delivered the fault with the wrong thread's TEB). segs_offs is plain emu state, no deref.
    if (verbose && emu) {
        extern int nx_guest_pid(void);
        char b[160];
        int n = snprintf(b, sizeof b, "nx_exc2c: fsbase=0x%llx gsbase=0x%llx pid=%d",
            (unsigned long long)emu->segs_offs[_FS], (unsigned long long)emu->segs_offs[_GS],
            nx_guest_pid());
        if (n > 0) nx_result_log(b);
    }

    // Defensive loop guard: if a fault recurs with NO forward progress, delivery/resume is broken —
    // bail to a crash report instead of hanging forever (a hung HOME-launched title needs a reboot).
    // (far, guest RIP) ALONE is not enough: a tight self-modifying-code loop (stress -DSTRESS_SMC:
    // one page rewritten at one store site 200x) legitimately re-faults at an IDENTICAL (far, rip)
    // every iteration — that is progress, not a stuck loop. The discriminator is whether the guest's
    // store LANDS: read the word at the fault address (a WnR data-abort target is a mapped, at-least-R
    // page, so this can't nest-fault) — a legit SMC loop advances that value each iteration, a truly
    // stuck loop (store never lands / resume re-enters the same state) leaves it frozen. Only count a
    // repeat when (far, rip, value) are ALL unchanged; any change resets. A program catching many
    // DIFFERENT faults also resets.
    {
        static __thread uintptr_t last_far = ~0ULL, last_rip = ~0ULL;
        static __thread uint32_t  last_val = 0;
        static __thread uint32_t  last_seq = 0;
        static __thread int repeat = 0;
        uint32_t cur_val = 0;
        if (((esr >> 6) & 1) /*WnR*/ && getProtection(ctx->far.x))
            cur_val = *(volatile uint32_t*)ctx->far.x;   // store target — mapped, safe to read
        // Count a repeat ONLY when the same (far,rip,value) recurs AND the guest handler did NOT recover
        // anything since the last such fault (kx_recov_seq unchanged). If a recovery happened
        // (kx_recov_seq advanced), the guest is progressing — a finite loop of recovered syscall-boundary
        // bad-pointer faults (e.g. om.c:149's NtCreateNamedPipeFile) re-faults at one identical (far,rip)
        // but each returns STATUS_ACCESS_VIOLATION and the test advances. Only a genuine no-recovery
        // re-fault (chg=0, box64 re-running the same insn / delivery broken) trips the guard.
        if (ctx->far.x == last_far && x64pc == last_rip && cur_val == last_val && kx_recov_seq == last_seq) {
            if (++repeat >= 16) {
                nx_result_log("nx_exc: same fault repeated 16x with no progress — giving up");
                nx_exc_unhandled_tail(ctx, cur_db, rx, rw, sig, si_code, x64pc);
                return;
            }
        } else { last_far = ctx->far.x; last_rip = x64pc; last_val = cur_val; last_seq = kx_recov_seq; repeat = 0; }
    }

#ifdef DYNAREC
    // 3a) SMC (self-modifying code): a guest WRITE (ESR.WnR=1) to a page box64 write-protected as translated
    //     code (PROT_DYNAREC — protectDB now applies a real svcSetMemoryPermission R on Switch). Restore
    //     write on the page + mark its overlapping dynablocks dirty (unprotectDB), reconstruct guest state at
    //     the faulting store (copyUCTXreg2Emu/adjustregs/ARCH_ADJUST — the same lift the delivery core uses),
    //     then siglongjmp(2): EmuRun re-runs the store in the interpreter against the now-writable page and
    //     regenerates any modified block on next entry. Runs BEFORE guest SIGSEGV delivery — an SMC write is
    //     box64-internal, never a guest signal. Mirrors box64's autosmc path (signals.c:954).
    if (sig == X64_SIGSEGV && ((esr >> 6) & 1) /*WnR*/ && cur_db && emu && emu->jmpbuf
        && (getProtection(ctx->far.x) & PROT_DYNAREC)) {
        dynablock_t* db = (dynablock_t*)cur_db;
        unprotectDB(ctx->far.x, 1, 1);                 // page -> real Rw + mark overlapping blocks dirty
        { static int logged = 0; if (!logged) { logged = 1; nx_result_log("nx_exc: SMC write -> unprotect + re-run (Stage 3)"); } }
        copyUCTXreg2Emu(emu, &uctx, x64pc);            // lift host regs -> emu, set R_RIP = faulting store
        adjustregs(emu, rw);                           // rewind any partial x86-instruction effect
        if (db->arch_size) ARCH_ADJUST(db, emu, &uctx, x64pc);   // reconstruct flags/x87/SSE at the fault
        dynablock_leave_runtime(db);
        cancel_deferred_signal_processing(emu);
        siglongjmp(emu->jmpbuf, 2);                    // re-run the store in interp, then resume; NEVER returns
    }
#endif

#ifdef DYNAREC
    // 3b) Stage 4: unaligned data access that the dynarec lowered to an alignment-faulting ARM64 op
    //     (unaligned atomic LDAXR/STLXR, some vector ld/st). box64 emulates the access byte-wise IN
    //     PLACE and resumes at the NEXT native instruction — the mid-block resume Horizon can only do
    //     via the register-restore trampoline (no kernel sigreturn; siglongjmp can't land mid-block).
    //     This runs BEFORE guest-signal delivery: an unaligned access box64 can fix is transparent to
    //     the guest, not a SIGBUS it should see. If sigbus_specialcases can't recognize the op it
    //     returns 0 and we fall through to real SIGBUS delivery / crash (correct terminate semantics).
    if (is_unaligned && emu) {
        struct fpsimd_context* fpsimd = (struct fpsimd_context*)uctx.uc_mcontext.__reserved;
        // Point sigbus at the rx (executable) alias: it reads the faulting opcode from `pc` and does
        // uc_mcontext.pc += 4, so the resume target becomes rx+4 (rw is non-executable under W^X).
        uctx.uc_mcontext.pc = ctx->pc.x;
        if (sigbus_specialcases(NULL, &uctx, (void*)ctx->pc.x, fpsimd, cur_db, x64pc,
                                emu->segs[_CS] == 0x23)) {
            static int logged = 0;
            if (!logged) { logged = 1; nx_result_log("nx_exc: unaligned access fixed in place (Stage 4)"); }
            nx_resume_ctx_t rc;
            for (int i = 0; i < 31; ++i) rc.x[i] = uctx.uc_mcontext.regs[i];
            rc.sp   = uctx.uc_mcontext.sp;
            rc.pc   = uctx.uc_mcontext.pc;              // rx + 4 (executable resume target)
            rc.nzcv = uctx.uc_mcontext.pstate;
            for (int i = 0; i < 32; ++i) rc.v[i] = fpsimd->vregs[i];
            rc.release = nx_exc_pop_release();          // slot freed by the .S tail after its last ctx read
            nx_resume_native(&rc);                      // reloads full state, branches to rx+4; NEVER returns
        }
    }
#endif

#ifdef DYNAREC
    // 3c) CALLRET (BOX64_DYNAREC_CALLRET>=2): each call-return / self-loop site carries a shadow slot that is
    //     a NOP while its block is clean and a UDF(#0xcafe) once the block is marked dirty. Hitting the UDF
    //     (undefined instruction -> ec==0 -> SIGILL) means box64 must re-validate the block. CLEAN: reset the
    //     callret slots to NOP + re-arm the jump table, then resume at the NEXT native instruction (rx+4) via
    //     the trampoline (Horizon has no kernel sigreturn, and siglongjmp can't land mid-block). DIRTY: lift
    //     guest state + siglongjmp(3) to leave the stale block (regen at the current RIP). Mirrors
    //     signals.c:859-929 (#ifdef ARCH_NOP SIGILL branch); the native fault addr is `rw` (compare to
    //     db->block, the rw alias), the resume PC is ctx->pc.x (rx) + 4. Runs before generic SIGILL delivery;
    //     a genuine guest ud2 won't match a callret slot and falls through.
    if (sig == X64_SIGILL && cur_db && emu) {
        dynablock_t* db = (dynablock_t*)cur_db;
        if (db->callret_size) {
            int is_callret = 0, type_callret = 0;
            for (int i = 0; i < db->callret_size && !is_callret; ++i)
                if ((uintptr_t)rw == (uintptr_t)db->block + db->callrets[i].offs) {
                    is_callret = 1; type_callret = db->callrets[i].type;
                }
            if (is_callret) {
                // "ret" type (0): the relevant x64 addr is the return target held in xRIP (X[27]); "loop"
                // type (1) keeps getX64Address's x64pc. Used for the hotpage/hash validity check + state lift.
                uintptr_t cr_x64pc = type_callret ? x64pc : (uintptr_t)ctx->cpu_gprs[27].x;
                int is_hotpage = checkInHotPage(cr_x64pc);
                uint32_t hash = (db->gone || is_hotpage) ? 0 : X31_hash_code(db->x64_addr, db->x64_size);
                if (!db->gone && (!is_hotpage || db->autocrc) && hash == db->hash) {
                    // CLEAN: block still valid -> reset callret slots to NOP + re-arm the jump table, resume rx+4.
                    if (db->always_test) {
                        protectDB((uintptr_t)db->x64_addr, 1);
                    } else {
                        for (int i = 0; i < db->callret_size; ++i)
                            *(uint32_t*)(db->block + db->callrets[i].offs) = ARCH_NOP;   // db->block is the writable rw alias
                        ClearCache(db->block, db->size);
                        protectDBJumpTable((uintptr_t)db->x64_addr, db->x64_size, db->block, db->jmpnext);
                        for (int i = 0; i < db->sep_size; ++i) {
                            uint32_t x64_offs = db->sep[i].x64_offs;
                            uint32_t nat_offs = db->sep[i].nat_offs;
                            if (addJumpTableIfDefault64(db->x64_addr + x64_offs, db->always_test ? db->jmpnext : (db->block + nat_offs)))
                                db->sep[i].active = 1;
                            else
                                db->sep[i].active = 0;
                        }
                    }
                    { static int logged = 0; if (!logged) { logged = 1; nx_result_log("nx_exc: CALLRET clean -> reset + resume rx+4 (Stage D)"); } }
                    struct fpsimd_context* fpsimd = (struct fpsimd_context*)uctx.uc_mcontext.__reserved;
                    nx_resume_ctx_t rc;
                    for (int i = 0; i < 31; ++i) rc.x[i] = uctx.uc_mcontext.regs[i];
                    rc.sp   = uctx.uc_mcontext.sp;
                    rc.pc   = ctx->pc.x + 4;                     // rx + 4 (skip the UDF/NOP shadow slot)
                    rc.nzcv = uctx.uc_mcontext.pstate;
                    for (int i = 0; i < 32; ++i) rc.v[i] = fpsimd->vregs[i];
                    rc.release = nx_exc_pop_release();           // slot freed by the .S tail after its last ctx read
                    nx_resume_native(&rc);                       // reloads full state, branches to rx+4; NEVER returns
                } else if (emu->jmpbuf) {
                    // DIRTY (or in a HotPage): leave the stale block. Lift guest regs; a "loop" type also needs
                    // the partial-instruction rewind + flags/x87/SSE reconstruction ("ret" is just the epilog).
                    { static int logged = 0; if (!logged) { logged = 1; nx_result_log("nx_exc: CALLRET dirty -> siglongjmp(3) regen (Stage D)"); } }
                    copyUCTXreg2Emu(emu, &uctx, cr_x64pc);
                    if (type_callret) {
                        adjustregs(emu, rw);
                        if (db->arch_size) ARCH_ADJUST(db, emu, &uctx, cr_x64pc);
                    }
                    emu->test.clean = 0;
                    dynablock_leave_runtime(db);
                    cancel_deferred_signal_processing(emu);
                    siglongjmp(emu->jmpbuf, 3);                  // regen a dynablock at current RIP; NEVER returns
                }
            }
        }
    }
#endif

    // 4) Deliver to the guest handler if one is installed. The core runs the guest handler and then either
    //    exit()s (the handler siglongjmp'd out and the program ran to exit_group) or siglongjmp()s back
    //    into EmuRun to resume the guest — it NEVER returns here on success. SIG_DFL(0)/SIG_IGN(1) or no
    //    emu -> fall through to the crash report (correct terminate-on-unhandled-fault).
    uintptr_t h = my_context ? my_context->signals[sig] : 0;
    if (emu && h > 1) {
        static __thread int old_code = -1;
        old_code = -1;
        my_sigactionhandler_oldcode(emu, sig, 0, &info, &uctx, &old_code, cur_db, x64pc);
        // Reached only if the core RETURNED (handler fixed the fault and wants to retry the instruction).
        // Resume at the restored R_RIP via siglongjmp — must not return (that goes to libnx -> svcBreak).
        if (emu->jmpbuf)
            siglongjmp(emu->jmpbuf, 3);
    }

    // Unhandled / default action: breadcrumb (+ the main-thread + hold when safe), then return ->
    // __kx_exception_returnentry -> svcBreak -> Horizon crash report.
    nx_exc_unhandled_tail(ctx, cur_db, rx, rw, sig, si_code, x64pc);
}

#endif // __SWITCH__
