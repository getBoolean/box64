// box64-nx — Horizon userspace CPU-exception handler (M2.2c2): async guest-signal delivery.
//
// A real bad guest dereference / bad jump / self-modifying-code write faults as an ARM64 CPU exception
// INSIDE dynarec-generated code. Horizon delivers such exceptions to a per-process userspace entry that
// libnx's crt0 dispatches to the weak __libnx_exception_handler. By DEFINING it (non-weak) + enlarging
// the exception stack + setting ignoredebug, we take over that path (instead of the kernel crash-report).
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

// Override libnx's weak exception scaffolding. Bigger stack than the 0x400 default: our fault path
// re-enters the dynarec to run the guest handler. ignoredebug=1 so the handler still runs when a
// debugger/gdbstub is attached (Ryujinx attaches one — though it never delivers user faults here anyway).
__attribute__((aligned(16))) u8 __nx_exception_stack[0x10000];
u64 __nx_exception_stack_size = sizeof(__nx_exception_stack);
u32 __nx_exception_ignoredebug = 1;

// box64 arm64 register map (see CLAUDE.md crash-triage): cpu_gprs[0]=xEmu (emu ptr), [10..25]=RAX..R15,
// [26]=xFlags, [27]=guest RIP (block-start). cpu_gprs[0..28] map 1:1 onto the Linux sigcontext regs[0..28].
void __libnx_exception_handler(ThreadExceptionDump* ctx)
{
    // Result-file breadcrumb FIRST (the only HW-visible channel) so even a crash mid-handler leaves a trace.
    {
        char b[192];
        int n = snprintf(b, sizeof b,
            "nx_exc: desc=0x%x esr=0x%x far=0x%llx pc=0x%llx pstate=0x%x gRIP(x27)=0x%llx xFlags(x26)=0x%llx",
            ctx->error_desc, ctx->esr, (unsigned long long)ctx->far.x, (unsigned long long)ctx->pc.x,
            ctx->pstate, (unsigned long long)ctx->cpu_gprs[27].x, (unsigned long long)ctx->cpu_gprs[26].x);
        if (n > 0) nx_result_log(b);
    }

    // KX_DIAG-A (temporary, DEREF-FREE): box64 .text anchor (symbolize the host fault PC of a nested crash)
    // + the live xEmu register (cpu_gprs[0]). Emitted BEFORE any structure walk (thread_get_emu / dynablock
    // lookup) so it survives even if THOSE nest-crash. Only channel that survives a 2nd fault.
    {
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

    // 1) Synthesize a Linux-aarch64 ucontext (shim layout) from the dump. Thread-local so concurrent
    //    guest-thread faults don't clobber each other (the libnx exception STACK is still shared — a known
    //    limitation for now; the gate is single-fault).
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
    // Only walk box64's (GLOBAL, unlocked) dynablock rbtree when we actually have an emu to deliver to.
    // With no emu (corrupt xEmu / TLS-less exc ctx) the walk is both pointless AND race-prone: the OTHER
    // guest thread may be mutating the tree concurrently -> rb_get_64 reads a NULL node (far=0x20) and the
    // handler LOOPS re-faulting. Skip it; x64pc falls back to the block-start RIP (x27) for the diagnostic.
    if (emu) {
        dynablock_t* db = FindDynablockFromNativeAddress(rw);
        if (db) {
            cur_db = db;
            uintptr_t gx = getX64Address(db, (uintptr_t)rw);
            if (gx) x64pc = gx;                  // precise faulting-instruction RIP
        }
    }
#endif

    // KX_DIAG-B (temporary): the PRECISE guest RIP (getX64Address) + rw + db. If DIAG-A logged but DIAG-B
    // does not, the nest-crash is in the FindDynablock/getX64Address lookup (lines above).
    {
        char b[160];
        int n = snprintf(b, sizeof b, "nx_exc2b: x64pc=0x%llx rw=%p db=%p",
            (unsigned long long)x64pc, rw, cur_db);
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
    {
        char b[192];
        uintptr_t hh = my_context ? (uintptr_t)my_context->signals[sig] : 0;
        int n = snprintf(b, sizeof b,
            "nx_exc2: anchor=%p x64pc=0x%llx emu=%p db=%p sig=%d h=0x%llx rw=%p",
            (void*)&__libnx_exception_handler, (unsigned long long)x64pc,
            (void*)emu, cur_db, sig, (unsigned long long)hh, rw);
        if (n > 0) nx_result_log(b);
    }

    // Defensive same-address loop guard: if the EXACT same fault (fault address + guest RIP) recurs many
    // times in a row, delivery isn't making progress (a delivery/resume bug) — bail to a crash report
    // instead of hanging forever. Hanging a HOME-launched title can only be recovered by a reboot, so this
    // safety net is worth keeping. A program that catches many DIFFERENT faults resets the counter.
    {
        static __thread uintptr_t last_far = ~0ULL, last_rip = ~0ULL;
        static __thread int repeat = 0;
        if (ctx->far.x == last_far && x64pc == last_rip) {
            if (++repeat >= 16) {
                nx_result_log("nx_exc: same fault repeated 16x — delivery not progressing, giving up");
                return;
            }
        } else { last_far = ctx->far.x; last_rip = x64pc; repeat = 0; }
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
            nx_resume_native(&rc);                      // reloads full state, branches to rx+4; NEVER returns
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

    // Unhandled / default action: final breadcrumb, then return -> libnx -> svcBreak -> Horizon crash report.
    {
        char b[160];
        int n = snprintf(b, sizeof b,
            "nx_exc: UNHANDLED sig=%d code=%d addr=0x%llx db=%p x64pc=0x%llx -> crash report",
            sig, si_code, (unsigned long long)ctx->far.x, cur_db, (unsigned long long)x64pc);
        if (n > 0) nx_result_log(b);
    }
}

#endif // __SWITCH__
