// box64-nx — Horizon userspace CPU-exception handler (M2.2c2, async guest-signal delivery).
//
// A real bad guest dereference / SMC write / bad jump faults as an ARM64 CPU exception inside
// dynarec-generated code. Horizon delivers such exceptions to a per-process userspace entry which libnx's
// crt0 dispatches to the weak __libnx_exception_handler. By DEFINING it (non-weak) + enlarging the weak
// exception stack + setting ignoredebug, we take over that path (instead of the kernel crash-report/fatal).
//
// STEP 1 (this file, for now): just prove Horizon delivers the exception to us, and dump enough to place
// the fault (error_desc/ESR/FAR + the box64 guest RIP in x27). The dump→ucontext shim, adjust_arch, and
// actual guest-signal delivery + siglongjmp resume come next.
#ifdef __SWITCH__

#include <switch.h>
#include <stdio.h>

extern void nx_result_log(const char*);   // nx_main.c: heap-free SD result line (the ONLY HW-visible channel)

// Override libnx's weak scaffolding. Bigger stack than the 0x400 default (box64's fault path is heavy);
// ignoredebug=1 so the handler still runs when a debugger/gdbstub is attached (Ryujinx often attaches one,
// which would otherwise route the exception to the debugger and skip our handler).
__attribute__((aligned(16))) u8 __nx_exception_stack[0x10000];
u64 __nx_exception_stack_size = sizeof(__nx_exception_stack);
u32 __nx_exception_ignoredebug = 1;

// box64 arm64 register map (see CLAUDE.md crash-triage): x10=RAX … x25=R15, x26=xFlags, x27=guest RIP.
// The dump runs ON THE FAULTING THREAD on the dedicated exception stack, AFTER the kernel exception frame
// was consumed by libnx's entry stub — so we cannot svcReturnFromException to resume (that's a userspace
// job, added with delivery). Returning from here lands in libnx's returnentry -> svcBreak -> crash report.
void __libnx_exception_handler(ThreadExceptionDump* ctx)
{
    char b[256];
    int n = snprintf(b, sizeof b,
        "nx_exc: desc=0x%x esr=0x%x far=0x%llx pc=0x%llx pstate=0x%x gRIP(x27)=0x%llx xFlags(x26)=0x%llx\n",
        ctx->error_desc, ctx->esr,
        (unsigned long long)ctx->far.x, (unsigned long long)ctx->pc.x, ctx->pstate,
        (unsigned long long)ctx->cpu_gprs[27].x, (unsigned long long)ctx->cpu_gprs[26].x);
    if (n > 0) svcOutputDebugString(b, (size_t)n);   // Ryujinx-visible
    nx_result_log(b);   // append to box64-result.txt — the ONLY way to see this on real HW (over FTP)
    // NOTE: Ryujinx does NOT deliver user CPU exceptions here (it uses its own InvalidAccessHandler), so
    // this handler only ever runs on real hardware. Returning lands in libnx -> svcBreak -> crash report;
    // that's fine for step 1 (prove delivery). Delivery + siglongjmp resume replace the return next.
}

#endif // __SWITCH__
