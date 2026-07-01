// box64-nx — Switch replacement for src/libtools/signals.c.
//
// box64's signals.c drives x86 signal emulation off the *host* Linux signal
// machinery: rich siginfo_t (si_addr/si_errno), struct sigaction with
// sa_sigaction, and aarch64 kernel sigcontext (_aarch64_ctx/FPSIMD_MAGIC).
// newlib provides none of these (its siginfo_t is the minimal 3-field POSIX
// form, its sigaction has no sa_sigaction), and Horizon never delivers Linux
// signals to the emulator anyway. So for M1 (interpreter, single-threaded,
// static guests) we replace the whole file with stubs of its public API:
// guests that install/raise signals get a clean no-op rather than a fault, and
// box64 links. Real host-signal-backed delivery returns with M2+.
#ifdef __SWITCH__

#include <stdint.h>
#include <signal.h>

#include "debug.h"
#include "x64emu.h"
#include "emu/x64emu_private.h"
#include "signals.h"
#include "../../libtools/signal_private.h"

// --- guest signal installation (bookkeeping only; never armed on Horizon) ---------------------
EXPORT sighandler_t my_signal(x64emu_t* emu, int signum, sighandler_t handler) {
    (void)emu; (void)signum; (void)handler; return SIG_DFL;
}
EXPORT sighandler_t my___sysv_signal(x64emu_t* emu, int signum, sighandler_t handler) {
    (void)emu; (void)signum; (void)handler; return SIG_DFL;
}
EXPORT sighandler_t my_sysv_signal(x64emu_t* emu, int signum, sighandler_t handler) {
    (void)emu; (void)signum; (void)handler; return SIG_DFL;
}
EXPORT sighandler_t my_sigset(x64emu_t* emu, int signum, sighandler_t handler) {
    (void)emu; (void)signum; (void)handler; return SIG_DFL;
}
EXPORT int my_sigaction(x64emu_t* emu, int signum, const x64_sigaction_t* act, x64_sigaction_t* oldact) {
    (void)emu; (void)signum; (void)act; (void)oldact; return 0;
}
EXPORT int my___sigaction(x64emu_t* emu, int signum, const x64_sigaction_t* act, x64_sigaction_t* oldact) {
    (void)emu; (void)signum; (void)act; (void)oldact; return 0;
}
EXPORT int my_syscall_rt_sigaction(x64emu_t* emu, int signum, const x64_sigaction_restorer_t* act, x64_sigaction_restorer_t* oldact, int sigsetsize) {
    (void)emu; (void)signum; (void)act; (void)oldact; (void)sigsetsize; return 0;
}
EXPORT int my_sigaltstack(x64emu_t* emu, const x64_stack_t* ss, x64_stack_t* oss) {
    (void)emu; (void)ss; (void)oss; return 0;
}

// --- ucontext family (guest get/set/make/swapcontext); unused by static guests ----------------
EXPORT int  my_getcontext(x64emu_t* emu, void* ucp) { (void)emu; (void)ucp; return 0; }
EXPORT int  my_setcontext(x64emu_t* emu, void* ucp) { (void)emu; (void)ucp; return 0; }
EXPORT void my_start_context(x64emu_t* emu) { (void)emu; }
EXPORT void my_makecontext(x64emu_t* emu, void* ucp, void* fnc, int32_t argc, int64_t* argv) {
    (void)emu; (void)ucp; (void)fnc; (void)argc; (void)argv;
}
EXPORT int  my_swapcontext(x64emu_t* emu, void* ucp1, void* ucp2) { (void)emu; (void)ucp1; (void)ucp2; return 0; }

// --- internal API other box64 TUs reference ---------------------------------------------------
x64_stack_t* sigstack_getstack(void) { return NULL; }

uint64_t RunFunctionHandler(x64emu_t* emu, int* exit, int dynarec, x64_ucontext_t* sigcontext, uintptr_t fnc, int nargs, ...) {
    (void)emu; (void)dynarec; (void)sigcontext; (void)fnc; (void)nargs;
    if (exit) *exit = 0;
    return 0;   // no guest signal handlers run on Horizon in M1
}

int  defer_signal(x64emu_t* emu, int signum, siginfo_t* info) { (void)emu; (void)signum; (void)info; return 0; }
void cancel_deferred_signal_processing(x64emu_t* emu) { (void)emu; }
void enter_critical_section(void) {}
void leave_critical_section(void) {}

void my_sigactionhandler_oldcode(x64emu_t* emu, int32_t sig, int simple, siginfo_t* info, void* ucntx, int* old_code, void* cur_db, uintptr_t x64pc) {
    (void)emu; (void)sig; (void)simple; (void)info; (void)ucntx; (void)old_code; (void)cur_db; (void)x64pc;
}
void my_sigactionhandler(int32_t sig, siginfo_t* info, void* ucntx) { (void)sig; (void)info; (void)ucntx; }

void init_signal_helper(box64context_t* context) { (void)context; }  // no host signal handlers installed
void fini_signal_helper(void) {}

// x86-64 and aarch64/newlib signal numbers mostly coincide for the common signals; identity
// is sufficient for M1 (signals are not delivered to the emulator on Horizon anyway).
int signal_from_x64(int sig) { return sig; }

#endif // __SWITCH__
