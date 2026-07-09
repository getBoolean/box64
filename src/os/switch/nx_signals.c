// box64-nx — Switch replacement for src/libtools/signals.c.
//
// box64's upstream signals.c drives x86 signal *emulation* off the HOST Linux
// signal machinery: it installs a real host SIGSEGV/SIGBUS/SIGILL/SIGABRT handler
// (my_box64signalhandler), and the guest's sigaction()/signal() calls are proxied
// onto the host with sa_sigaction=MY_SIGHANDLER. Horizon has NO POSIX signal
// delivery, and newlib's siginfo_t is the minimal 3-field POSIX form (no si_errno /
// si_addr), so none of that host path exists here.
//
// What box64-nx keeps is the *synchronous* delivery path: when the x86 engine itself
// raises a fault (EmitSignal/EmitDiv0/EmitInterruption in emit_signal_switch.c) or the
// guest raises a signal at itself (kill/tgkill/raise), we build the x86-64 sigframe on
// the guest stack and run the guest's own handler directly — exactly the body of
// my_sigactionhandler_oldcode(_64) from upstream, ported verbatim minus the host bits.
// The ASYNC host-CPU-fault path (a real aarch64 exception -> guest SIGSEGV) is a
// separate vehicle (Horizon exception handler; not here).
//
// Ported almost verbatim from src/libtools/signals.c; deviations are commented "box64-nx:".
#ifdef __SWITCH__

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stddef.h>
#include <stdarg.h>
#include <signal.h>
#include <setjmp.h>
#include <pthread.h>
#include <ucontext.h>

#include "x64_signals.h"
#include "os.h"
#include "box64context.h"
#include "debug.h"
#include "x64emu.h"
#include "emu/x64emu_private.h"
#include "signals.h"
#include "box64cpu.h"
#include "custommem.h"
#include "emu/x87emu_private.h"
#include "sigtools.h"
#include "env.h"
#ifdef DYNAREC
#include "dynablock.h"
#include "dynarec/dynablock_private.h"
#include "dynarec_native.h"
#include "dynarec/dynarec_arch.h"
#include "dynarec/dynarec_next.h"
#endif
#include "libtools/signal_private.h"

// box64-nx: the guest speaks the x86-64 Linux signal ABI, and newlib's host macros
// (SA_ONSTACK, SS_DISABLE, SEGV_ACCERR, ...) may carry different values, so pin the
// x86-64 values box64/the guest expect rather than trusting <signal.h>.
#define X64_SA_SIGINFO   0x00000004u
#define X64_SA_RESTORER  0x04000000u
#define X64_SA_ONSTACK   0x08000000u
#define X64_SS_ONSTACK   1
#define X64_SS_DISABLE   2
#define X64_SEGV_MAPERR  1
#define X64_SEGV_ACCERR  2
#define X64_FPE_INTOVF   2
#define X64_SI_KERNEL    128
#define X64_SI_TKILL     (-6)

extern void nx_result_log(const char*);   // nx_main.c: heap-free SD result line (for signal-context exit visibility)

int  my_sigactionhandler_oldcode_64(x64emu_t* emu, int32_t sig, int simple, x64_siginfo_t* info, void* ucntx, int* old_code, void* cur_db);
void my_sigactionhandler_oldcode(x64emu_t* emu, int32_t sig, int simple, x64_siginfo_t* info, void* ucntx, int* old_code, void* cur_db, uintptr_t x64pc);

// ----- alternate-signal-stack, kept per-thread via a pthread key (libnx has pthread keys) -----
static void sigstack_destroy(void* p)
{
    x64_stack_t *ss = (x64_stack_t*)p;
    box_free(ss);
}

static pthread_key_t sigstack_key;
static pthread_once_t sigstack_key_once = PTHREAD_ONCE_INIT;

static void sigstack_key_alloc() {
    pthread_key_create(&sigstack_key, sigstack_destroy);
}

x64_stack_t* sigstack_getstack() {
    return (x64_stack_t*)pthread_getspecific(sigstack_key);
}

// this allows handling a "safe" access that just aborts on a bad address (used by
// my_sigaltstack). On Horizon there is no host SIGSEGV to longjmp us back here, so the
// sigsetjmp below always falls through with 0 — harmless, kept for faithfulness.
static __thread JUMPBUFF signal_jmpbuf;
#define SIG_JMPBUF &signal_jmpbuf
static __thread int signal_jmpbuf_active = 0;

uint64_t RunFunctionHandler(x64emu_t* emu, int* exit, int dynarec, x64_ucontext_t* sigcontext, uintptr_t fnc, int nargs, ...)
{
    if(fnc==0 || fnc==1) {
        va_list va;
        va_start (va, nargs);
        int sig = va_arg(va, int);
        va_end (va);
        printf_log(LOG_NONE, "%04d|Warning, calling Signal %d function handler %s\n", GetTID(), sig, fnc?"SIG_IGN":"SIG_DFL");
        if(fnc==0) {
            printf_log(LOG_NONE, "Unhandled signal caught, aborting\n");
            abort();
        }
        return 0;
    }
#ifdef HAVE_TRACE
    uintptr_t old_start = trace_start, old_end = trace_end;
#endif
    if(!emu)
        emu = thread_get_emu();
    #ifdef DYNAREC
    if (BOX64ENV(dynarec_test))
        emu->test.test = 0;
    #endif

    int align = nargs&1;

    if(nargs>6)
        R_RSP -= (nargs-6+align)*sizeof(void*);   // need to push in reverse order

    uint64_t *p = (uint64_t*)R_RSP;

    va_list va;
    va_start (va, nargs);
    for (int i=0; i<nargs; ++i) {
        if(i<6) {
            int nn[] = {_DI, _SI, _DX, _CX, _R8, _R9};
            emu->regs[nn[i]].q[0] = va_arg(va, uint64_t);
        } else {
            *p = va_arg(va, uint64_t);
            p++;
        }
    }
    va_end (va);

    printf_log(LOG_DEBUG, "%04d|signal #%d function handler %p called, RSP=%p%s\n", GetTID(), R_EDI, (void*)fnc, (void*)R_RSP, dynarec?" with Dynarec":"");

    int oldquitonlongjmp = emu->flags.quitonlongjmp;
    emu->flags.quitonlongjmp = 2;
    int old_cs = R_CS;
    R_CS = 0x33;
#ifdef __SWITCH__
    // DynaCall/EmuCall stop the nested emulation by setting emu->quit=1 (their "callee returned"
    // sentinel). On Horizon a signal handler is delivered SYNCHRONOUSLY as a nested call, so that quit
    // must NOT leak to the outer emulation loop (which would think the guest exited). Save & restore it.
    int old_quit = emu->quit;
#endif

    if(dynarec)
        DynaCall(emu, fnc, 0);
    else
        EmuCall(emu, fnc);
#ifdef __SWITCH__
    emu->quit = old_quit;
#endif

    if(nargs>6 && !emu->flags.longjmp)
        R_RSP+=((nargs-6+align)*sizeof(void*));

    if(!emu->flags.longjmp && R_CS==0x33)
        R_CS = old_cs;

    emu->flags.quitonlongjmp = oldquitonlongjmp;

    #ifdef DYNAREC
    if (BOX64ENV(dynarec_test)) {
        emu->test.test = 0;
        emu->test.clean = 0;
    }
#endif

    if(emu->flags.longjmp) {
        // longjmp inside signal handler, lets grab all relevent value and do the actual longjmp in the signal handler
        emu->flags.longjmp = 0;
        if(sigcontext) {
            sigcontext->uc_mcontext.gregs[X64_R8] = R_R8;
            sigcontext->uc_mcontext.gregs[X64_R9] = R_R9;
            sigcontext->uc_mcontext.gregs[X64_R10] = R_R10;
            sigcontext->uc_mcontext.gregs[X64_R11] = R_R11;
            sigcontext->uc_mcontext.gregs[X64_R12] = R_R12;
            sigcontext->uc_mcontext.gregs[X64_R13] = R_R13;
            sigcontext->uc_mcontext.gregs[X64_R14] = R_R14;
            sigcontext->uc_mcontext.gregs[X64_R15] = R_R15;
            sigcontext->uc_mcontext.gregs[X64_RAX] = R_RAX;
            sigcontext->uc_mcontext.gregs[X64_RCX] = R_RCX;
            sigcontext->uc_mcontext.gregs[X64_RDX] = R_RDX;
            sigcontext->uc_mcontext.gregs[X64_RDI] = R_RDI;
            sigcontext->uc_mcontext.gregs[X64_RSI] = R_RSI;
            sigcontext->uc_mcontext.gregs[X64_RBP] = R_RBP;
            sigcontext->uc_mcontext.gregs[X64_RSP] = R_RSP;
            sigcontext->uc_mcontext.gregs[X64_RBX] = R_RBX;
            sigcontext->uc_mcontext.gregs[X64_RIP] = R_RIP;
            // flags
            sigcontext->uc_mcontext.gregs[X64_EFL] = emu->eflags.x64;
            // get segments
            sigcontext->uc_mcontext.gregs[X64_CSGSFS] = ((uint64_t)(R_CS)) | (((uint64_t)(R_GS))<<16) | (((uint64_t)(R_FS))<<32) | (((uint64_t)(R_SS))<<48) ;
        } else {
            printf_log(LOG_NONE, "Warning, longjmp in signal but no sigcontext to change\n");
        }
    }
    if(exit)
        *exit = emu->exit;

    uint64_t ret = R_RAX;

#ifdef HAVE_TRACE
    trace_start = old_start; trace_end = old_end;
#endif

    return ret;
}

EXPORT int my_sigaltstack(x64emu_t* emu, const x64_stack_t* ss, x64_stack_t* oss)
{
    if(!ss && !oss) {   // this is not true, ss can be NULL to retreive oss info only
        errno = EFAULT;
        return -1;
    }
    signal_jmpbuf_active = 1;
    if(sigsetjmp(SIG_JMPBUF, 1)) {
        // segfault while gathering function name...
        errno = EFAULT;
        return -1;
    }

    x64_stack_t *new_ss = (x64_stack_t*)pthread_getspecific(sigstack_key);
    if(oss) {
        if(!new_ss) {
            oss->ss_flags = X64_SS_DISABLE;
            oss->ss_sp = emu->init_stack;
            oss->ss_size = emu->size_stack;
        } else {
            oss->ss_flags = new_ss->ss_flags;
            oss->ss_sp = new_ss->ss_sp;
            oss->ss_size = new_ss->ss_size;
        }
    }
    if(!ss) {
        signal_jmpbuf_active = 0;
        return 0;
    }
    printf_log(LOG_DEBUG, "%04d|sigaltstack called ss=%p[flags=0x%x, sp=%p, ss=0x%lx], oss=%p\n", GetTID(), ss, ss->ss_flags, ss->ss_sp, ss->ss_size, oss);
    if(ss->ss_flags && ss->ss_flags!=X64_SS_DISABLE && ss->ss_flags!=X64_SS_ONSTACK) {
        errno = EINVAL;
        signal_jmpbuf_active = 0;
        return -1;
    }

    if(ss->ss_flags==X64_SS_DISABLE) {
        if(new_ss)
            box_free(new_ss);
        pthread_setspecific(sigstack_key, NULL);
        signal_jmpbuf_active = 0;
        return 0;
    }

    if(!new_ss)
        new_ss = (x64_stack_t*)box_calloc(1, sizeof(x64_stack_t));
    new_ss->ss_flags = 0;
    new_ss->ss_sp = ss->ss_sp;
    new_ss->ss_size = ss->ss_size;

    pthread_setspecific(sigstack_key, new_ss);
    signal_jmpbuf_active = 0;
    return 0;
}

// ----- deferred-signal critical section (drives box64's own memory-protection locks) -----
static int is_signal_deferrable(int sig)
{
    switch (sig) {
        case X64_SIGSEGV:
        case X64_SIGBUS:
        case X64_SIGILL:
        case X64_SIGABRT:
            return 0;
    }
    return 1;
}

int defer_signal(x64emu_t* emu, int signum, x64_siginfo_t* info)
{
    if (!emu || signum < 0 || signum > MAX_SIGNAL || !is_signal_deferrable(signum) || emu->critical_section <= 0)
        return 0;

    if (info)
        emu->deferred_siginfo[signum] = *info;
    else
        memset(&emu->deferred_siginfo[signum], 0, sizeof(emu->deferred_siginfo[signum]));
    emu->deferred_siginfo[signum].si_signo = signum;
    if (!emu->deferred_signal_pending[signum])
        ++emu->deferred_signal_count;
    emu->deferred_signal_pending[signum] = 1;
    return 1;
}

void cancel_deferred_signal_processing(x64emu_t* emu)
{
    if (!emu) return;
    emu->critical_section = 0;
    emu->deferred_signal_processing = 0;
}

void enter_critical_section()
{
    x64emu_t* emu = thread_get_emu_no_create();
    if (emu) ++emu->critical_section;
}

void leave_critical_section()
{
    x64emu_t* emu = thread_get_emu_no_create();
    if (!emu || emu->critical_section <= 0)
        return;
    if (--emu->critical_section || !emu->deferred_signal_count || emu->deferred_signal_processing)
        return;

    emu->deferred_signal_processing = 1;
    while (emu->deferred_signal_count) {
        int handled = 0;
        for (int sig = 1; sig <= MAX_SIGNAL; ++sig) {
            if (!emu->deferred_signal_pending[sig])
                continue;
            x64_siginfo_t info = emu->deferred_siginfo[sig];
            emu->deferred_signal_pending[sig] = 0;
            --emu->deferred_signal_count;
            handled = 1;
            my_sigactionhandler_oldcode(emu, sig, 0, &info, NULL, NULL, NULL, R_RIP);
        }
        if (!handled) {
            emu->deferred_signal_count = 0;
            break;
        }
    }
    emu->deferred_signal_processing = 0;
}

int my_sigactionhandler_oldcode_64(x64emu_t* emu, int32_t sig, int simple, x64_siginfo_t* info, void * ucntx, int* old_code, void* cur_db)
{
    (void)simple;
    int Locks = unlockMutex();
    int log_minimum = (BOX64ENV(showsegv))?LOG_NONE:LOG_DEBUG;

    printf_log(LOG_DEBUG, "Sigactionhanlder for signal #%d called (jump to %p/%s)\n", sig, (void*)my_context->signals[sig], GetNativeName((void*)my_context->signals[sig], 1));

    uintptr_t restorer = my_context->restorer[sig];
    // get that actual ESP first!
    if(!emu)
        emu = thread_get_emu();
    uintptr_t frame = R_RSP;
#if defined(DYNAREC)
    dynablock_t* db = (dynablock_t*)cur_db;//FindDynablockFromNativeAddress(pc);
    ucontext_t *p = (ucontext_t *)ucntx;
    void* pc = NULL;
    if(p) {
        pc = (void*)CONTEXT_PC(p);
        if(db)
            frame = (uintptr_t)CONTEXT_REG(p, xRSP);    //this should not be needed, as emu has been "adjusted" to dynablock value already in the caller
    }
#else
    (void)ucntx; (void)cur_db;
    void* pc = NULL;
#endif

    // stack tracking
    x64_stack_t *new_ss = my_context->onstack[sig]?(x64_stack_t*)pthread_getspecific(sigstack_key):NULL;
    int used_stack = 0;
    if(new_ss && (new_ss->ss_flags!=X64_SS_ONSTACK)) {  // alt stack and not already using it
        frame = (uintptr_t)(((uintptr_t)new_ss->ss_sp + new_ss->ss_size - 16ULL) & ~0x0fULL);
        used_stack = 1;
        new_ss->ss_flags = X64_SS_ONSTACK;
    } else {
        frame = frame&~15ULL;
        frame -= 0x200ULL; // redzone
    }

    // TODO: do I need to really setup 2 stack frame? That doesn't seems right!
    // setup stack frame
    frame -= 512+64+16*16;
    void* xstate = (void*)frame;
    frame -= sizeof(x64_siginfo_t);
    x64_siginfo_t* info2 = (x64_siginfo_t*)frame;
    memcpy(info2, info, sizeof(x64_siginfo_t));
    // try to fill some sigcontext....
    frame -= sizeof(x64_ucontext_t);
    x64_ucontext_t   *sigcontext = (x64_ucontext_t*)frame;
    // get general register
    emu2mctx(&sigcontext->uc_mcontext, emu);
    // get FloatPoint status
    sigcontext->uc_mcontext.fpregs = xstate;//(struct x64_libc_fpstate*)&sigcontext->xstate;
    fpu_xsave_mask(emu, xstate, 0, 0b111);
    memcpy(&sigcontext->xstate, xstate, sizeof(sigcontext->xstate));
    ((struct x64_fpstate*)xstate)->res[12] = 0x46505853;   // magic number to signal an XSTATE type of fpregs
    ((struct x64_fpstate*)xstate)->res[13] = 0; // offset to xstate after this?
    // get signal mask

    if(new_ss) {
        sigcontext->uc_stack.ss_sp = new_ss->ss_sp;
        sigcontext->uc_stack.ss_size = new_ss->ss_size;
        sigcontext->uc_stack.ss_flags = new_ss->ss_flags;
    } else
        sigcontext->uc_stack.ss_flags = X64_SS_DISABLE;
    // Try to guess some X64_TRAPNO (values are x86 trap numbers, see upstream comment)
    uint32_t prot = getProtection((uintptr_t)info->si_addr);
    uint32_t mmapped = memExist((uintptr_t)info->si_addr);
    uint32_t sysmapped = (info->si_addr<(void*)box64_pagesize)?1:mmapped;
    uint32_t real_prot = 0;
    int skip = 3;   // in case sigjump is used to restore exectuion, 1 will switch to interpreter, 3 will switch to dynarec
    if(prot&PROT_READ) real_prot|=PROT_READ;
    if(prot&PROT_WRITE) real_prot|=PROT_WRITE;
    if(prot&PROT_EXEC) real_prot|=PROT_WRITE;
    if(prot&PROT_DYNAREC) real_prot|=PROT_WRITE;
    sigcontext->uc_mcontext.gregs[X64_ERR] = 0;
    sigcontext->uc_mcontext.gregs[X64_TRAPNO] = 0;
    if(sig==X64_SIGBUS)
        sigcontext->uc_mcontext.gregs[X64_TRAPNO] = 17;
    else if(sig==X64_SIGSEGV) {
        if((uintptr_t)info->si_addr == sigcontext->uc_mcontext.gregs[X64_RIP]) {
            if(info->si_errno==0xbad0) {
                //bad opcode
                sigcontext->uc_mcontext.gregs[X64_ERR] = 0;
                sigcontext->uc_mcontext.gregs[X64_TRAPNO] = 13;
                info2->si_code = 128;
                info2->si_errno = 0;
                info2->si_addr = NULL;
            } else if (info->si_errno==0xecec) {
                // no excute bit on segment
                sigcontext->uc_mcontext.gregs[X64_ERR] = 0x14|((sysmapped && !(real_prot&PROT_READ))?0:1);
                sigcontext->uc_mcontext.gregs[X64_TRAPNO] = 14;
                if(!mmapped) info2->si_code = 1;
                info2->si_errno = 0;
            } else if (info->si_errno==0xb09d) {
                // bound exception
                sigcontext->uc_mcontext.gregs[X64_ERR] = 0;
                sigcontext->uc_mcontext.gregs[X64_TRAPNO] = 5;
                info2->si_errno = 0;
            }else {
                sigcontext->uc_mcontext.gregs[X64_ERR] = 0x14|((sysmapped && !(real_prot&PROT_READ))?0:1);
                sigcontext->uc_mcontext.gregs[X64_TRAPNO] = 14;
            }
        } else {
            sigcontext->uc_mcontext.gregs[X64_TRAPNO] = 14;
            sigcontext->uc_mcontext.gregs[X64_ERR] = 4|((sysmapped && !(real_prot&PROT_READ))?0:1);
            if(write_opcode(sigcontext->uc_mcontext.gregs[X64_RIP], (uintptr_t)pc, (R_CS==0x23)))
                sigcontext->uc_mcontext.gregs[X64_ERR] |= 2;
        }
        if(info->si_code == X64_SEGV_ACCERR && old_code)
            *old_code = -1;
        if(info->si_errno==0x1234) {
            sigcontext->uc_mcontext.gregs[X64_TRAPNO] = 13;
            info2->si_errno = 0;
        } else if(info->si_errno==0xdead) {
            // INT x
            uint8_t int_n = info->si_code;
            info2->si_errno = 0;
            info2->si_code = 128;
            info2->si_addr = NULL;
            sigcontext->uc_mcontext.gregs[X64_TRAPNO] = 13;
            skip = 3;   // can resume in dynarec
            // some special cases...
            if(int_n==3) {
                info2->si_signo = X64_SIGTRAP;
                sigcontext->uc_mcontext.gregs[X64_TRAPNO] = 3;
                sigcontext->uc_mcontext.gregs[X64_ERR] = 0;
            } else if(int_n==0x04) {
                sigcontext->uc_mcontext.gregs[X64_TRAPNO] = 4;
                sigcontext->uc_mcontext.gregs[X64_ERR] = 0;
            } else if (int_n==0x29 || int_n==0x2c || int_n==0x2d) {
                sigcontext->uc_mcontext.gregs[X64_ERR] = 0x02|(int_n<<3);
            } else {
                sigcontext->uc_mcontext.gregs[X64_ERR] = 0x0a|(int_n<<3);
                sigcontext->uc_mcontext.gregs[X64_TRAPNO] = 13;
            }
        } else if(info->si_errno==0xcafe) { // divide by 0
            info2->si_errno = 0;
            sigcontext->uc_mcontext.gregs[X64_ERR] = 0;
            sigcontext->uc_mcontext.gregs[X64_TRAPNO] = 0;
            info2->si_signo = X64_SIGFPE;
            skip = 3; // can resume in dynarec
        }
    } else if(sig==X64_SIGFPE) {
        if (info->si_code == X64_FPE_INTOVF)
            sigcontext->uc_mcontext.gregs[X64_TRAPNO] = 4;
        else
            sigcontext->uc_mcontext.gregs[X64_TRAPNO] = 19;
        skip = 3;
    } else if(sig==X64_SIGILL) {
        info2->si_code = 2;
        sigcontext->uc_mcontext.gregs[X64_TRAPNO] = 6;
        info2->si_addr = (void*)sigcontext->uc_mcontext.gregs[X64_RIP];
    } else if(sig==X64_SIGTRAP) {
        if(info->si_code==1) {  //single step
            info2->si_code = 2;
            info2->si_addr = (void*)sigcontext->uc_mcontext.gregs[X64_RIP];
        } else
            info2->si_code = 128;
        sigcontext->uc_mcontext.gregs[X64_TRAPNO] = info->si_code;
        sigcontext->uc_mcontext.gregs[X64_ERR] = 0;
    } else {
        skip = 3;   // other signal can resume in dynarec
    }
    //TODO: SIGABRT generate what?
    printf_log((sig==10)?LOG_DEBUG:log_minimum, "Signal %d: si_addr=%p, TRAPNO=%d, ERR=%d, RIP=%p, prot=%x, mmapped:%d\n", sig, (void*)info2->si_addr, sigcontext->uc_mcontext.gregs[X64_TRAPNO], sigcontext->uc_mcontext.gregs[X64_ERR],sigcontext->uc_mcontext.gregs[X64_RIP], prot, mmapped);
    #ifdef DYNAREC
    if(sig==3)
        SerializeAllMapping();  // Signal Interupt: it's a good time to serialize the mappings if needed
    #endif
    // call the signal handler
    x64_ucontext_t sigcontext_copy = *sigcontext;
    // save old value from emu
    #define GO(A) uint64_t old_##A = R_##A
    GO(RAX);
    GO(RDI);
    GO(RSI);
    GO(RDX);
    GO(RCX);
    GO(R8);
    GO(R9);
    GO(RBP);
    #undef GO
    uint64_t old_eflags = emu->eflags.x64;
    emu->eflags.x64 = 0x202; // default flags for inside the signal handler
    // set stack pointer
    R_RSP = frame;
    // set frame pointer
    R_RBP = sigcontext->uc_mcontext.gregs[X64_RBP];

    int exits = 0;
    int ret;
    int dynarec = 0;
    #ifdef DYNAREC
    if(!((Locks&is_dyndump_locked) || (Locks&is_memprot_locked)))
        dynarec = BOX64ENV(dynarec_interp_signal)?0:1;
    #endif
    ret = RunFunctionHandler(emu, &exits, dynarec, sigcontext, my_context->signals[info2->si_signo], 3, info2->si_signo, info2, sigcontext);
    if(used_stack)  // release stack
        new_ss->ss_flags = 0;
    // restore old value from emu
    #define GO(A) R_##A = old_##A
    GO(RAX);
    GO(RDI);
    GO(RSI);
    GO(RDX);
    GO(RCX);
    GO(R8);
    GO(R9);
    GO(RBP);
    #undef GO
    emu->eflags.x64 = old_eflags;

#ifdef __SWITCH__
    // box64-nx (M2.2c2): if the guest EXITED inside the handler — i.e. it did a non-local jump (siglongjmp)
    // out of the handler and ran the program all the way to exit_group(), which on Horizon sets emu->exit
    // (=> exits) and RETURNS here rather than terminating (there is no host exit syscall) — then there is
    // NOTHING to resume: the guest is gone. Terminate NOW with its code. This MUST come before the
    // memcmp/siglongjmp resume block below: the guest's exit-path execution dirties the on-stack sigcontext
    // (changed!=0), so that block would otherwise siglongjmp back to the (already-exited) faulting RIP and
    // re-fault forever. `ret` is RunFunctionHandler's return = the guest's exit code (captured pre-restore).
    if(exits) {
        char b[64]; snprintf(b, sizeof b, "guest exited=%d (in signal handler)", (int)ret); nx_result_log(b);
        #ifdef DYNAREC
        if(Locks & is_dyndump_locked) CancelBlock64(1);
        #endif
        exit((int)ret);
    }
#endif
    if(memcmp(sigcontext, &sigcontext_copy, sizeof(x64_ucontext_t))) {
        #if defined(DYNAREC)
        if(db || emu->jmpbuf)
            mctx2emu(emu, &sigcontext->uc_mcontext);
        #ifndef __SWITCH__
        // box64-nx (M2.2c2): the native_next resume relies on a KERNEL sigreturn restoring the modified
        // host context (copyEmu2USignalCTXreg writes emu back into the host regs[]/pc, then the handler
        // returns and the kernel resumes at native_next). Horizon has no sigreturn from a CPU exception —
        // libnx's return path goes to svcBreak. So on Switch we skip this and fall through to the
        // siglongjmp(emu->jmpbuf) branch below, which resumes the guest by re-entering EmuRun on the
        // faulting thread's own stack at the (already-updated) R_RIP.
        if(db && !ACCESS_FLAG(F_TF)) {
            // if signal was inside a dynablock, just mirror all the new regs in the right place to simple run native_next
            mctx2emu(emu, &sigcontext->uc_mcontext);
            copyEmu2USignalCTXreg(p, emu, native_next);
            printf_log((sig==10)?LOG_DEBUG:log_minimum, "Context has been changed in Sigactionhanlder, jumping to native_next from DynaBlock at %p, RSP=%p\n", (void*)R_RIP, (void*)R_RSP);
            return 1;
        }
        #endif // !__SWITCH__
        #endif
        if(emu->jmpbuf) {
            #ifndef DYNAREC
            mctx2emu(emu, &sigcontext->uc_mcontext);
            #endif
            if((skip==1) && (emu->ip.q[0]!=sigcontext->uc_mcontext.gregs[X64_RIP]) && !ACCESS_FLAG(F_TF))
                skip = 3;   // if it jumps elsewhere, it can resume with dynarec...
            if (ACCESS_FLAG(F_TF) && skip == 1) emu->flags.no_tf = 1;
            printf_log((sig==10)?LOG_DEBUG:log_minimum, "Context has been changed in Sigactionhanlder, doing siglongjmp to resume emu at %p, RSP=%p (resume with %s)\n", (void*)R_RIP, (void*)R_RSP, (skip==3)?"Dynarec":"Interp");
            if(old_code)
                *old_code = -1;    // re-init the value to allow another segfault at the same place
            //relockMutex(Locks);   // do not relock mutex, because of the siglongjmp, whatever was running is canceled
            #ifdef DYNAREC
            if(Locks & is_dyndump_locked)
                CancelBlock64(1);
            #endif
            #if defined(RV64) || defined(PPC64LE)
            emu->xSPSave = emu->old_savedsp;
            #endif
            #ifdef DYNAREC
            dynablock_leave_runtime((dynablock_t*)cur_db);
            #endif
            cancel_deferred_signal_processing(emu);
            // box64-nx: Switch is non-ANDROID -> emu->jmpbuf is the (JUMPBUFF*) armed by
            // EmuRun; siglongjmp() is remapped to newlib longjmp() in os.h.
            siglongjmp(emu->jmpbuf, skip);
        }
        printf_log(LOG_INFO, "Warning, context has been changed in Sigactionhanlder%s\n", (sigcontext->uc_mcontext.gregs[X64_RIP]!=sigcontext_copy.uc_mcontext.gregs[X64_RIP])?" (EIP changed)":"");
    }
    // restore regs...
    #define GO(R)   R_##R=sigcontext->uc_mcontext.gregs[X64_##R]
    GO(RAX);
    GO(RCX);
    GO(RDX);
    GO(RDI);
    GO(RSI);
    GO(RBP);
    GO(RSP);
    GO(RBX);
    GO(R8);
    GO(R9);
    GO(R10);
    GO(R11);
    GO(R12);
    GO(R13);
    GO(R14);
    GO(R15);
    GO(RIP);
    #undef GO
    emu->eflags.x64=sigcontext->uc_mcontext.gregs[X64_EFL];
    if (ACCESS_FLAG(F_TF)) emu->flags.no_tf = 1;
    uint16_t seg;
    seg = (sigcontext->uc_mcontext.gregs[X64_CSGSFS] >> 0)&0xffff;
    #define GO(S) emu->segs[_##S]=seg;
    GO(CS);
    seg = (sigcontext->uc_mcontext.gregs[X64_CSGSFS] >> 16)&0xffff;
    GO(GS);
    seg = (sigcontext->uc_mcontext.gregs[X64_CSGSFS] >> 32)&0xffff;
    GO(FS);
    seg = (sigcontext->uc_mcontext.gregs[X64_CSGSFS] >> 48)&0xffff;
    GO(SS);
    #undef GO

    printf_log(LOG_DEBUG, "Sigactionhanlder main function returned (exit=%d, restorer=%p)\n", exits, (void*)restorer);
    if(exits) {
        //relockMutex(Locks);   // the thread will exit, so no relock there
        #ifdef DYNAREC
        if(Locks & is_dyndump_locked)
            CancelBlock64(1);
        #endif
        // box64-nx (M2.2c2): the guest exited from inside the handler (siglongjmp-out then ran to
        // exit_group). This is the correct terminate-now path; log the code since nx_main's
        // "guest exited=N" line is skipped when we exit() from this nested delivery context.
        { char b[64]; snprintf(b, sizeof b, "guest exited=%d (in signal handler)", (int)ret); nx_result_log(b); }
        exit(ret);
    }
#ifndef __SWITCH__
    // On Linux the guest handler "returns" to the restorer (__restore_rt), which calls rt_sigreturn to
    // pop the kernel-pushed host signal frame and resume the interrupted code. On Horizon delivery is a
    // SYNCHRONOUS nested call (no host signal frame): the emu is already restored above (GO(R) block),
    // and rt_sigreturn has nothing to return from (-> -ENOSYS). So skip the restorer and just return —
    // the outer emulation continues at the restored RIP. (Async CPU-fault delivery resumes via
    // siglongjmp(emu->jmpbuf) in the libnx exception handler, not here.)
    if(restorer)
        RunFunctionHandler(emu, &exits, 0, NULL, restorer, 0);
#else
    (void)restorer;
#endif
    relockMutex(Locks);
    return 0;
}

void my_sigactionhandler_oldcode(x64emu_t* emu, int32_t sig, int simple, x64_siginfo_t* info, void * ucntx, int* old_code, void* cur_db, uintptr_t x64pc)
{
    #define GO(A) uintptr_t old_##A = R_##A;
    GO(RAX);
    GO(RBX);
    GO(RCX);
    GO(RDX);
    GO(RBP);
    GO(RSP);
    GO(RDI);
    GO(RSI);
    GO(R8);
    GO(R9);
    GO(R10);
    GO(R11);
    GO(R12);
    GO(R13);
    GO(R14);
    GO(R15);
    GO(RIP);
    #undef GO
    x64flags_t old_eflags;
    deferred_flags_t old_df;
    multiuint_t old_op1;
    multiuint_t old_op2;
    multiuint_t old_res;
    sse_regs_t old_xmm[16];
    sse_regs_t old_ymm[16];
    mmx87_regs_t old_mmx[8];
    mmx87_regs_t old_x87[8];
    uint32_t old_top = emu->top;
    uint16_t old_segs[6];
    uintptr_t old_segs_offs[6];
    memcpy(old_xmm, emu->xmm, sizeof(old_xmm));
    memcpy(old_ymm, emu->ymm, sizeof(old_ymm));
    memcpy(old_mmx, emu->mmx, sizeof(old_mmx));
    memcpy(old_x87, emu->x87, sizeof(old_x87));
    memcpy(old_segs, emu->segs, sizeof(old_segs));
    memcpy(old_segs_offs, emu->segs_offs, sizeof(old_segs_offs));
    #define GO(A) old_##A = emu->A
    GO(eflags);
    GO(df);
    GO(op1);
    GO(op2);
    GO(res);
    #undef GO
    #ifdef DYNAREC
    dynablock_t* db = cur_db;
    if(db && ucntx) {
        void * pc =(void*)CONTEXT_PC((ucontext_t*)ucntx);
        copyUCTXreg2Emu(emu, ucntx, x64pc);
        adjustregs(emu, pc);
        if(db && db->arch_size)
            ARCH_ADJUST(db, emu, ucntx, x64pc);
    }
    #else
    (void)x64pc;
    #endif
    // box64-nx: Switch is never BOX32 -> always the 64bit delivery core.
    int direct_ret = my_sigactionhandler_oldcode_64(emu, sig, simple, info, ucntx, old_code, cur_db);
    if(direct_ret)
        return;
    #define GO(A) R_##A = old_##A
    GO(RAX);
    GO(RBX);
    GO(RCX);
    GO(RDX);
    GO(RBP);
    GO(RSP);
    GO(RDI);
    GO(RSI);
    GO(R8);
    GO(R9);
    GO(R10);
    GO(R11);
    GO(R12);
    GO(R13);
    GO(R14);
    GO(R15);
    GO(RIP);
    #undef GO
    #define GO(A) emu->A = old_##A
    GO(eflags);
    GO(df);
    GO(op1);
    GO(op2);
    GO(res);
    #undef GO
    memcpy(emu->xmm, old_xmm, sizeof(old_xmm));
    memcpy(emu->ymm, old_ymm, sizeof(old_ymm));
    memcpy(emu->mmx, old_mmx, sizeof(old_mmx));
    memcpy(emu->x87, old_x87, sizeof(old_x87));
    memcpy(emu->segs, old_segs, sizeof(old_segs));
    memcpy(emu->segs_offs, old_segs_offs, sizeof(old_segs_offs));
    emu->top = old_top;
}

// ----- self-directed delivery: kill/tgkill/raise route straight into the guest handler -----
// Horizon is a single guest process with no host signal delivery, so a guest kill/raise at
// itself is delivered synchronously (or queued if we are inside a box64 critical section).
static void nx_deliver_self(x64emu_t* emu, int sig)
{
    if(!emu)
        emu = thread_get_emu();
    if(sig<=0 || sig>MAX_SIGNAL)
        return;
    uintptr_t h = my_context->signals[sig];
    if(h==1)                        // SIG_IGN
        return;
    if(h==0) {                      // SIG_DFL -> terminate (matches RunFunctionHandler's fnc==0 path)
        printf_log(LOG_NONE, "Unhandled signal %d (SIG_DFL), aborting\n", sig);
        abort();
    }
    x64_siginfo_t info = {0};
    info.si_signo = sig;
    info.si_code = X64_SI_TKILL;    // sent by tkill/tgkill (matches glibc raise())
    if(defer_signal(emu, sig, &info))
        return;                     // deferrable + inside a critical section: run it on leave

    // Synchronous self-signal delivery. box64's host-signal-shaped delivery core (_64) rebuilds the guest
    // from a sigcontext it lays on the guest stack; here (a nested call from inside the tgkill syscall) the
    // handler's own stack use clobbers that frame and corrupts the resume. So deliver directly: run the
    // guest handler via RunFunctionHandler with siginfo+ucontext kept OFF the guest stack (per-thread
    // buffers are guest-readable — box64 maps guest memory 1:1 with the host). Preserve the caller-saved
    // GPRs EmuCall does NOT (RAX/RCX/RDX/R8-R11) + eflags so glibc's post-syscall code resumes intact
    // (RBX/RDI/RSI/RBP/RSP/RIP are already saved/restored by EmuCall). FP/xmm are not preserved here; a
    // handler that changes control flow via longjmp isn't honored — both are follow-ups for wider programs.
    uint64_t s_rax=R_RAX, s_rcx=R_RCX, s_rdx=R_RDX, s_r8=R_R8, s_r9=R_R9, s_r10=R_R10, s_r11=R_R11;
    x64flags_t s_eflags = emu->eflags;
    int exits = 0;
    uint64_t hret;
    if(my_context->is_sigaction[sig]) {
        static __thread x64_siginfo_t  si_buf;
        static __thread x64_ucontext_t uc_buf;
        si_buf = info;
        memset(&uc_buf, 0, sizeof(uc_buf));
        emu2mctx(&uc_buf.uc_mcontext, emu);   // give an SA_SIGINFO handler a real mcontext to inspect
        hret = RunFunctionHandler(emu, &exits, 1, NULL, h, 3, (uint64_t)sig,
                                  (uint64_t)(uintptr_t)&si_buf, (uint64_t)(uintptr_t)&uc_buf);
    } else {
        hret = RunFunctionHandler(emu, &exits, 1, NULL, h, 1, (uint64_t)sig);
    }
    // box64-nx (M2.2c2): if the handler (or code it siglongjmp()'d into) ran the guest all the way to
    // exit()/exit_group(), the exit propagates here as emu->exit (=> *exits). We must terminate NOW —
    // returning would restore the pre-signal regs and resume the (already-exited) guest into garbage
    // (glibc then trips its stack canary -> "stack smashing detected"). hret carries the exit code.
    if(exits) {
        char b[64]; snprintf(b, sizeof b, "guest exited=%d (in signal handler)", (int)hret); nx_result_log(b);
        exit((int)hret);
    }
    R_RAX=s_rax; R_RCX=s_rcx; R_RDX=s_rdx; R_R8=s_r8; R_R9=s_r9; R_R10=s_r10; R_R11=s_r11;
    emu->eflags = s_eflags;
}

int my_kill(x64emu_t* emu, int pid, int sig)
{
    (void)pid;  // single guest process: any target resolves to "self"
    if(sig<0 || sig>MAX_SIGNAL) {
        errno = EINVAL;
        return -1;
    }
    if(sig==0)
        return 0;   // sig 0 is an existence probe; the (only) process exists
    nx_deliver_self(emu, sig);
    return 0;
}

int my_tgkill(x64emu_t* emu, int tgid, int tid, int sig)
{
    (void)tgid; (void)tid;
    if(sig<0 || sig>MAX_SIGNAL) {
        errno = EINVAL;
        return -1;
    }
    if(sig==0)
        return 0;
    nx_deliver_self(emu, sig);
    return 0;
}

int my_raise(x64emu_t* emu, int sig)
{
    if(sig<0 || sig>MAX_SIGNAL) {
        errno = EINVAL;
        return -1;
    }
    nx_deliver_self(emu, sig);
    return 0;
}

// ----- guest signal-disposition bookkeeping (recorded only; nothing armed on the host) -----
EXPORT sighandler_t my_signal(x64emu_t* emu, int signum, sighandler_t handler)
{
    if(signum<0 || signum>MAX_SIGNAL)
        return SIG_ERR;

    if(signum==X64_SIGSEGV && emu->context->no_sigsegv)
        return 0;

    sighandler_t old = (sighandler_t)my_context->signals[signum];
    // record the new handler (box64-nx: no host sigaction() — Horizon delivers no signals)
    my_context->signals[signum] = (uintptr_t)handler;
    my_context->is_sigaction[signum] = 0;
    my_context->restorer[signum] = 0;
    my_context->onstack[signum] = 0;
    return old;
}
EXPORT sighandler_t my___sysv_signal(x64emu_t* emu, int signum, sighandler_t handler) __attribute__((alias("my_signal")));
EXPORT sighandler_t my_sysv_signal(x64emu_t* emu, int signum, sighandler_t handler) __attribute__((alias("my_signal")));

EXPORT sighandler_t my_sigset(x64emu_t* emu, int signum, sighandler_t handler)
{
    // box64-nx: no host signal mask on Horizon, so the SIG_HOLD (handler==2) branch that
    // upstream implements with sigprocmask() is dropped; treat as a plain disposition set.
    return my_signal(emu, signum, handler);
}

int EXPORT my_sigaction(x64emu_t* emu, int signum, const x64_sigaction_t *act, x64_sigaction_t *oldact)
{
    printf_log(LOG_DEBUG, "Sigaction(signum=%d, act=%p(f=%p, flags=0x%x), old=%p)\n", signum, act, act?act->_u._sa_handler:NULL, act?act->sa_flags:0, oldact);
    if(signum<0 || signum>MAX_SIGNAL) {
        errno = EINVAL;
        return -1;
    }

    if(signum==X64_SIGSEGV && emu->context->no_sigsegv)
        return 0;

    if(signum==X64_SIGILL && emu->context->no_sigill)
        return 0;

    // snapshot the previous disposition for oldact
    uintptr_t old_handler = my_context->signals[signum];
    int old_is_sigaction = my_context->is_sigaction[signum];
    uintptr_t old_restorer = my_context->restorer[signum];
    int old_onstack = my_context->onstack[signum];

    if(act) {
        if(act->sa_flags&X64_SA_SIGINFO) {
            my_context->signals[signum] = (uintptr_t)act->_u._sa_sigaction;
            my_context->is_sigaction[signum] = 1;
        } else {
            my_context->signals[signum] = (uintptr_t)act->_u._sa_handler;
            my_context->is_sigaction[signum] = 0;
        }
        my_context->restorer[signum] = (act->sa_flags&X64_SA_RESTORER)?(uintptr_t)act->sa_restorer:0;
        my_context->onstack[signum] = (act->sa_flags&X64_SA_ONSTACK)?1:0;
    }
    if(oldact) {
        memset(oldact, 0, sizeof(*oldact));
        if(old_is_sigaction) {
            oldact->_u._sa_sigaction = (void*)old_handler;
            oldact->sa_flags = X64_SA_SIGINFO;
        } else {
            oldact->_u._sa_handler = (sighandler_t)old_handler;
            oldact->sa_flags = 0;
        }
        if(old_restorer) {
            oldact->sa_restorer = (void*)old_restorer;
            oldact->sa_flags |= X64_SA_RESTORER;
        }
        if(old_onstack)
            oldact->sa_flags |= X64_SA_ONSTACK;
    }
    return 0;
}
int EXPORT my___sigaction(x64emu_t* emu, int signum, const x64_sigaction_t *act, x64_sigaction_t *oldact)
__attribute__((alias("my_sigaction")));

int EXPORT my_syscall_rt_sigaction(x64emu_t* emu, int signum, const x64_sigaction_restorer_t *act, x64_sigaction_restorer_t *oldact, int sigsetsize)
{
    printf_log(LOG_DEBUG, "Syscall/Sigaction(signum=%d, act=%p, old=%p, size=%d)\n", signum, act, oldact, sigsetsize);
    if(signum<0 || signum>MAX_SIGNAL) {
        errno = EINVAL;
        return -1;
    }

    if(signum==X64_SIGSEGV && emu->context->no_sigsegv)
        return 0;

    // box64-nx: the upstream 32/33 "kernel sigaction via raw syscall" special case and the
    // libc-sigaction path both collapse to in-memory recording (no host signals on Horizon).
    uintptr_t old_handler = my_context->signals[signum];
    int old_is_sigaction = my_context->is_sigaction[signum];
    uintptr_t old_restorer = my_context->restorer[signum];
    int old_onstack = my_context->onstack[signum];

    if(act) {
        if(act->sa_flags&X64_SA_SIGINFO) {
            my_context->signals[signum] = (uintptr_t)act->_u._sa_sigaction;
            my_context->is_sigaction[signum] = 1;
        } else {
            my_context->signals[signum] = (uintptr_t)act->_u._sa_handler;
            my_context->is_sigaction[signum] = 0;
        }
        my_context->restorer[signum] = (act->sa_flags&X64_SA_RESTORER)?(uintptr_t)act->sa_restorer:0;
        my_context->onstack[signum] = (act->sa_flags&X64_SA_ONSTACK)?1:0;
    }
    if(oldact) {
        memset(oldact, 0, sizeof(*oldact));
        if(old_is_sigaction) {
            oldact->_u._sa_sigaction = (void*)old_handler;
            oldact->sa_flags = X64_SA_SIGINFO;
        } else {
            oldact->_u._sa_handler = (sighandler_t)old_handler;
            oldact->sa_flags = 0;
        }
        if(old_restorer) {
            oldact->sa_restorer = (void*)old_restorer;
            oldact->sa_flags |= X64_SA_RESTORER;
        }
        if(old_onstack)
            oldact->sa_flags |= X64_SA_ONSTACK;
    }
    return 0;
}

// ----- ucontext family (get/set/make/swapcontext); unused by static guests, kept as stubs -----
EXPORT int  my_getcontext(x64emu_t* emu, void* ucp) { (void)emu; (void)ucp; return 0; }
EXPORT int  my_setcontext(x64emu_t* emu, void* ucp) { (void)emu; (void)ucp; return 0; }
EXPORT void my_start_context(x64emu_t* emu) { (void)emu; }
EXPORT void my_makecontext(x64emu_t* emu, void* ucp, void* fnc, int32_t argc, int64_t* argv) {
    (void)emu; (void)ucp; (void)fnc; (void)argc; (void)argv;
}
EXPORT int  my_swapcontext(x64emu_t* emu, void* ucp1, void* ucp2) { (void)emu; (void)ucp1; (void)ucp2; return 0; }

void init_signal_helper(box64context_t* context)
{
    // box64-nx: no host signal handlers to install (Horizon delivers none). Just make sure the
    // guest dispositions start at SIG_DFL (context is box_calloc'd, so 0 already) and set up the
    // per-thread alternate-stack key so guest sigaltstack()/SA_ONSTACK works.
    for(int i=0; i<=MAX_SIGNAL; ++i)
        context->signals[i] = 0;    // SIG_DFL
    pthread_once(&sigstack_key_once, sigstack_key_alloc);
}

void fini_signal_helper(void) {}

// x86-64 and aarch64/newlib signal numbers coincide for the common signals; identity is fine
// (nothing is delivered to the host on Horizon). Referenced by wrappedlibc.c / threads.c.
int signal_from_x64(int sig) { return sig; }

#endif // __SWITCH__
