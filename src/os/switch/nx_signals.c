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
#include <stdatomic.h>
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
            // Prefer the hardware ESR.WnR bit (set by the async CPU-fault handler) for the write-bit —
            // exact for SSE2/AVX/POP stores x86 write_opcode() can't decode. -1 => self-delivered signal,
            // fall back to the x86 opcode decode.
            { extern __thread int kx_fault_wnr;
              int is_write = (kx_fault_wnr >= 0) ? kx_fault_wnr
                  : (write_opcode(sigcontext->uc_mcontext.gregs[X64_RIP], (uintptr_t)pc, (R_CS==0x23)) ? 1 : 0);
              if(is_write) sigcontext->uc_mcontext.gregs[X64_ERR] |= 2; }
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
#ifdef __SWITCH__
    // KX_DIAG-R (standing): which recovery path did Wine's segv_handler choose? Log old (faulting)
    // RIP/RSP vs the handler-set RIP/RSP. old==new (chg=0) => the line-2005 same-RIP loop
    // (virtual_handle_fault falsely returned SUCCESS); new = __wine_syscall_dispatcher_return =>
    // clean syscall-status recovery; new = KiUserExceptionDispatcher => user-mode exception dispatch
    // (is_inside_syscall returned FALSE). A known nRIP function entry also anchors the ntdll base.
    { extern void nx_result_log(const char*); static int on=-1; if(on<0) on=getenv("KX_EXC_LOG")?1:0;
      if(on) { int chg = memcmp(sigcontext,&sigcontext_copy,sizeof(x64_ucontext_t))?1:0; char b[240];
        // far = si_addr distinguishes the failing WRITE (0xdeadbee0) from the recovering READ (0xdeadbef7)
        // faults; err = the DELIVERED ERR (bit1 = write) box64 handed Wine (pre-handler snapshot). Wine's
        // is_inside_syscall is RSP-only, so oRSP is the decider — compare WRITE vs READ oRSP.
        int n=snprintf(b,sizeof b,"nx_recov: far=0x%llx err=0x%llx chg=%d oRIP=0x%llx nRIP=0x%llx oRSP=0x%llx nRSP=0x%llx",
          (unsigned long long)(uintptr_t)info2->si_addr,
          (unsigned long long)sigcontext_copy.uc_mcontext.gregs[X64_ERR], chg,
          (unsigned long long)sigcontext_copy.uc_mcontext.gregs[X64_RIP],
          (unsigned long long)sigcontext->uc_mcontext.gregs[X64_RIP],
          (unsigned long long)sigcontext_copy.uc_mcontext.gregs[X64_RSP],
          (unsigned long long)sigcontext->uc_mcontext.gregs[X64_RSP]);
        if(n>0) nx_result_log(b);
        // KX_DIAG-RECFLAGS (standing): when the guest handler set up KiUserExceptionDispatcher (chg=1),
        // Wine's setup_raise_exception placed a stack_layout at the new RSP: {CONTEXT; CONTEXT_EX;
        // EXCEPTION_RECORD; ...}. Scan the low part of that frame for the EXCEPTION_RECORD (ExceptionCode
        // 0xCxxxxxxx) and dump its ExceptionFlags — the ntdll:exception 0xC0000025 fingerprint is
        // EH_NONCONTINUABLE(bit0) set on a rec that dreg_handler "continues". flags=0 here => the
        // noncontinuable bit is introduced LATER in guest dispatch (an emulation-fidelity bug); flags!=0 =>
        // box64 delivered / Wine built the record noncontinuable at the source.
        if(chg) {
            static __thread int rf_n = 0;
            uintptr_t nrsp = (uintptr_t)sigcontext->uc_mcontext.gregs[X64_RSP];
            if(rf_n < 4 && nrsp && getProtection(nrsp)) {
                for(int off=0x400; off<=0x520; off+=8) {
                    if(!getProtection(nrsp+off)) break;
                    uint32_t code  = *(volatile uint32_t*)(nrsp+off);
                    uint32_t flags = *(volatile uint32_t*)(nrsp+off+4);
                    if((code & 0xF0000000u) == 0xC0000000u) {
                        char rb[176];
                        snprintf(rb, sizeof rb, "nx_recflags: nRSP=0x%llx off=0x%x code=0x%x flags=0x%x nparam=0x%x info0=0x%llx",
                            (unsigned long long)nrsp, off, code, flags,
                            *(volatile uint32_t*)(nrsp+off+24),
                            (unsigned long long)*(volatile uint64_t*)(nrsp+off+32));
                        nx_result_log(rb); rf_n++; break;
                    }
                }
            }
        }
    } }
#endif
    if(memcmp(sigcontext, &sigcontext_copy, sizeof(x64_ucontext_t))) {
        // The guest handler CHANGED the context => it resolved this fault (syscall-status recovery to
        // __wine_syscall_dispatcher_return, or KiUserExceptionDispatcher, or a longjmp target) and the
        // guest is now progressing elsewhere. Bump a per-thread progress counter so the exception
        // handler's same-fault loop guard resets: a finite guest loop of syscall-boundary bad-pointer
        // faults (e.g. om.c:149's NtCreateNamedPipeFile bad handle ptr -> Wine recovers each) re-faults
        // at one identical (far,rip) but is PROGRESS, not a stuck box64 delivery. Only a no-recovery
        // re-fault (chg=0, box64 re-running the same insn) must trip the guard.
        { extern __thread uint32_t kx_recov_seq; kx_recov_seq++; }
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
extern int nx_gettid(void);
extern int nx_guest_pid(void);
static void nx_deliver_self(x64emu_t* emu, int sig)
{
    if(!emu)
        emu = thread_get_emu();
    if(sig<=0 || sig>MAX_SIGNAL)
        return;
    // Not a CPU fault — clear any stale ESR.WnR so the delivery core's write-bit uses write_opcode().
    { extern __thread int kx_fault_wnr; kx_fault_wnr = -1; }
    uintptr_t h = my_context->signals[sig];
    { static int siglog = -1; if (siglog < 0) siglog = getenv("KX_SIGLOG") ? 1 : 0;
      if (siglog) {
          // tid/gpid/FS identify WHICH thread is about to run the handler, and FS is what the guest's
          // own pthread_getspecific() reads — the two facts needed when a handler finds its TLS empty.
          printf_log(LOG_NONE, "nx_sig: deliver self sig=%d tid=%d gpid=%d fs=0x%lx rip=%p handler=0x%lx\n",
                     sig, nx_gettid(), nx_guest_pid(), (unsigned long)emu->segs_offs[_FS],
                     (void*)R_RIP, (unsigned long)h);
          if (sig == 6) {   // SIGABRT (abort/stack-smash): dump the guest stack so the smashed frame's
              uintptr_t rsp = R_RSP;   // return-address chain (raise<-abort<-__fortify_fail<-smashed) is visible
              uintptr_t fsb = emu->segs_offs[_FS], gsb = emu->segs_offs[_GS];
              // false-positive-canary test: the glibc master canary lives at %fs:0x28. If it differs from
              // the on-stack copy, the smash is a %fs-base/canary corruption, not a real buffer overflow.
              uint64_t master = fsb ? *(volatile uint64_t*)(fsb + 0x28) : 0;
              printf_log(LOG_NONE, "nx_sig: fsbase=0x%lx gsbase=0x%lx master_canary=0x%lx\n",
                         (unsigned long)fsb, (unsigned long)gsb, (unsigned long)master);
              for (int qi = 0; qi < 128; qi++) {
                  uint64_t val = *(volatile uint64_t*)(rsp + (uintptr_t)qi * 8);
                  // flag code addresses in the test-exe (0x1.4xxx) / low-VA PE (0x0.bxxx-0x0.exxx) ranges
                  const char* tag = "";
                  if (val >= 0x140000000ULL && val < 0x141000000ULL) tag = " <TESTEXE>";
                  else if (val >= 0x0b000000ULL && val < 0x10000000ULL) tag = " <PE-lowva>";
                  printf_log(LOG_NONE, "nx_sig: stk +0x%03x = 0x%lx%s\n", qi * 8, (unsigned long)val, tag);
              }
          }
      } }
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
    // box64-nx: a real kernel sigframe ALSO preserves the guest's SSE state, not just the GPRs above —
    // the handler runs on this emu in-place (RunFunctionHandler), and glibc/Wine use SSE heavily
    // (memcpy / strlen / string ops), so a handler that clobbers xmm/ymm/mxcsr corrupts the interrupted
    // code when it resumes. DEFAULT-ON since 2026-07-18, PROVEN by tests/m2/xmmsig.c (kurokonx): without
    // the save, a clobbering handler returns ALL 16 xmm as garbage and leaks mxcsr (exit 50); with it,
    // exit 42 — a real kernel always preserves. (Historically added speculatively for the ntdll:directory
    // stack-smash, which it did NOT fix — kept for correctness, not as that fix.) KX_NO_XMM_SAVE=1
    // restores the old GPR-only delivery for A/B. x87 is not preserved either way (rare in
    // signal-interruptible paths).
    static int xmm_save = -1;
    if (xmm_save < 0) xmm_save = getenv("KX_NO_XMM_SAVE") ? 0 : 1;
    sse_regs_t s_xmm[16], s_ymm[16]; mmxcontrol_t s_mxcsr;
    if (xmm_save) {
        memcpy(s_xmm, emu->xmm, sizeof(s_xmm));
        memcpy(s_ymm, emu->ymm, sizeof(s_ymm));
        s_mxcsr = emu->mxcsr;
    }
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
    if (xmm_save) {
        memcpy(emu->xmm, s_xmm, sizeof(s_xmm));
        memcpy(emu->ymm, s_ymm, sizeof(s_ymm));
        emu->mxcsr = s_mxcsr;
    }
    R_RAX=s_rax; R_RCX=s_rcx; R_RDX=s_rdx; R_R8=s_r8; R_R9=s_r9; R_R10=s_r10; R_R11=s_r11;
    emu->eflags = s_eflags;
}

// ---- directed (cross-thread) signal delivery -----------------------------------------------------
//
// tkill/tgkill name a SPECIFIC thread, and Wine relies on that: send_thread_signal() is how
// NtSuspendThread and NtGetContextThread interrupt another thread. Delivering on the CALLER instead
// (which is what this did before 2026-07-27) runs the handler on the wrong thread, where Wine's
// NtCurrentTeb() — pthread_getspecific(teb_key), not a segment register — returns NULL, and the
// handler dereferences it (crash at ntdll.so+0x420b7; it blocked the whole ws2_32 rung).
//
// A signal must run on the TARGET's own emu/TCB/stack, so it cannot be delivered by the sender.
// Instead the sender queues it and the target runs it at its next safe point (nx_signal_check_pending,
// called from the syscall boundary and from the blocking wait loops). That is cooperative rather than
// preemptive: a target spinning in pure guest code with no syscalls will not notice. Wine's threads
// are constantly in server round-trips and futex waits, so in practice the latency is one syscall.
enum { NX_SIGTHREAD_MAX = 256 };
typedef struct {
    _Atomic int      tid;      // 0 = free slot
    int              gpid;     // guest instance (client vs the in-process wineserver)
    x64emu_t*        emu;
    _Atomic uint64_t pending;  // bit (sig-1) set by ANOTHER thread
} nx_sigthread_t;
static nx_sigthread_t g_sigthreads[NX_SIGTHREAD_MAX];

extern int nx_gettid(void);
extern int nx_guest_pid(void);

// Registration is LAZY — done on this thread's first syscall (nx_signal_check_pending), not at thread
// start. That is not a shortcut, it is the only ordering that works: `thread_set_emu()` runs inside
// box64's clone_fn_syscall, i.e. AFTER the clone trampoline would have registered, so a register call
// there always saw a NULL emu and silently did nothing. Registering off the emu the syscall dispatcher
// already hands us removes the dependency entirely.
//
// Getting this wrong is not benign: an unregistered thread makes nx_signal_queue return ESRCH, and
// Wine's server/ptrace.c latches `unix_tid = -1` on ESRCH — permanently marking the thread dead, after
// which it silently drops that thread's APCs and suspends instead of erroring.
void nx_sigthread_register(x64emu_t* emu)
{
    if (!emu) return;
    int tid = nx_gettid(), gpid = nx_guest_pid();
    // Pass 1: already registered? (A second slot for the same thread would leak — every lookup takes
    // the first match, so unregister would free the new one and strand the old.)
    for (int i = 0; i < NX_SIGTHREAD_MAX; i++)
        if (atomic_load(&g_sigthreads[i].tid) == tid && g_sigthreads[i].gpid == gpid) {
            g_sigthreads[i].emu = emu;
            return;
        }
    // Pass 2: claim a free slot. Fill gpid/emu/pending BEFORE publishing tid — tid is what a sender
    // matches on, so publishing it first lets a concurrent nx_signal_queue match this slot while still
    // reading the previous occupant's gpid.
    for (int i = 0; i < NX_SIGTHREAD_MAX; i++) {
        if (atomic_load(&g_sigthreads[i].tid) != 0) continue;
        g_sigthreads[i].gpid = gpid;
        g_sigthreads[i].emu  = emu;
        atomic_store(&g_sigthreads[i].pending, 0);
        int expected = 0;
        if (atomic_compare_exchange_strong(&g_sigthreads[i].tid, &expected, tid))
            return;
    }
    printf_log(LOG_NONE, "nx_sig: thread registry FULL (%d) — tid=%d gpid=%d will look dead to senders\n",
               NX_SIGTHREAD_MAX, tid, gpid);
}

void nx_sigthread_unregister(void)
{
    int tid = nx_gettid(), gpid = nx_guest_pid();
    for (int i = 0; i < NX_SIGTHREAD_MAX; i++)
        if (atomic_load(&g_sigthreads[i].tid) == tid && g_sigthreads[i].gpid == gpid) {
            g_sigthreads[i].emu = NULL;
            atomic_store(&g_sigthreads[i].pending, 0);
            atomic_store(&g_sigthreads[i].tid, 0);
            return;
        }
}

// Queue `sig` on another thread. Returns 0, or -1/ESRCH if that thread is not (or no longer) live.
// `gpid` selects the guest INSTANCE: the wineserver signals the client's threads, and both instances
// number their main thread 1, so the tid alone is ambiguous.
static int nx_signal_queue(int gpid, int tid, int sig)
{
    for (int i = 0; i < NX_SIGTHREAD_MAX; i++) {
        if (atomic_load(&g_sigthreads[i].tid) != tid || g_sigthreads[i].gpid != gpid) continue;
        atomic_fetch_or(&g_sigthreads[i].pending, 1ULL << (sig - 1));
        // Wake it if it is parked in a vfd wait (pipe/socketpair/poll/select). A futex wait is woken
        // by whoever owns that futex; a target in pure guest code notices at its next syscall.
        { extern void nx_vfd_wake_all(void); nx_vfd_wake_all(); }
        return 0;
    }
    errno = ESRCH;
    return -1;
}

// Safe point: run any signal another thread queued for us, on OUR emu. Cheap when idle (one relaxed
// atomic load), so it can sit on the syscall boundary.
// Cheap "is a directed signal waiting for me?" probe, so a blocking wait can decide whether to drop
// its lock and deliver. One atomic load in the common (nothing pending) case.
int nx_signal_pending_self(void)
{
    int tid = nx_gettid(), gpid = nx_guest_pid();
    for (int i = 0; i < NX_SIGTHREAD_MAX; i++)
        if (atomic_load(&g_sigthreads[i].tid) == tid && g_sigthreads[i].gpid == gpid)
            return atomic_load(&g_sigthreads[i].pending) != 0;
    return 0;
}

static __thread int g_sigthread_registered = 0;

// Syscall boundary: REGISTRATION ONLY. Deliberately does not deliver.
//
// Running a queued handler here is what deadlocked ws2_32:afd. A Wine signal handler
// (usr1_handler -> wait_suspend) does a full wineserver round-trip, and the syscall boundary is
// exactly where the thread may already have a request IN FLIGHT — it has written a request and not
// yet read its reply. Injecting a nested request there desynchronises the strictly-paired
// request/reply protocol, and the client then blocks forever on a reply that no longer matches.
// Measured: the client parked in `nx_vfd: RDBLK … n=16` while the wineserver ran on happily for
// another 23 s (its registry save is a red herring — the client froze first).
//
// Delivery happens in nx_signal_deliver_pending() instead, called from the BLOCKING WAITS, which is
// where a real kernel would interrupt the thread and where Wine's design expects a suspend signal to
// land: parked, with no half-finished request outstanding.
void nx_signal_check_pending(x64emu_t* emu)
{
    if (!g_sigthread_registered) {          // first syscall on this thread: join the registry
        if (!emu) return;
        nx_sigthread_register(emu);
        g_sigthread_registered = 1;
    }
}

// Run whatever another thread queued for us. MUST be called with no subsystem lock held (the handler
// re-enters the vfd layer for its server round-trip), and only from a point where the guest has no
// half-completed operation outstanding — i.e. from inside a blocking wait.
// Returns 1 if a handler actually ran, 0 otherwise — the caller uses that to decide whether to
// interrupt its wait, so it must NOT report an interruption it did not cause.
//
// Delivery is OPT-IN (KX_SIG_DIRECTED=1), and Wine's own source says why rather than just
// measurement. The SIGUSR1 the wineserver sends a client thread comes from queue_apc()
// (server/thread.c): it is sent only when the target is NOT already in an interruptible server wait
// (`!is_in_apc_wait`), and the server calls wake_thread() immediately afterwards either way. So for a
// thread parked in a server wait — which is every thread we can actually reach — the WAKEUP already
// does the work and the signal is redundant belt-and-braces for a thread spinning in guest code.
//
// Running it anyway is not merely unnecessary, it is harmful: usr1_handler -> wait_suspend() issues
// its own server_select and blocks for a resume, and a per-thread server connection carries one
// request at a time. Delivering while the thread has a request in flight puts two on the wire and
// both sides wait forever. A/B-proven on one binary: delivery off -> ws2_32:afd 1187 tests / 75
// failures; delivery on -> hang at afd.c:131, identically for all three delivery points tried
// (syscall boundary, inside-the-wait-then-resume, inside-the-wait-then-EINTR).
//
// The machinery itself is correct and exercised — with the gate on, 5 queued / 5 delivered / 0 ESRCH
// — so it is here for a guest that genuinely needs directed signals, and for the day box64-nx can
// interrupt a guest thread asynchronously (the real gap: a kernel signals at an arbitrary
// instruction, we can only act at points we choose, and every point we can choose is "request in
// flight").
int nx_signal_deliver_pending(void)
{
    static int deliver = -1;
    if (deliver < 0) deliver = getenv("KX_SIG_DIRECTED") ? 1 : 0;
    x64emu_t* emu = NULL;
    int ran = 0;
    int tid = nx_gettid(), gpid = nx_guest_pid();
    for (int i = 0; i < NX_SIGTHREAD_MAX; i++) {
        if (atomic_load(&g_sigthreads[i].tid) != tid || g_sigthreads[i].gpid != gpid) continue;
        uint64_t bits = atomic_exchange(&g_sigthreads[i].pending, 0);
        if (!bits) return 0;
        if (!deliver) {
            static int warned = 0;
            if (!warned) { warned = 1;
                printf_log(LOG_NONE, "nx_sig: queued 0x%llx for tid=%d gpid=%d NOT delivered "
                           "(KX_SIG_DIRECTED=1 to enable; the server's wake_thread covers it)\n",
                           (unsigned long long)bits, tid, gpid); }
            return 0;
        }
        // Never fall back to thread_get_emu(): on a thread without one it ALLOCATES a fresh emu on a
        // small scratch stack and would run the guest handler there. Dropping the signal is bad;
        // running it on a synthetic emu is worse.
        if (!emu) emu = g_sigthreads[i].emu;
        if (!emu) {
            printf_log(LOG_NONE, "nx_sig: pending 0x%llx for tid=%d gpid=%d but no emu — dropped\n",
                       (unsigned long long)bits, tid, gpid);
            return 0;
        }
        for (int sig = 1; sig <= MAX_SIGNAL && bits; sig++)
            if (bits & (1ULL << (sig - 1))) {
                bits &= ~(1ULL << (sig - 1));
                // A QUEUED signal with no handler is dropped, not acted on. nx_deliver_self treats
                // SIG_DFL as "terminate" and abort()s — correct for a synchronous raise(), but for a
                // directed signal that would tear down the whole Horizon process (both guest
                // instances) from an arbitrary thread at an arbitrary syscall boundary. In practice a
                // queued signal with no handler means OUR plumbing aimed it wrong, and killing
                // everything makes that undebuggable.
                uintptr_t disposition = my_context->signals[sig];
                if (disposition == 0 || disposition == 1) {
                    static int warned[MAX_SIGNAL + 1];
                    if (!warned[sig]) {
                        warned[sig] = 1;
                        printf_log(LOG_NONE, "nx_sig: queued sig=%d for tid=%d gpid=%d has %s — dropped\n",
                                   sig, tid, gpid, disposition ? "SIG_IGN" : "SIG_DFL");
                    }
                    continue;
                }
                nx_deliver_self(emu, sig);
                ran = 1;
            }
        return ran;
    }
    return 0;
}

int my_kill(x64emu_t* emu, int pid, int sig)
{
    (void)pid;  // single guest process: any target resolves to "self"
    { static int sl=-1; if(sl<0) sl=getenv("KX_SIGLOG")?1:0;
      if(sl) printf_log(LOG_NONE, "nx_sig: kill(pid=%d,sig=%d) from tid=%d gpid=%d\n", pid, sig, nx_gettid(), nx_guest_pid()); }
    if(sig<0 || sig>MAX_SIGNAL) {
        errno = EINVAL;
        return -1;
    }
    if(sig==0)
        return 0;   // sig 0 is an existence probe; the (only) process exists
    nx_deliver_self(emu, sig);
    return 0;
}

// tkill(tid, sig) — no thread group in the call, so the target is in the CALLER's instance.
int my_tkill(x64emu_t* emu, int tid, int sig)
{
    return my_tgkill(emu, nx_guest_pid(), tid, sig);
}

int my_tgkill(x64emu_t* emu, int tgid, int tid, int sig)
{
    if(sig<0 || sig>MAX_SIGNAL) {
        errno = EINVAL;
        return -1;
    }
    static int siglog = -1;
    if (siglog < 0) siglog = getenv("KX_SIGLOG") ? 1 : 0;
    if (siglog) printf_log(LOG_NONE, "nx_sig: tgkill(tgid=%d,tid=%d,sig=%d) from tid=%d gpid=%d\n",
                           tgid, tid, sig, nx_gettid(), nx_guest_pid());
    if(sig==0)
        return 0;
    // tgid selects the guest INSTANCE, and it is load-bearing rather than decoration: the in-process
    // wineserver (gpid 2) signals the CLIENT's threads (gpid 100) with
    // tgkill(thread->unix_pid, thread->unix_tid, sig), and BOTH instances number their main thread 1.
    // Matching on tid alone made the wineserver deliver to ITSELF and run the client's ntdll handler,
    // where Wine's NtCurrentTeb() is legitimately NULL — the crash that blocked the whole ws2_32 rung.
    if(tgid <= 0) tgid = nx_guest_pid();
    // Self stays SYNCHRONOUS: glibc raise() is tgkill(getpid(), gettid(), sig) and its callers expect
    // the handler to have run by the time it returns.
    if(tid <= 0 || (tgid == nx_guest_pid() && tid == nx_gettid())) {
        nx_deliver_self(emu, sig);
        return 0;
    }
    if (siglog) printf_log(LOG_NONE, "nx_sig: queue sig=%d for gpid=%d tid=%d (from gpid=%d tid=%d)\n",
                           sig, tgid, tid, nx_guest_pid(), nx_gettid());
    if(nx_signal_queue(tgid, tid, sig) < 0) {
        // No such live thread. ESRCH is the honest answer and is what Wine checks for when a thread
        // has already exited — do NOT fall back to self-delivery, which is the bug this replaced.
        if (siglog) printf_log(LOG_NONE, "nx_sig: gpid=%d tid=%d not live -> ESRCH\n", tgid, tid);
        return -1;
    }
    return 0;
}

int my_raise(x64emu_t* emu, int sig)
{
    { static int sl=-1; if(sl<0) sl=getenv("KX_SIGLOG")?1:0;
      if(sl) printf_log(LOG_NONE, "nx_sig: raise(sig=%d) from tid=%d gpid=%d\n", sig, nx_gettid(), nx_guest_pid()); }
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
