// box64 Horizon port — guest fault/interrupt emitters (box64-nx).
//
// These are the SYNCHRONOUS side of x86 signal emulation: when the x86 engine itself
// decides the guest hit a fault (#GP, non-executable page, INT n, divide-by-zero, #UD,
// #BR, ...), it builds a minimal x86-64 siginfo and hands it to the shared delivery core
// (my_sigactionhandler_oldcode) which runs the guest's own handler on the guest stack.
//
// Ported from src/os/emit_signals_linux.c. Differences from upstream (all "box64-nx:"):
//   * siginfo_t -> x64_siginfo_t (newlib's siginfo_t lacks si_errno/si_addr).
//   * No host signal / host backtrace / native-BT diagnostics (Horizon has none); the
//     verbose pre-delivery dump is reduced to a single showsegv/LOG_INFO line.
#ifdef __SWITCH__

#include <stdint.h>
#include <string.h>

#include "emit_signals.h"
#include "x64_signals.h"
#include "os.h"          // PROT_EXEC/PROT_READ (box64's own defines)
#include "box64context.h"
#include "custommem.h"
#include "debug.h"
#include "emu/x64emu_private.h"
#include "emu/x87emu_private.h"
#include "x64emu.h"
#include "signals.h"
#include "env.h"
#include "libtools/signal_private.h"

// x86-64 si_code the delivery core keys off (newlib's SEGV_ACCERR may differ).
#define X64_SEGV_ACCERR  2

void my_sigactionhandler_oldcode(x64emu_t* emu, int32_t sig, int simple, x64_siginfo_t* info, void * ucntx, int* old_code, void* cur_db, uintptr_t x64pc);

void EmitSignal(x64emu_t* emu, int sig, void* addr, int code)
{
    x64_siginfo_t info = { 0 };
    info.si_signo = sig;
    info.si_errno = (sig == X64_SIGSEGV) ? 0x1234 : 0; // Mark as a sign this is a #GP(0) (like privileged instruction)
    info.si_code = code;
    if (sig == X64_SIGSEGV && code == 0xbad0) {
        info.si_errno = 0xbad0;
        info.si_code = 0;
    } else if (sig == X64_SIGSEGV && code == 0xecec) {
        info.si_errno = 0xecec;
        info.si_code = X64_SEGV_ACCERR;
    } else if (sig == X64_SIGSEGV && code == 0xb09d) {
        info.si_errno = 0xb09d;
        info.si_code = 0;
    }
    info.si_addr = addr;
    // box64-nx: no native backtrace / /proc maps on Horizon — one concise line under showsegv.
    if (BOX64ENV(log) > LOG_INFO || BOX64ENV(showsegv)) {
        printf_log(LOG_NONE, "%04d|Emit Signal %d at IP=%p / addr=%p, code=0x%x\n", GetTID(), sig, (void*)R_RIP, addr, code);
    }
    my_sigactionhandler_oldcode(emu, sig, 0, &info, NULL, NULL, NULL, R_RIP);
}

void CheckExec(x64emu_t* emu, uintptr_t addr)
{
    if (box64_pagesize != 4096)
        return; // disabling the test, 4K pagesize simlation isn't good enough for this
    while ((getProtection/*_fast*/(addr) & (PROT_EXEC | PROT_READ)) != (PROT_EXEC | PROT_READ)) {
        R_RIP = addr; // incase there is a slight difference
        EmitSignal(emu, X64_SIGSEGV, (void*)addr, 0xecec);
    }
}

void EmitInterruption(x64emu_t* emu, int num, void* addr)
{
    x64_siginfo_t info = { 0 };
    info.si_signo = X64_SIGSEGV;
    info.si_errno = 0xdead;
    info.si_code = num;
    info.si_addr = NULL; // addr;
    if (BOX64ENV(log) > LOG_INFO || BOX64ENV(showsegv)) {
        printf_log(LOG_NONE, "Emit Interruption 0x%x at IP=%p / addr=%p\n", num, (void*)R_RIP, addr);
    }
    my_sigactionhandler_oldcode(emu, X64_SIGSEGV, 0, &info, NULL, NULL, NULL, R_RIP);
}

void EmitDiv0(x64emu_t* emu, void* addr, int code)
{
    x64_siginfo_t info = { 0 };
    info.si_signo = X64_SIGSEGV;
    info.si_errno = 0xcafe;
    info.si_code = code;
    info.si_addr = addr;
    if (BOX64ENV(log) > LOG_INFO || BOX64ENV(showsegv)) {
        printf_log(LOG_NONE, "Emit Divide by 0 at IP=%p / addr=%p\n", (void*)R_RIP, addr);
    }
    my_sigactionhandler_oldcode(emu, X64_SIGSEGV, 0, &info, NULL, NULL, NULL, R_RIP);
}

// box64-nx: Wine INT emulation (32bit sigframe path) is not needed for the current guests;
// keep it a loud no-op until Wine is on the table.
void EmitWineInt(x64emu_t* emu, int num, void* addr)
{
    (void)emu;
    printf_log(LOG_NONE, "[switch] EmitWineInt %d at %p (unhandled)\n", num, addr);
}

#endif // __SWITCH__
