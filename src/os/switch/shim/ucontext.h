// box64-nx shim — <ucontext.h> for the box64 Horizon port (newlib has none).
// Provides the Linux aarch64 mcontext_t/ucontext_t layout so box64's signal code compiles.
// Horizon delivers no POSIX signals, so this is layout-only; the handlers stay inert at runtime.
#pragma once
#ifdef __SWITCH__

#include <stdint.h>
#include <signal.h>
#include <stddef.h>

// Linux aarch64 sigcontext == mcontext_t
typedef struct sigcontext {
    uint64_t fault_address;
    uint64_t regs[31];
    uint64_t sp;
    uint64_t pc;
    uint64_t pstate;
    // fpsimd / SVE etc. live here on Linux; box64 reads them via casts into this buffer.
    uint8_t __reserved[4096] __attribute__((__aligned__(16)));
} mcontext_t;

typedef struct ucontext {
    unsigned long      uc_flags;
    struct ucontext   *uc_link;
    stack_t            uc_stack;
    sigset_t           uc_sigmask;
    mcontext_t         uc_mcontext;
} ucontext_t;

// The makecontext/swapcontext family is unsupported on Horizon (box64 doesn't need them for the
// interpreter path); declare for completeness.
int  getcontext(ucontext_t *ucp);
int  setcontext(const ucontext_t *ucp);
void makecontext(ucontext_t *ucp, void (*func)(void), int argc, ...);
int  swapcontext(ucontext_t *oucp, const ucontext_t *ucp);

#endif // __SWITCH__
