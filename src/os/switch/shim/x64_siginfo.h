// box64-nx shim — box64-private x86-64 siginfo_t.
//
// newlib's siginfo_t is the minimal 3-field POSIX form (si_signo/si_code/si_value)
// and LACKS si_errno and si_addr, so box64's signal-delivery core and the guest
// fault emitters can't use it: a guest x86-64 SA_SIGINFO handler expects the full
// 128-byte x86-64 kernel siginfo (si_errno at +4, _sigfault.si_addr at +16). This
// type reproduces that layout. Only the fields box64 touches are named; the rest is
// padding so the struct is a byte-accurate 128-byte x86-64 siginfo the guest parses.
#ifndef __NX_X64_SIGINFO_H__
#define __NX_X64_SIGINFO_H__
#ifdef __SWITCH__

#include <stddef.h>

typedef struct x64_siginfo_s {
    int si_signo;   // +0
    int si_errno;   // +4  (newlib's siginfo_t omits this)
    int si_code;    // +8
    // +12: 4 bytes of padding (the union below is 8-byte aligned because of si_addr)
    union {
        int   _pad[(128 / sizeof(int)) - 4]; // pad the whole struct to 128 bytes
        void* si_addr;                        // +16: _sifields._sigfault.si_addr
                                              // (SIGSEGV/SIGBUS/SIGILL/SIGFPE/SIGTRAP)
    };
} x64_siginfo_t;

#endif // __SWITCH__
#endif // __NX_X64_SIGINFO_H__
