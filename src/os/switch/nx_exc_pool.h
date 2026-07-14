// box64-nx — per-fault exception {dump, stack} slot pool (M2.6 concurrent-fault hardening).
//
// libnx's weak __libnx_exception_entry funnels EVERY faulting thread through one process-global
// ThreadExceptionDump (__nx_exceptiondump) and one exception stack — two simultaneous faults (32-way
// concurrent SMC, tests/m2/stress.c -DSTRESS_SMC) corrupt each other's dump and stack. Our strong
// override (nx_exception_entry.S) instead claims one slot per in-flight fault from the static pool
// defined in nx_exception.c. This header carries the constants shared between the .S and the C side
// (the nx_resume.h pattern: the .S includes it through cpp).
//
// Slot lifecycle (the invariant is documented at the pool definition in nx_exception.c): claimed by
// the entry asm (ldaxr/stlxr on kx_exc_owner[i]), released ONLY at the three safe sites — the
// handler-entry SP-chain prune, the nx_resume.S tail stlr, and nx_exc_thread_exit(). NEVER release a
// slot before a siglongjmp: the longjmp tail still executes on the slot's stack and a concurrent
// claimant would start writing handler frames over the live frames.
#ifndef __NX_EXC_POOL_H__
#define __NX_EXC_POOL_H__

// Pool size: stress = 32 guest workers + main = 33 steady holders (each thread that ever faulted
// keeps its top slot until its next fault entry or thread exit) + concurrency/nesting transients.
#define KX_EXC_NSLOTS   48
// Per-slot handler stack. 64 KiB matches the proven pre-M2.6 single-stack size (the fault path
// re-enters the dynarec via DynaCall to run guest signal handlers). 48 x 64 KiB = 3 MiB .bss.
#define KX_EXC_STKSZ    0x10000
// sizeof(ThreadExceptionDump) = 0x338, rounded up to 16 (static-asserted in nx_exception.c).
#define KX_EXC_DUMPSZ   0x340
// Per-thread nested-fault cap (a guest signal handler faulting during delivery stacks another slot).
#define KX_EXC_MAXDEPTH 8

#endif // __NX_EXC_POOL_H__
