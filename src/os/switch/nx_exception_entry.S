// box64-nx — STRONG __libnx_exception_entry override (M2.6 concurrent-fault hardening).
//
// Horizon delivers a userspace CPU exception by re-entering the process at its entrypoint with
// x0 = exception type (non-zero) and x1 = &ThreadExceptionFrameA64 (libnx switch_crt0.s dispatches
// here). libnx's own weak entry (nx/source/runtime/exception.s) fills ONE process-global dump and
// points the resumed thread at ONE global stack — concurrent faults corrupt each other. This strong
// override replaces it: each fault atomically claims a {dump, stack} slot from the pool defined in
// nx_exception.c, so 32 threads can fault simultaneously. With this entry linked, libnx exception.o
// (and its __nx_exceptiondump/__libnx_exception_returnentry) is never pulled from the archive; we
// provide our own trampoline (__kx_exception_returnentry).
//
// Parity note vs libnx: we DROP its svcGetInfo(IsCurrentProcessBeingDebugged) check — box64 always
// shipped __nx_exception_ignoredebug=1, which made that check dead at runtime; dropping it also makes
// the entry stack-free (libnx only used the interrupted SP to spill regs around that SVC).
//
// Exception-entry register contract (verified against libnx exception.s):
//   x0 = exception type -> dump error_desc        x1 = frame ptr (fields read THEN rewritten in place)
//   frame holds the real x0..x8, lr, sp, elr, pstate/afsr/esr/far; x9..x28, x29 and q0..q31 are the
//   faulting thread's LIVE registers and must not be touched until dumped. Scratch: x2..x8, x30.
// The frame is rewritten so svcReturnFromException(0) ERETs the faulting thread onto the slot stack
// at __kx_exception_returnentry with x0 = &slot dump; the dump records the ORIGINAL x0/sp/pc.
// svcReturnFromException(0xf801) = "unhandled": kernel default handling -> creport (the bounded
// degradation for a NULL frame or an exhausted pool — never a hang).
#ifdef __SWITCH__

#include "nx_exc_pool.h"

	.text
	.balign 4
	.global __libnx_exception_entry
	.type __libnx_exception_entry, %function
__libnx_exception_entry:
	cbz	x1, .Labort		// no frame -> not handled

	// KX_EXC_SINGLE legacy A/B gate: slot 0 unconditionally, no claim (old single-slot semantics).
	adrp	x2, kx_exc_single
	ldr	w3, [x2, #:lo12:kx_exc_single]
	adrp	x2, kx_exc_owner
	add	x2, x2, #:lo12:kx_exc_owner
	mov	w4, wzr			// w4 = slot index
	cbnz	w3, .Lclaimed

	// Atomic slot claim: first kx_exc_owner[i]==0 -> 1 (acquire/release exclusives). All busy -> abort.
.Lclaim_next:
	add	x5, x2, w4, uxtw #2	// &kx_exc_owner[w4]
1:	ldaxr	w6, [x5]
	cbnz	w6, 2f			// slot busy -> try the next one
	mov	w6, #1
	stlxr	w7, w6, [x5]
	cbnz	w7, 1b			// lost the exclusive -> retry this slot
	b	.Lclaimed
2:	clrex
	add	w4, w4, #1
	cmp	w4, #KX_EXC_NSLOTS
	b.lo	.Lclaim_next
	b	.Labort			// pool exhausted -> creport (self-healing degradation)

.Lclaimed:
	// x3 = &kx_exc_dumps[idx], x4 = slot stack TOP = &kx_exc_stacks[idx+1]
	adrp	x3, kx_exc_dumps
	add	x3, x3, #:lo12:kx_exc_dumps
	mov	w5, #KX_EXC_DUMPSZ
	umaddl	x3, w4, w5, x3
	adrp	x5, kx_exc_stacks
	add	x5, x5, #:lo12:kx_exc_stacks
	add	w6, w4, #1
	mov	w7, #KX_EXC_STKSZ
	umaddl	x4, w6, w7, x5

	// Fill the dump (ThreadExceptionDump layout) with x2 as the write cursor, mirroring libnx's
	// read-original-then-rewrite sequence for the three frame fields that get redirected.
	mov	x2, x3
	str	w0, [x2], #4		// error_desc = exception type
	str	wzr, [x2], #4		// pad[3]
	str	wzr, [x2], #4
	str	wzr, [x2], #4
	// cpu_gprs[0..8] from the frame; frame.x0 := &dump (what the trampoline hands the C handler)
	ldp	x5, x6, [x1]
	str	x3, [x1]
	stp	x5, x6, [x2], #16
	ldp	x5, x6, [x1, #16]
	stp	x5, x6, [x2], #16
	ldp	x5, x6, [x1, #32]
	stp	x5, x6, [x2], #16
	ldp	x5, x6, [x1, #48]
	stp	x5, x6, [x2], #16
	ldr	x5, [x1, #64]
	str	x5, [x2], #8
	// cpu_gprs[9..28] + fp: the LIVE faulting-thread registers
	str	x9, [x2], #8
	stp	x10, x11, [x2], #16
	stp	x12, x13, [x2], #16
	stp	x14, x15, [x2], #16
	stp	x16, x17, [x2], #16
	stp	x18, x19, [x2], #16
	stp	x20, x21, [x2], #16
	stp	x22, x23, [x2], #16
	stp	x24, x25, [x2], #16
	stp	x26, x27, [x2], #16
	str	x28, [x2], #8
	str	x29, [x2], #8		// fp
	// lr from the frame (authoritative — live x30 is scratch on this path)
	ldr	x5, [x1, #72]
	str	x5, [x2], #8
	// sp: dump the ORIGINAL, frame.sp := slot stack top
	ldr	x5, [x1, #80]
	str	x4, [x1, #80]
	str	x5, [x2], #8
	// pc (elr_el1): dump the ORIGINAL, frame.elr := our trampoline
	ldr	x5, [x1, #88]
	adrp	x6, __kx_exception_returnentry
	add	x6, x6, #:lo12:__kx_exception_returnentry
	str	x6, [x1, #88]
	str	x5, [x2], #8
	str	xzr, [x2], #8		// padding
	// fpu_gprs: live q0..q31 (cursor is 16-aligned: dump base aligned(16), offset 0x120)
	stp	q0,  q1,  [x2], #32
	stp	q2,  q3,  [x2], #32
	stp	q4,  q5,  [x2], #32
	stp	q6,  q7,  [x2], #32
	stp	q8,  q9,  [x2], #32
	stp	q10, q11, [x2], #32
	stp	q12, q13, [x2], #32
	stp	q14, q15, [x2], #32
	stp	q16, q17, [x2], #32
	stp	q18, q19, [x2], #32
	stp	q20, q21, [x2], #32
	stp	q22, q23, [x2], #32
	stp	q24, q25, [x2], #32
	stp	q26, q27, [x2], #32
	stp	q28, q29, [x2], #32
	stp	q30, q31, [x2], #32
	// pstate, afsr0, afsr1, esr (4 x u32 = 16 bytes at frame +96), then far (u64 at +112)
	ldp	x5, x6, [x1, #96]
	stp	x5, x6, [x2], #16
	ldr	x5, [x1, #112]
	str	x5, [x2], #8

	mov	w0, wzr			// handled: ERET onto the slot stack at the trampoline
	bl	svcReturnFromException
	b	.

.Labort:
	mov	w0, #0xf801		// not handled: kernel default handling -> creport
	bl	svcReturnFromException
	b	.
	.size __libnx_exception_entry, .-__libnx_exception_entry

// Jumped to by the kernel's ERET (via the rewritten frame elr) on the slot stack, x0 = &slot dump.
// Byte-for-byte what libnx's __libnx_exception_returnentry does: run the C handler; if it RETURNS
// (unhandled fault — every handled path leaves via siglongjmp or nx_resume_native), panic-break so
// Horizon produces a crash report.
	.balign 4
	.global __kx_exception_returnentry
	.type __kx_exception_returnentry, %function
__kx_exception_returnentry:
	bl	__libnx_exception_handler
	mov	w0, wzr			// BreakReason_Panic
	mov	x1, xzr
	mov	x2, xzr
	bl	svcBreak
	b	.
	.size __kx_exception_returnentry, .-__kx_exception_returnentry

#endif // __SWITCH__
