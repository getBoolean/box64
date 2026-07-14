// box64-nx — native register-restore-and-branch trampoline (M2.2c2 Stage 4). See nx_resume.h.
//
//   void nx_resume_native(const nx_resume_ctx_t* c);   // x0 = c; never returns
//
// Reloads v0..v31, NZCV, SP, x0..x30 from *c and branches to c->pc. x16 is used as the ctx base
// pointer and x17 as the branch vehicle — both are outside box64's arm64 register model (only x0..x7
// and x10..x28 are allocated), so their "guest" values are dead and safely discarded. Everything else
// is restored to its exact fault-time value so execution continues mid-block at the (executable, rx)
// resume PC.
#ifdef __SWITCH__

#include "nx_resume.h"

	.text
	.balign 4
	.global nx_resume_native
	.type nx_resume_native, %function
nx_resume_native:
	mov	x16, x0				// x16 = ctx base (dead in box64's model)

	// --- SIMD/FP: v0..v31 (16 pairs, 128-bit each) ---
	ldp	q0,  q1,  [x16, #(NX_RC_V + 0x000)]
	ldp	q2,  q3,  [x16, #(NX_RC_V + 0x020)]
	ldp	q4,  q5,  [x16, #(NX_RC_V + 0x040)]
	ldp	q6,  q7,  [x16, #(NX_RC_V + 0x060)]
	ldp	q8,  q9,  [x16, #(NX_RC_V + 0x080)]
	ldp	q10, q11, [x16, #(NX_RC_V + 0x0A0)]
	ldp	q12, q13, [x16, #(NX_RC_V + 0x0C0)]
	ldp	q14, q15, [x16, #(NX_RC_V + 0x0E0)]
	ldp	q16, q17, [x16, #(NX_RC_V + 0x100)]
	ldp	q18, q19, [x16, #(NX_RC_V + 0x120)]
	ldp	q20, q21, [x16, #(NX_RC_V + 0x140)]
	ldp	q22, q23, [x16, #(NX_RC_V + 0x160)]
	ldp	q24, q25, [x16, #(NX_RC_V + 0x180)]
	ldp	q26, q27, [x16, #(NX_RC_V + 0x1A0)]
	ldp	q28, q29, [x16, #(NX_RC_V + 0x1C0)]
	ldp	q30, q31, [x16, #(NX_RC_V + 0x1E0)]

	// --- NZCV (from pstate; msr nzcv applies bits [31:28]) ---
	ldr	x17, [x16, #NX_RC_NZCV]
	msr	nzcv, x17

	// --- SP ---
	ldr	x17, [x16, #NX_RC_SP]
	mov	sp, x17

	// --- GPRs x0..x30 (skip x16=base, x17=vehicle — both dead) ---
	ldp	x0,  x1,  [x16, #(NX_RC_X + 0x00)]
	ldp	x2,  x3,  [x16, #(NX_RC_X + 0x10)]
	ldp	x4,  x5,  [x16, #(NX_RC_X + 0x20)]
	ldp	x6,  x7,  [x16, #(NX_RC_X + 0x30)]
	ldp	x8,  x9,  [x16, #(NX_RC_X + 0x40)]
	ldp	x10, x11, [x16, #(NX_RC_X + 0x50)]
	ldp	x12, x13, [x16, #(NX_RC_X + 0x60)]
	ldp	x14, x15, [x16, #(NX_RC_X + 0x70)]
	ldp	x18, x19, [x16, #(NX_RC_X + 0x90)]
	ldp	x20, x21, [x16, #(NX_RC_X + 0xA0)]
	ldp	x22, x23, [x16, #(NX_RC_X + 0xB0)]
	ldp	x24, x25, [x16, #(NX_RC_X + 0xC0)]
	ldp	x26, x27, [x16, #(NX_RC_X + 0xD0)]
	ldp	x28, x29, [x16, #(NX_RC_X + 0xE0)]
	ldr	x30,      [x16, #(NX_RC_X + 0xF0)]

	// --- release the M2.6 exception slot (if any), then branch to the (executable, rx) resume PC.
	// Order matters: BOTH ctx reads complete before the stlr frees the slot (the ctx lives on the
	// dying slot stack), and SP was already restored off that stack above — after the stlr a
	// concurrent claimant may immediately reuse the stack, but only registers are used from here.
	ldr	x17, [x16, #NX_RC_PC]
	ldr	x16, [x16, #NX_RC_RELEASE]
	cbz	x16, 1f
	stlr	wzr, [x16]
1:	br	x17

	.size nx_resume_native, .-nx_resume_native

#endif // __SWITCH__
