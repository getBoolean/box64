#ifndef __SIGNALS_H__
#define __SIGNALS_H__
#include <stdint.h>

#include "x64_signals.h"
#include "box64context.h"

typedef void (*sighandler_t)(int);

#ifdef ANDROID
typedef struct x64_sigaction_s {
	int sa_flags;
	union {
	  sighandler_t _sa_handler;
	  void (*_sa_sigaction)(int, siginfo_t *, void *);
	} _u;
	sigset_t sa_mask;
	void (*sa_restorer)(void);
} x64_sigaction_t;
#else
typedef struct x64_sigaction_s {
	union {
	  sighandler_t _sa_handler;
	  void (*_sa_sigaction)(int, siginfo_t *, void *);
	} _u;
	sigset_t sa_mask;
	uint32_t sa_flags;
	void (*sa_restorer)(void);
} x64_sigaction_t;
#endif

typedef struct x64_sigaction_restorer_s {
	union {
	  sighandler_t _sa_handler;
	  void (*_sa_sigaction)(int, siginfo_t *, void *);
	} _u;
	uint32_t sa_flags;
	void (*sa_restorer)(void);
	sigset_t sa_mask;
} x64_sigaction_restorer_t;

#ifdef BOX32
typedef struct __attribute__((packed)) i386_sigaction_s {
	union {
	  ptr_t _sa_handler;	// sighandler_t
	  ptr_t _sa_sigaction; //void (*_sa_sigaction)(int, siginfo_t *, void *);
	} _u;
	sigset_t sa_mask;
	uint32_t sa_flags;
	ptr_t sa_restorer; //void (*sa_restorer)(void);
} i386_sigaction_t;

typedef struct __attribute__((packed)) i386_sigaction_restorer_s {
	union {
	  ptr_t _sa_handler;	//sighandler_t
	  ptr_t _sa_sigaction; //void (*_sa_sigaction)(int, siginfo_t *, void *);
	} _u;
	uint32_t sa_flags;
	ptr_t sa_restorer; //void (*sa_restorer)(void);
	sigset_t sa_mask;
} i386_sigaction_restorer_t;

#endif

sighandler_t my_signal(x64emu_t* emu, int signum, sighandler_t handler);
sighandler_t my___sysv_signal(x64emu_t* emu, int signum, sighandler_t handler);
sighandler_t my_sysv_signal(x64emu_t* emu, int signum, sighandler_t handler);

int my_sigaction(x64emu_t* emu, int signum, const x64_sigaction_t *act, x64_sigaction_t *oldact);
int my___sigaction(x64emu_t* emu, int signum, const x64_sigaction_t *act, x64_sigaction_t *oldact);

int my_syscall_rt_sigaction(x64emu_t* emu, int signum, const x64_sigaction_restorer_t *act, x64_sigaction_restorer_t *oldact, int sigsetsize);

void enter_critical_section();
void leave_critical_section();
#ifdef __SWITCH__
// box64-nx: the deferred-signal queue stores full x86-64 siginfo (newlib's is too
// small); defer_signal takes the box64-private x64_siginfo_t there. See nx_signals.c.
#include "x64_siginfo.h"
int defer_signal(x64emu_t* emu, int signum, x64_siginfo_t* info);
#else
int defer_signal(x64emu_t* emu, int signum, siginfo_t* info);
#endif
void cancel_deferred_signal_processing(x64emu_t* emu);

void init_signal_helper(box64context_t* context);
void fini_signal_helper(void);

#ifdef __SWITCH__
// box64-nx: guest signal delivery (Horizon has no host signal delivery, so kill/tkill/tgkill/raise
// are routed straight into the guest's own handler). Self-directed delivery is SYNCHRONOUS; tkill and
// tgkill naming another thread are DIRECTED — queued on that thread and run by it at its next safe
// point, because a handler must execute on its target's own emu/TCB/stack.
int my_kill(x64emu_t* emu, int pid, int sig);
int my_tkill(x64emu_t* emu, int tid, int sig);
int my_tgkill(x64emu_t* emu, int tgid, int tid, int sig);
int my_raise(x64emu_t* emu, int sig);
// Registry hooks (nx_posix.c clone trampoline + nx_main.c for the main thread).
void nx_sigthread_register(x64emu_t* emu);
void nx_sigthread_unregister(void);
// Safe point: deliver anything another thread queued for us. Cheap when idle.
void nx_signal_check_pending(x64emu_t* emu);
#endif

#endif //__SIGNALS_H__
