// KurokoNX shim — <sys/prctl.h> (Horizon has no prctl; stubbed in kuro_posix.c).
#pragma once
#ifdef __SWITCH__

#define PR_SET_NAME 15
#define PR_GET_NAME 16
#define PR_SET_SECCOMP 22
#define PR_SET_NO_NEW_PRIVS 38
#define PR_GET_NO_NEW_PRIVS 39
#define PR_SET_SYSCALL_USER_DISPATCH 59
#define PR_SYS_DISPATCH_OFF 0
#define PR_SYS_DISPATCH_ON  1
#define PR_SET_PTRACER 0x59616d61

int prctl(int option, ...);

#endif // __SWITCH__
