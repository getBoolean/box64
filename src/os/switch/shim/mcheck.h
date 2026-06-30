// KurokoNX shim — <mcheck.h> (glibc malloc checking; stubbed for link).
#pragma once
#ifdef __SWITCH__
enum mcheck_status {
    MCHECK_DISABLED = -1,
    MCHECK_OK = 0,
    MCHECK_FREE = 1,
    MCHECK_HEAD = 2,
    MCHECK_TAIL = 3
};
int  mcheck(void (*abortfunc)(enum mcheck_status));
int  mcheck_pedantic(void (*abortfunc)(enum mcheck_status));
void mcheck_check_all(void);
enum mcheck_status mprobe(void *ptr);
void mtrace(void);
void muntrace(void);
#endif // __SWITCH__
