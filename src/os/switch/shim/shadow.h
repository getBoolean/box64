// KurokoNX shim — <shadow.h> (glibc shadow passwords; stubbed for link).
#pragma once
#ifdef __SWITCH__
#include <stdio.h>

struct spwd {
    char *sp_namp;
    char *sp_pwdp;
    long  sp_lstchg;
    long  sp_min;
    long  sp_max;
    long  sp_warn;
    long  sp_inact;
    long  sp_expire;
    unsigned long sp_flag;
};

void setspent(void);
void endspent(void);
struct spwd *getspent(void);
struct spwd *getspnam(const char *name);
struct spwd *sgetspent(const char *s);
struct spwd *fgetspent(FILE *stream);
int putspent(const struct spwd *p, FILE *stream);
int getspent_r(struct spwd *spbuf, char *buf, size_t buflen, struct spwd **spbufp);
int getspnam_r(const char *name, struct spwd *spbuf, char *buf, size_t buflen, struct spwd **spbufp);
int lckpwdf(void);
int ulckpwdf(void);
#endif // __SWITCH__
