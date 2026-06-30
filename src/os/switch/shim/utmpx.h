// KurokoNX shim — <utmpx.h> (glibc login records; stubbed for link).
#pragma once
#ifdef __SWITCH__
#include <sys/time.h>
#include <sys/types.h>

#define __UT_LINESIZE 32
#define __UT_NAMESIZE 32
#define __UT_HOSTSIZE 256

struct exit_status {
    short int e_termination;
    short int e_exit;
};

struct utmpx {
    short int ut_type;
    pid_t     ut_pid;
    char      ut_line[__UT_LINESIZE];
    char      ut_id[4];
    char      ut_user[__UT_NAMESIZE];
    char      ut_host[__UT_HOSTSIZE];
    struct exit_status ut_exit;
    long int  ut_session;
    struct timeval ut_tv;
    int32_t   ut_addr_v6[4];
    char      __glibc_reserved[20];
};

#define EMPTY         0
#define RUN_LVL       1
#define BOOT_TIME     2
#define NEW_TIME      3
#define OLD_TIME      4
#define INIT_PROCESS  5
#define LOGIN_PROCESS 6
#define USER_PROCESS  7
#define DEAD_PROCESS  8
#define ACCOUNTING    9

void setutxent(void);
void endutxent(void);
struct utmpx *getutxent(void);
struct utmpx *getutxid(const struct utmpx *id);
struct utmpx *getutxline(const struct utmpx *line);
struct utmpx *pututxline(const struct utmpx *utmpx);
int utmpxname(const char *file);
#endif // __SWITCH__
