// KurokoNX shim — <sys/utmp.h>. newlib's <utmp.h> includes it but doesn't ship it.
// Minimal login-record struct + accessors (stubbed for link).
#pragma once
#ifdef __SWITCH__
#include <sys/types.h>
#include <sys/time.h>
#include <stdint.h>

#define UT_LINESIZE 32
#define UT_NAMESIZE 32
#define UT_HOSTSIZE 256
#define _PATH_UTMP  "/var/run/utmp"
#define _PATH_WTMP  "/var/log/wtmp"
#define UTMP_FILE   _PATH_UTMP
#define WTMP_FILE   _PATH_WTMP

struct utmp {
    short int ut_type;
    pid_t     ut_pid;
    char      ut_line[UT_LINESIZE];
    char      ut_id[4];
    char      ut_user[UT_NAMESIZE];
    char      ut_host[UT_HOSTSIZE];
    struct {
        short int e_termination;
        short int e_exit;
    } ut_exit;
    long int  ut_session;
    struct timeval ut_tv;
    int32_t   ut_addr_v6[4];
    char      __glibc_reserved1[20];
};

#define ut_name ut_user
#define ut_time ut_tv.tv_sec

void setutent(void);
void endutent(void);
struct utmp *getutent(void);
struct utmp *getutid(const struct utmp *id);
struct utmp *getutline(const struct utmp *line);
struct utmp *pututline(const struct utmp *utmp);
int  utmpname(const char *file);
void updwtmp(const char *wtmp_file, const struct utmp *ut);
int  login_tty(int fd);
void login(const struct utmp *ut);
int  logout(const char *ut_line);
void logwtmp(const char *ut_line, const char *ut_name, const char *ut_host);

#endif // __SWITCH__
