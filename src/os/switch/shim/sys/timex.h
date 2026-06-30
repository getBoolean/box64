// KurokoNX shim — <sys/timex.h> (Linux adjtimex; stubbed for link).
#pragma once
#ifdef __SWITCH__
#include <sys/time.h>

struct timex {
    unsigned int modes;
    long offset;
    long freq;
    long maxerror;
    long esterror;
    int  status;
    long constant;
    long precision;
    long tolerance;
    struct timeval time;
    long tick;
    long ppsfreq;
    long jitter;
    int  shift;
    long stabil;
    long jitcnt;
    long calcnt;
    long errcnt;
    long stbcnt;
    int  tai;
    int  __pad[11];
};

#define ADJ_OFFSET    0x0001
#define ADJ_FREQUENCY 0x0002
#define ADJ_STATUS    0x0010
#define TIME_OK    0
#define TIME_ERROR 5

int adjtimex(struct timex *buf);
int ntp_adjtime(struct timex *buf);
int clock_adjtime(int clk_id, struct timex *buf);
#endif // __SWITCH__
