// box64-nx shim — <aio.h> (POSIX async I/O; no AIO on Horizon, stubbed for link).
#pragma once
#ifdef __SWITCH__
#include <sys/types.h>
#include <signal.h>
#include <time.h>

struct aiocb {
    int             aio_fildes;
    int             aio_lio_opcode;
    int             aio_reqprio;
    volatile void  *aio_buf;
    size_t          aio_nbytes;
    struct sigevent aio_sigevent;
    void           *__next_prio;
    int             __abs_prio;
    int             __policy;
    int             __error_code;
    long            __return_value;
    off_t           aio_offset;
    char            __pad[32];
};

#define AIO_CANCELED    0
#define AIO_NOTCANCELED 1
#define AIO_ALLDONE     2
#define LIO_READ        0
#define LIO_WRITE       1
#define LIO_NOP         2
#define LIO_WAIT        0
#define LIO_NOWAIT      1

int     aio_read(struct aiocb *aiocbp);
int     aio_write(struct aiocb *aiocbp);
int     aio_fsync(int op, struct aiocb *aiocbp);
int     aio_error(const struct aiocb *aiocbp);
ssize_t aio_return(struct aiocb *aiocbp);
int     aio_suspend(const struct aiocb *const list[], int nent, const struct timespec *timeout);
int     aio_cancel(int fildes, struct aiocb *aiocbp);
int     lio_listio(int mode, struct aiocb *const list[], int nent, struct sigevent *sig);

#endif // __SWITCH__
