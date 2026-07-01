// box64-nx shim — <mqueue.h> (POSIX message queues; none on Horizon, stubbed for link).
#pragma once
#ifdef __SWITCH__
#include <sys/types.h>
#include <signal.h>
#include <time.h>
#include <fcntl.h>

typedef int mqd_t;

struct mq_attr {
    long mq_flags;
    long mq_maxmsg;
    long mq_msgsize;
    long mq_curmsgs;
    long __pad[4];
};

mqd_t   mq_open(const char *name, int oflag, ...);
int     mq_close(mqd_t mqdes);
int     mq_unlink(const char *name);
int     mq_send(mqd_t mqdes, const char *msg_ptr, size_t msg_len, unsigned msg_prio);
ssize_t mq_receive(mqd_t mqdes, char *msg_ptr, size_t msg_len, unsigned *msg_prio);
int     mq_getattr(mqd_t mqdes, struct mq_attr *attr);
int     mq_setattr(mqd_t mqdes, const struct mq_attr *newattr, struct mq_attr *oldattr);
int     mq_notify(mqd_t mqdes, const struct sigevent *notification);
int     mq_timedsend(mqd_t mqdes, const char *msg_ptr, size_t msg_len, unsigned msg_prio, const struct timespec *abs_timeout);
ssize_t mq_timedreceive(mqd_t mqdes, char *msg_ptr, size_t msg_len, unsigned *msg_prio, const struct timespec *abs_timeout);

#endif // __SWITCH__
