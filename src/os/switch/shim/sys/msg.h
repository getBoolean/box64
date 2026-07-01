// box64-nx shim — <sys/msg.h> (SysV message queues; stubbed for link).
#pragma once
#ifdef __SWITCH__
#include <sys/ipc.h>
#include <sys/types.h>
#include <time.h>

typedef unsigned long msgqnum_t;
typedef unsigned long msglen_t;

struct msqid_ds {
    struct ipc_perm msg_perm;
    time_t          msg_stime;
    time_t          msg_rtime;
    time_t          msg_ctime;
    msglen_t        __msg_cbytes;
    msgqnum_t       msg_qnum;
    msglen_t        msg_qbytes;
    pid_t           msg_lspid;
    pid_t           msg_lrpid;
};

struct msgbuf {
    long mtype;
    char mtext[1];
};

#define MSG_NOERROR 010000
#define MSG_STAT    11
#define MSG_INFO    12

int     msgget(key_t key, int msgflg);
int     msgctl(int msqid, int cmd, struct msqid_ds *buf);
int     msgsnd(int msqid, const void *msgp, size_t msgsz, int msgflg);
ssize_t msgrcv(int msqid, void *msgp, size_t msgsz, long msgtyp, int msgflg);
#endif // __SWITCH__
