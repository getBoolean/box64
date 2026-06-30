// KurokoNX shim — <sys/sem.h> (SysV semaphores; structs only, for box64's struct
// marshalling. The sem* syscalls route through the stubbed syscall() passthrough).
#pragma once
#ifdef __SWITCH__
#include <sys/ipc.h>
#include <time.h>

struct semid_ds {
    struct ipc_perm sem_perm;
    time_t          sem_otime;
    time_t          sem_ctime;
    unsigned long   sem_nsems;
};

struct sembuf {
    unsigned short sem_num;
    short          sem_op;
    short          sem_flg;
};

#define SEM_UNDO 0x1000
#define GETPID   11
#define GETVAL   12
#define GETALL   13
#define GETNCNT  14
#define GETZCNT  15
#define SETVAL   16
#define SETALL   17

#endif // __SWITCH__
