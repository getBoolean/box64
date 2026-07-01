// box64-nx shim — <sys/shm.h> (SysV shared memory; stubbed for link).
#pragma once
#ifdef __SWITCH__
#include <sys/ipc.h>
#include <sys/types.h>
#include <time.h>

typedef unsigned long shmatt_t;

struct shmid_ds {
    struct ipc_perm shm_perm;
    size_t          shm_segsz;
    time_t          shm_atime;
    time_t          shm_dtime;
    time_t          shm_ctime;
    pid_t           shm_cpid;
    pid_t           shm_lpid;
    shmatt_t        shm_nattch;
};

#define SHM_R      0400
#define SHM_W      0200
#define SHM_RDONLY 010000
#define SHM_RND    020000
#define SHM_REMAP  040000
#define SHM_EXEC   0100000
#define SHM_LOCK   11
#define SHM_UNLOCK 12
#define SHM_STAT   13
#define SHM_INFO   14

int   shmget(key_t key, size_t size, int shmflg);
void *shmat(int shmid, const void *shmaddr, int shmflg);
int   shmdt(const void *shmaddr);
int   shmctl(int shmid, int cmd, struct shmid_ds *buf);
#endif // __SWITCH__
