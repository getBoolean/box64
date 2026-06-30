// KurokoNX shim — <sys/ipc.h> (SysV IPC perms; Horizon has no SysV IPC, but box64
// references these structs when marshalling guest syscalls).
#pragma once
#ifdef __SWITCH__
#include <sys/types.h>

struct ipc_perm {
    key_t          __key;
    uid_t          uid;
    gid_t          gid;
    uid_t          cuid;
    gid_t          cgid;
    unsigned short mode;
    unsigned short __seq;
};

#define IPC_PRIVATE ((key_t)0)
#define IPC_CREAT   01000
#define IPC_EXCL    02000
#define IPC_NOWAIT  04000
#define IPC_RMID    0
#define IPC_SET     1
#define IPC_STAT    2
#define IPC_INFO    3

#endif // __SWITCH__
