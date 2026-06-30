// KurokoNX shim — <sys/uio.h> (scatter/gather I/O). struct iovec comes from libnx.
#pragma once
#ifdef __SWITCH__
#include <sys/types.h>
#include <sys/_iovec.h>   // struct iovec (libnx)

ssize_t readv(int fd, const struct iovec *iov, int iovcnt);
ssize_t writev(int fd, const struct iovec *iov, int iovcnt);
ssize_t preadv(int fd, const struct iovec *iov, int iovcnt, off_t offset);
ssize_t pwritev(int fd, const struct iovec *iov, int iovcnt, off_t offset);
// Linux cross-process memory (no equivalent on Horizon; stubbed in kuro_posix.c).
ssize_t process_vm_readv(int pid, const struct iovec *lvec, unsigned long liovcnt,
                         const struct iovec *rvec, unsigned long riovcnt, unsigned long flags);
ssize_t process_vm_writev(int pid, const struct iovec *lvec, unsigned long liovcnt,
                          const struct iovec *rvec, unsigned long riovcnt, unsigned long flags);

#endif // __SWITCH__
