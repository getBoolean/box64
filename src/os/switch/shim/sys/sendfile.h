// KurokoNX shim — <sys/sendfile.h> (Linux sendfile; stubbed for link).
#pragma once
#ifdef __SWITCH__
#include <sys/types.h>
ssize_t sendfile(int out_fd, int in_fd, off_t *offset, size_t count);
#endif // __SWITCH__
