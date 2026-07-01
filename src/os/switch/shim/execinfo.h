// box64-nx shim — <execinfo.h> (GNU backtrace; no host unwinder on Horizon).
// Stubbed in nx_posix.c.
#pragma once
#ifdef __SWITCH__
int    backtrace(void **buffer, int size);
char **backtrace_symbols(void *const *buffer, int size);
void   backtrace_symbols_fd(void *const *buffer, int size, int fd);
#endif // __SWITCH__
