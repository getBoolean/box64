// box64-nx shim — <error.h> (GNU error()). Implemented in nx_posix.c.
#pragma once
#ifdef __SWITCH__

extern char *program_invocation_name;
extern char *program_invocation_short_name;

void error(int status, int errnum, const char *format, ...);
void error_at_line(int status, int errnum, const char *filename,
                   unsigned int linenum, const char *format, ...);

#endif // __SWITCH__
