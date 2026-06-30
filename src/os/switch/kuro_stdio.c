// KurokoNX — addressable glibc-style data globals for the Switch build.
//
// box64's wrapper DATA() table takes the address of libc data symbols (DATA(stdout) ->
// &stdout), which must be a compile-time constant. glibc exposes these as real globals;
// newlib either #defines them as reentrancy-struct accessor macros (stdin/stdout/stderr,
// signgam, tzname, timezone, daylight) or lacks them (_LIB_VERSION, _nl_msg_cat_cntr,
// __check_rhosts_file, the __-prefixed tz vars). We provide real globals here; the wrapper
// table points at them (see the __SWITCH__ #undef/extern block in wrappedlib_init.h), and
// the stream ones are bound to the live newlib streams at startup.
#ifdef __SWITCH__
#include <stdio.h>

#undef stdin
#undef stdout
#undef stderr
#undef signgam
#undef tzname
#undef timezone
#undef daylight

FILE *stdin = NULL;
FILE *stdout = NULL;
FILE *stderr = NULL;

int    __daylight = 0;
int    daylight = 0;
long   __timezone = 0;
long   timezone = 0;
char  *__tzname[2] = {(char *)"UTC", (char *)"UTC"};
char  *tzname[2]   = {(char *)"UTC", (char *)"UTC"};
int    signgam = 0;
int    _LIB_VERSION = 1;          // _POSIX_
int    _nl_msg_cat_cntr = 0;
void  *__check_rhosts_file = 0;   // static_libc.h declares it void*

// more glibc data symbols box64 references (program name, secure flag, libio internals).
char  *__progname = (char *)"box64";
char  *__progname_full = (char *)"box64";
int    __libc_enable_secure = 0;
void  *_IO_list_all = 0;
void  *_IO_file_jumps = 0;
FILE  *_IO_2_1_stdin_ = 0;
FILE  *_IO_2_1_stdout_ = 0;
FILE  *_IO_2_1_stderr_ = 0;

__attribute__((constructor)) static void kuro_bind_std_streams(void) {
    stdin  = _REENT_STDIN(__getreent());
    stdout = _REENT_STDOUT(__getreent());
    stderr = _REENT_STDERR(__getreent());
    _IO_2_1_stdin_  = stdin;
    _IO_2_1_stdout_ = stdout;
    _IO_2_1_stderr_ = stderr;
}

#endif // __SWITCH__
