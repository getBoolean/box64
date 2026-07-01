// box64-nx shim — <printf.h> (glibc custom printf hooks; stubbed for link).
#pragma once
#ifdef __SWITCH__
#include <stdio.h>
#include <stdarg.h>

struct printf_info {
    int          prec;
    int          width;
    wchar_t      spec;
    unsigned int is_long_double : 1;
    unsigned int is_short : 1;
    unsigned int is_long : 1;
    unsigned int alt : 1;
    unsigned int space : 1;
    unsigned int left : 1;
    unsigned int showsign : 1;
    unsigned int group : 1;
    unsigned int extra : 1;
    unsigned int is_char : 1;
    unsigned int wide : 1;
    unsigned int i18n : 1;
    unsigned int is_binary128 : 1;
    unsigned int __pad : 3;
    unsigned short int user;
    wchar_t      pad;
};

union printf_arg {
    wchar_t            pa_wchar;
    int                pa_int;
    long int           pa_long_int;
    long long int      pa_long_long_int;
    unsigned int       pa_u_int;
    unsigned long int  pa_u_long_int;
    unsigned long long pa_u_long_long_int;
    double             pa_double;
    long double        pa_long_double;
    const char        *pa_string;
    const wchar_t     *pa_wstring;
    void              *pa_pointer;
};

typedef int (*printf_function)(FILE *stream, const struct printf_info *info, const void *const *args);
typedef int (*printf_arginfo_size_function)(const struct printf_info *info, size_t n, int *argtypes, int *size);
typedef int (*printf_va_arg_function)(void *mem, va_list *ap);

int  register_printf_specifier(int spec, printf_function func, printf_arginfo_size_function arginfo);
int  register_printf_function(int spec, printf_function func, void *arginfo);
int  register_printf_modifier(const wchar_t *str);
int  register_printf_type(printf_va_arg_function fct);
size_t parse_printf_format(const char *fmt, size_t n, int *argtypes);

#define PA_INT     0
#define PA_CHAR    1
#define PA_WCHAR   2
#define PA_STRING  3
#define PA_WSTRING 4
#define PA_POINTER 5
#define PA_FLOAT   6
#define PA_DOUBLE  7
#define PA_LAST    8
#define PA_FLAG_LONG_LONG 256
#define PA_FLAG_LONG_DOUBLE PA_FLAG_LONG_LONG
#define PA_FLAG_LONG      512
#define PA_FLAG_SHORT     1024
#define PA_FLAG_PTR       2048
#endif // __SWITCH__
