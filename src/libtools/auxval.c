#include <stdio.h>
#include <string.h>

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <syscall.h>
#include <stddef.h>
#include <stdarg.h>
#include <fts.h>

#include "box64context.h"
#include "debug.h"
#include "x64emu.h"
#include "emu/x64emu_private.h"
#include "box64stack.h"
#include "auxval.h"

static uintptr_t* auxval_start = NULL;

#ifdef __SWITCH__
#include <switch.h>     // randomGet64
#include <elf.h>        // AT_*
// libnx's crt0 provides no Linux ELF auxv after envp, so synthesize a minimal one.
// A static guest mostly ignores it; AT_RANDOM/PAGESZ keep glibc-ish guests sane later.
static uintptr_t     kuro_auxv[2*8 + 2];
static unsigned char kuro_random[16];
int init_auxval(int argc, const char **argv, char **env) {
    (void)argc; (void)argv; (void)env;
    uint64_t r0 = randomGet64(), r1 = randomGet64();
    memcpy(kuro_random,     &r0, 8);
    memcpy(kuro_random + 8, &r1, 8);
    int i = 0;
    kuro_auxv[i++] = AT_PAGESZ; kuro_auxv[i++] = 0x1000;
    kuro_auxv[i++] = AT_CLKTCK; kuro_auxv[i++] = 100;
    kuro_auxv[i++] = AT_UID;    kuro_auxv[i++] = 0;
    kuro_auxv[i++] = AT_EUID;   kuro_auxv[i++] = 0;
    kuro_auxv[i++] = AT_GID;    kuro_auxv[i++] = 0;
    kuro_auxv[i++] = AT_EGID;   kuro_auxv[i++] = 0;
    kuro_auxv[i++] = AT_SECURE; kuro_auxv[i++] = 0;
    kuro_auxv[i++] = AT_RANDOM; kuro_auxv[i++] = (uintptr_t)kuro_random;
    kuro_auxv[i++] = AT_NULL;   kuro_auxv[i++] = 0;
    auxval_start = kuro_auxv;
    return 0;
}
#else
int init_auxval(int argc, const char **argv, char **env) {
    (void)argc; (void)argv;

    // auxval vector is after envs...
    while(*env)
        env++;
    auxval_start = (uintptr_t*)(env+1);
    return 0;
}
#endif

#ifdef BUILD_LIB
__attribute__((section(".init_array"))) static void *init_auxval_constructor = &init_auxval;
#endif

unsigned long real_getauxval(unsigned long type)
{
    if(!auxval_start)
        return 0;
    uintptr_t* p = auxval_start;
    while(*p) {
        if(*p == type)
            return p[1];
        p+=2;
    }
    return 0;
}

#ifdef BOX32
EXPORT unsigned long my32_getauxval(x64emu_t* emu, unsigned long type)
{
    ptr_t* p = (ptr_t*)emu->context->auxval_start;
    while(*p) {
        if(*p == type)
            return p[1];
        p+=2;
    }
    return 0;
}
#endif

EXPORT unsigned long my_getauxval(x64emu_t* emu, unsigned long type)
{
    #ifdef BOX32
    if(box64_is32bits)
        return my32_getauxval(emu, type);
    #endif
    uintptr_t* p = emu->context->auxval_start;
    while(*p) {
        if(*p == type)
            return p[1];
        p+=2;
    }
    return 0;
}
