// box64-nx shim — <link.h> (host dynamic-linker introspection; unused on Horizon).
#pragma once
#ifdef __SWITCH__
#include <stddef.h>
#include <stdint.h>

struct dl_phdr_info {
    uintptr_t          dlpi_addr;
    const char        *dlpi_name;
    const void        *dlpi_phdr;
    uint16_t           dlpi_phnum;
    unsigned long long dlpi_adds;
    unsigned long long dlpi_subs;
    size_t             dlpi_tls_modid;
    void              *dlpi_tls_data;
};

// No host shared objects on Horizon — stub (see nx_posix.c).
int dl_iterate_phdr(int (*callback)(struct dl_phdr_info *info, size_t size, void *data), void *data);

// newlib's <elf.h> provides all Elf{32,64}_* types/constants but not glibc's
// ElfW() machinery (glibc defines it here, in <link.h>). box64 is 64-bit only.
#ifndef __ELF_NATIVE_CLASS
#define __ELF_NATIVE_CLASS 64
#endif
#ifndef ElfW
#define _ElfW_1(e, w, t) e##w##t
#define _ElfW(e, w, t)   _ElfW_1(e, w, _##t)
#define ElfW(type)       _ElfW(Elf, __ELF_NATIVE_CLASS, type)
#endif

#endif // __SWITCH__
