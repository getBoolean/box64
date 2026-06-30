// KurokoNX shim — <link.h> (host dynamic-linker introspection; unused on Horizon).
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

// No host shared objects on Horizon — stub (see kuro_posix.c).
int dl_iterate_phdr(int (*callback)(struct dl_phdr_info *info, size_t size, void *data), void *data);

#endif // __SWITCH__
