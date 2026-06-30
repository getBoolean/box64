// KurokoNX shim — <dlfcn.h> for the box64 Horizon port (newlib has none; Horizon has no dlopen).
// STATICBUILD avoids dlopen at runtime, so these are link-satisfying stubs (see kuro_posix.c).
#pragma once
#ifdef __SWITCH__

#define RTLD_LOCAL   0
#define RTLD_LAZY    0x0001
#define RTLD_NOW     0x0002
#define RTLD_GLOBAL  0x0100
#define RTLD_NODELETE 0x1000
#define RTLD_NOLOAD  0x0004
#define RTLD_DEFAULT ((void*)0)
#define RTLD_NEXT    ((void*)-1)

typedef struct {
    const char *dli_fname;
    void       *dli_fbase;
    const char *dli_sname;
    void       *dli_saddr;
} Dl_info;

#ifdef __cplusplus
extern "C" {
#endif

#define RTLD_DI_LINKMAP 2

void *dlopen(const char *filename, int flags);
int   dlclose(void *handle);
void *dlsym(void *handle, const char *symbol);
void *dlvsym(void *handle, const char *symbol, const char *version);
char *dlerror(void);
int   dladdr(const void *addr, Dl_info *info);
int   dlinfo(void *handle, int request, void *info);

#ifdef __cplusplus
}
#endif

#endif // __SWITCH__
