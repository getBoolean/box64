// nx_spawn.c — M2.5 process model: run a SECOND independent x86-64 guest (the wineserver) inside
// the same Horizon process, on a host thread.
//
// Horizon has no fork/execve, so Wine's client-forks-and-execs-wineserver model can't work. Instead
// we PRE-START wineserver64 as its own guest instance BEFORE the wine client reaches server_connect():
// its own real ld.so + libc (freshly loaded — separate link map/TLS from the client), its own initial
// SysV stack (argc/argv/envp/auxv), its own x64emu on a detached pthread, and a distinct guest pid.
// The two instances talk over the in-process AF_UNIX socket layer (nx_vfd.c). Wine's connect() finds
// the listening socket and never forks (fork() is stubbed to a benign no-op on __SWITCH__).
//
// Why a second guest is even possible in box64's singleton-context engine: on the real-ld.so path
// (KurokoNX M2.1) box64 is ONLY the x86-64 engine + syscall libos — it does NOT resolve guest symbols
// or use my_context->elfs[] during execution; the guest's own ld.so does all of that, reading argv/
// auxv from ITS OWN stack (not the context). So a guest with a private stack + emu + ld.so runs
// independently; box64 globals it touches (dynablock cache keyed by address, mmap arena) are shared-safe.

#ifdef __SWITCH__

#include <switch.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include <sys/mman.h>

#include "box64context.h"
#include "elfloader.h"
#include "elfs/elfloader_private.h"   // struct elfheader_s (delta/entrypoint/PHEntries/numPHEntries)
#include "x64emu.h"
#include "emu/x64emu_private.h"       // R_RSP etc. via regs.h
#include "box64cpu.h"
#include "box64cpu_util.h"   // Push64, PushString, SetRIP
#include "custommem.h"
#include "threads.h"        // inc/dec_active_emu_workers — keep endBox64 from freeing my_context under us
#include "librarian.h"
#include "debug.h"           // box64_pagesize (uintptr_t)

extern box64context_t* my_context;
void nx_result_log(const char* s);
void nx_set_guest_pid(int pid);
int  nx_translate_path(const char* p, char* out, size_t outn);
void PushString(x64emu_t* emu, const char* s);   // tools/box64stack.c
void setProtection_stack(uintptr_t addr, size_t size, uint32_t prot);   // custommem.c

static void slog(const char* fmt, ...) {
    char b[192]; va_list ap; va_start(ap, fmt);
    int n = vsnprintf(b, sizeof b, fmt, ap); va_end(ap);
    if (n > 0) { svcOutputDebugString(b, (size_t)n); nx_result_log(b); }
}

// PT_PHDR mapped address for AT_PHDR (ld.so derives the main program's base from AT_PHDR - p_vaddr)
static uintptr_t elf_phdr_mapped(elfheader_t* h) {
    uintptr_t phdr = (uintptr_t)h->PHEntries._64;
    for (size_t i = 0; i < h->numPHEntries; ++i)
        if (h->PHEntries._64[i].p_type == PT_PHDR)
            return (uintptr_t)(h->delta + h->PHEntries._64[i].p_vaddr);
    return phdr;
}

// Load an x86-64 ELF (exec=1 program, exec=0 interp) into the shared context's address space.
static elfheader_t* load_elf(const char* guestpath, int exec) {
    char hp[512];
    if (nx_translate_path(guestpath, hp, sizeof hp) != 0) { slog("nx_spawn: translate '%s' fail\n", guestpath); return NULL; }
    FILE* f = fopen(hp, "rb");
    if (!f) { slog("nx_spawn: fopen '%s' fail\n", hp); return NULL; }
    elfheader_t* h = LoadAndCheckElfHeader(f, guestpath, exec);
    if (!h) { fclose(f); slog("nx_spawn: bad ELF '%s'\n", hp); return NULL; }
    if (CalcLoadAddr(h))                        { slog("nx_spawn: CalcLoadAddr fail\n"); return NULL; }
    // CRITICAL: neutralize PT_TLS in box64's PARSED phdr copy before AllocLoadElfMemory. That routine
    // copies each PT_TLS into the SHARED context->tlsdata at context->tlssize+AddTLSPartition() — after
    // the CLIENT's TLS is already fixed, that grows past the client's TLS buffer and overwrites its heap
    // (-> the client's later dlsym(__wine_main) returns NULL). The server's own real ld.so sets up TLS
    // from the ELF's phdrs in the MAPPED image (AT_PHDR), independent of box64's context TLS, so skipping
    // box64's copy is harmless. (Zero tlssize too so AddTLSPartition doesn't grow the shared partition.)
    for (size_t i = 0; i < h->numPHEntries; ++i)
        if (h->PHEntries._64[i].p_type == PT_TLS) h->PHEntries._64[i].p_type = PT_NULL;
    h->tlssize = 0;
    if (AllocLoadElfMemory(my_context, h, exec)){ slog("nx_spawn: AllocLoadElfMemory fail\n"); return NULL; }
    // Deliberately NO AddElfHeader: the server is a fully independent guest whose OWN real ld.so does
    // all symbol resolution; registering it in the shared my_context->elfs[] (esp. a SECOND ld-linux
    // with the same soname) confuses box64's librarian and breaks the CLIENT's later dlopen/dlsym.
    slog("nx_spawn: loaded %s base=0x%lx entry=0x%lx\n", guestpath,
         (unsigned long)h->delta, (unsigned long)(h->entrypoint + h->delta));
    return h;
}

typedef struct {
    elfheader_t* prog;
    elfheader_t* interp;
    const char** argv;   // NULL-terminated, stable strings
    const char** envp;   // NULL-terminated, stable strings
    int          pid;
} spawn_t;

// Build a SysV init stack (argc, argv[], NULL, envp[], NULL, auxv[]) for `s` on `emu`'s stack, with
// AT_* pointing at s->prog / s->interp. Mirrors tools/box64stack.c SetupInitialStack but stands alone
// (no my_context->argv/elfs[0] dependency — those belong to the client). RSP ends at argc.
static void build_stack(x64emu_t* emu, spawn_t* s) {
    int argc = 0; while (s->argv[argc]) argc++;
    int envc = 0; while (s->envp[envc]) envc++;

    Push64(emu, 0);
    PushString(emu, (char*)s->argv[0]);
    uintptr_t p_arg0 = R_RSP;

    uintptr_t p_envv[envc + 1]; p_envv[envc] = 0;
    for (int i = envc - 1; i >= 0; --i) { PushString(emu, (char*)s->envp[i]); p_envv[i] = R_RSP; }
    uintptr_t p_argv[argc + 1]; p_argv[argc] = 0;
    for (int i = argc - 1; i >= 0; --i) { PushString(emu, (char*)s->argv[i]); p_argv[i] = R_RSP; }

    uintptr_t tmp = R_RSP & ~15UL; memset((void*)tmp, 0, R_RSP - tmp); R_RSP = tmp;
    PushString(emu, "x86_64"); uintptr_t p_x86_64 = R_RSP;
    for (int i = 0; i < 4; ++i) Push64(emu, (uint64_t)(0x9e3779b97f4a7c15ULL * (i + 1 + s->pid)));
    uintptr_t p_random = R_RSP;
    tmp = R_RSP & ~15UL; memset((void*)tmp, 0, R_RSP - tmp); R_RSP = tmp;

    uintptr_t prog_ep = s->prog->entrypoint + s->prog->delta;
    Push64(emu, 0); Push64(emu, 0);                                            // AT_NULL
    Push64(emu, elf_phdr_mapped(s->prog)); Push64(emu, 3);                     // AT_PHDR (mapped)
    Push64(emu, sizeof(Elf64_Phdr)); Push64(emu, 4);                          // AT_PHENT
    Push64(emu, s->prog->numPHEntries); Push64(emu, 5);                       // AT_PHNUM
    Push64(emu, box64_pagesize); Push64(emu, 6);                             // AT_PAGESZ
    Push64(emu, (uintptr_t)s->interp->delta); Push64(emu, 7);                 // AT_BASE = interp load base
    Push64(emu, 0); Push64(emu, 8);                                           // AT_FLAGS
    Push64(emu, prog_ep); Push64(emu, 9);                                     // AT_ENTRY = program entry
    Push64(emu, 0);  Push64(emu, 11);                                         // AT_UID
    Push64(emu, 0);  Push64(emu, 12);                                         // AT_EUID
    Push64(emu, 0);  Push64(emu, 13);                                         // AT_GID
    Push64(emu, 0);  Push64(emu, 14);                                         // AT_EGID
    Push64(emu, p_x86_64); Push64(emu, 15);                                   // AT_PLATFORM
    Push64(emu, 1<<0|1<<4|1<<8|1<<11|1<<15|1<<19|1<<23|1<<24|1<<25|1<<26|1<<28); Push64(emu, 16); // AT_HWCAP
    Push64(emu, 100); Push64(emu, 17);                                        // AT_CLKTCK
    Push64(emu, 0);   Push64(emu, 23);                                        // AT_SECURE
    Push64(emu, p_random); Push64(emu, 25);                                   // AT_RANDOM
    Push64(emu, 1<<1); Push64(emu, 26);                                       // AT_HWCAP2 (FSGSBASE)
    Push64(emu, p_arg0); Push64(emu, 31);                                     // AT_EXECFN
    Push64(emu, 0); Push64(emu, 32);                                          // AT_SYSINFO

    Push64(emu, 0);
    for (int i = envc - 1; i >= 0; --i) Push64(emu, p_envv[i]);
    Push64(emu, 0);
    for (int i = argc - 1; i >= 0; --i) Push64(emu, p_argv[i]);
    Push64(emu, (uint64_t)argc);
}

#define SRV_STACK (8u << 20)

static void* spawn_thread(void* arg) {
    spawn_t* s = (spawn_t*)arg;
    nx_set_guest_pid(s->pid);

    void* stackmem = mmap(NULL, SRV_STACK, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (stackmem == MAP_FAILED) { slog("nx_spawn: stack mmap fail\n"); return NULL; }
    setProtection_stack((uintptr_t)stackmem, SRV_STACK, PROT_READ | PROT_WRITE);   // box64 must know it's guest RAM

    uintptr_t interp_ep = s->interp->entrypoint + s->interp->delta;
    x64emu_t* emu = NewX64Emu(my_context, interp_ep, (uintptr_t)stackmem, SRV_STACK, 1);
    SetupX64Emu(emu, NULL);
    // RSP at the top of our stack, then build the SysV init frame downward.
    emu->regs[_SP].q[0] = (uintptr_t)stackmem + SRV_STACK - 16;
    build_stack(emu, s);
    SetRIP(emu, interp_ep);                       // enter the guest's real ld.so (it jumps to AT_ENTRY)
    Push64(emu, my_context->exit_bridge);         // exit bridge (as emulate() does)
    SetRDX(emu, Pop64(emu));

    slog("nx_spawn: wineserver thread starting, ld.so=0x%lx prog_ep=0x%lx pid=%d\n",
         (unsigned long)interp_ep, (unsigned long)(s->prog->entrypoint + s->prog->delta), s->pid);
    // Count this thread as an active emu worker so endBox64() (fired when the PRIMARY guest exits) waits
    // for / skips freeing my_context while the wineserver is still executing dynarec. Otherwise it frees
    // my_context under us and the next internalDBGetBlock -> mutex_lock(&my_context->mutex_dyndump) faults.
    inc_active_emu_workers();
    // The wineserver is its own guest instance (own pid), and its main thread is a tkill/tgkill target
    // like any other — register it in the directed-signal registry (nx_signals.c), which is keyed on
    // (tid, gpid) so the two instances' thread ids cannot collide.
    { extern void nx_sigthread_register(x64emu_t*); nx_sigthread_register(emu); }
    DynaRun(emu);
    { extern void nx_sigthread_unregister(void); nx_sigthread_unregister(); }
    dec_active_emu_workers();
    slog("nx_spawn: wineserver exited eax=%d\n", GetEAX(emu));
    return NULL;
}

// ---- listening handshake: nx_listen (nx_vfd.c) pings this when the wineserver socket binds --------
static volatile int g_srv_listening = 0;
void nx_spawn_note_listen(const char* bpath) {
    if (bpath && strstr(bpath, "/wine/server-") && strstr(bpath, "/socket"))
        g_srv_listening = 1;
}
int nx_spawn_server_ready(void) { return g_srv_listening; }

// Pre-start wineserver. Returns 0 if the thread launched (not necessarily listening yet).
static const char* g_srv_argv[] = { "/usr/lib/wine/wineserver64", "--foreground", NULL };

int nx_spawn_wineserver(const char** envp) {
    static spawn_t s;
    if (getenv("KX_WINESERVER_NOLOAD")) { slog("nx_spawn: NOLOAD — skipping server load entirely\n"); return -1; }
    s.prog = load_elf("/usr/lib/wine/wineserver64", 1);
    if (!s.prog) return -1;
    s.interp = load_elf("/lib/ld-linux-x86-64.so.2", 0);   // a SECOND, independent ld.so instance
    if (!s.interp) return -1;
    s.argv = g_srv_argv;
    s.envp = envp;
    s.pid  = 2;                                             // wineserver is guest pid 2 (client = 100)

    if (getenv("KX_WINESERVER_NORUN")) { slog("nx_spawn: NORUN — loaded, not starting thread\n"); return 0; }
    pthread_attr_t attr; pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, 1u << 20);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_t th;
    int rc = pthread_create(&th, &attr, spawn_thread, &s);
    pthread_attr_destroy(&attr);
    if (rc) { slog("nx_spawn: pthread_create fail rc=%d\n", rc); return -1; }
    return 0;
}

#endif // __SWITCH__
