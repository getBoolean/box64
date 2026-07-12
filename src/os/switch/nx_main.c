// box64-nx — libnx NRO entry for box64 on Horizon (replaces src/main.c on __SWITCH__).
//
// box64's normal main() takes (argc, argv, env) from the shell. A homebrew NRO has no
// shell, so we synthesize argv = {"box64", "<guest path>"} and drive box64's own
// initialize()/emulate() (src/core.c). The guest path comes from argv[1] when a launcher
// supplies one, else the NX_GUEST_PATH compile default. Guest stdout (write(1)) and box64's
// logs surface on the libnx console; a couple of svcOutputDebugString markers also land in
// the Ryujinx log for headless tracing.
#ifdef __SWITCH__

#include <switch.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>   // environ, write/close
#include <fcntl.h>    // open (heap-free result logging)

#include "core.h"     // initialize(), emulate(), x64emu_t, elfheader_t
#include "nx_posix.h" // nx_vm_status() — which memory backend (arena vs heap fallback) is active

// Default guest path on the SD card. Overridable at build time (-DNX_GUEST_PATH=... /
// the NX_GUEST_PATH CMake cache var) or at runtime via argv[1].
#ifndef NX_GUEST_PATH
#define NX_GUEST_PATH "sdmc:/box64/box64-guest"
#endif

static void kdbg(const char *s) { svcOutputDebugString(s, strlen(s)); }

// Append a line to a result file on the SD. A title (NSP) has no nxlink and its console is replaced by
// am's "software closed" dialog when it self-exits, so this is the only reliable way to read a title's
// result off-device (over FTP). Open+close each call so the line is flushed even if we crash/exit next.
static void rlog(const char *s) {
    // POSIX open/write, NOT fopen: fopen mallocs a FILE+buffer, so a null/broken heap (exactly the
    // failure we're chasing) makes the instrument itself crash before it can record anything. open()
    // uses libnx's static fd table — no malloc — so this survives a dead heap.
    int fd = open("sdmc:/box64/box64-result.txt", O_WRONLY | O_CREAT | O_APPEND, 0666);
    if (fd >= 0) { write(fd, s, strlen(s)); write(fd, "\n", 1); close(fd); }
    // fsdev buffers SD writes; a hard system fatal (e.g. an unsafe-pool op crashing a sysmodule) can
    // lose them. Commit each checkpoint so the last line survives even if the whole console dies next.
    fsdevCommitDevice("sdmc");
}

// Exported so the loader reroute (core.c) and the mmap libos (nx_virtmem.c) can drop load-address
// markers into the SAME result file. On real HW this is the only crash-diagnostics channel (no
// svcOutputDebugString capture), so it's how we turn a creport's guest RIP (X[27]) into lib+offset.
void nx_result_log(const char *s) { rlog(s); }

// The console's owning thread (the client/main guest). The in-process wineserver runs on a SEPARATE host
// thread; libnx's console double-buffer is not safe to drive from two threads, so guest output is only
// rendered to the screen from this thread (the wineserver's diagnostics still tee to the SD file). Set
// in main() right after consoleInit().
static Handle g_main_thread = 0;
static int g_hold_done = 0;   // ensures the on-screen "press + to exit" hold runs exactly once

// Guest stdout/stderr tee (x64syscall.c write + nx_posix.c writev call this): mirror to the debug
// log (Ryujinx) AND — bounded, so a chatty guest can't flood the SD — to the result file, which is
// the only channel an installed title has on real HW (e.g. wine --version's one banner line).
void nx_guest_output(int fd, const void *buf, size_t len) {
    if (!buf || !len) return;
    svcOutputDebugString((const char*)buf, len);
    // Mirror ALL guest output to the ON-SCREEN console (svcOutputDebugString isn't captured on real HW) —
    // both the client's (cmd.exe's echo) and the in-process wineserver's (its sock_init/file_set_error
    // startup warnings), which the wineserver writes to fd 2 from its own host thread. fwrite() renders
    // into the console grid from ANY thread — stdio's FILE lock serialises it — but consoleUpdate() (the
    // gfx present) is done ONLY from the console-owning main thread: presenting from two threads deadlocks
    // libnx's double-buffer (that was the earlier hang). The wineserver's lines therefore appear on the
    // next main-thread present — nx_applet_keepalive() pumps one every ~30 ms. All of it tees to the SD
    // file below too, so it's LOGGED as well as shown.
    fwrite(buf, 1, len, stdout); fflush(stdout);
    if (threadGetCurHandle() == g_main_thread) consoleUpdate(NULL);
    // Bounded so a chatty guest can't flood the SD, but generous enough that a wineserver's startup
    // chatter (registry-save warnings, ~1 KiB) doesn't crowd out the actual command output that
    // follows — this file is the ONLY result channel on real HW.
    static size_t teed = 0;
    const size_t CAP = 16384;
    if (teed >= CAP) return;
    if (len > CAP - teed) len = CAP - teed;
    teed += len;
    char line[256];
    while (len) {
        size_t chunk = len < sizeof(line) - 16 ? len : sizeof(line) - 16;
        int n = snprintf(line, sizeof line, "guest fd%d> %.*s", fd, (int)chunk, (const char*)buf);
        // strip the guest's own newline; rlog appends one
        while (n > 0 && (line[n-1] == '\n' || line[n-1] == '\r')) line[--n] = 0;
        rlog(line);
        buf = (const char*)buf + chunk; len -= chunk;
    }
    // Hold on the guest's FIRST stdout line until + (real HW + KX_WAIT_EXIT). THIS is the only place a hold
    // works: we're inside the guest's write() syscall, so the guest is still running and box64 is the
    // foreground app (appletMainLoop() true, input flows). A hold at exit_group instead shows HOME — by then
    // the OS has already queued box64's Exit. Blocks the write() until +, then the guest resumes and exits.
    // no-op after the first hold, off real HW, or without KX_WAIT_EXIT. (fd 1 = the program's own output.)
    if (fd == 1) { extern void nx_wait_for_exit_button(void); nx_wait_for_exit_button(); }
}

// Optional runtime tuning WITHOUT a rebuild: read sdmc:/box64/box64.env and setenv each KEY=VALUE line
// (blank / '#' lines skipped). Horizon has no shell env, so this is how we flip BOX64_DYNAREC / BOX64_LOG
// etc. over FTP between hardware runs. Overwrites, so the file wins over the compiled-in defaults.
static void load_env_file(void) {
    int fd = open("sdmc:/box64/box64.env", O_RDONLY);
    if (fd < 0) return;
    static char buf[1024];
    ssize_t n = read(fd, buf, sizeof buf - 1);
    close(fd);
    if (n <= 0) return;
    buf[n] = 0;
    char *p = buf;
    while (*p) {
        char *line = p;
        while (*p && *p != '\n' && *p != '\r') ++p;
        if (*p) *p++ = 0;
        while (*p == '\n' || *p == '\r') ++p;
        while (*line == ' ' || *line == '\t') ++line;
        if (*line == '#' || !*line) continue;
        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq = 0;
        setenv(line, eq + 1, 1);
        { char b[160]; snprintf(b, sizeof b, "env %s=%s", line, eq + 1); rlog(b); }
    }
}

// nxlink host socket (>=0 only when launched via nxlink) — lets a hardware run stream box64's
// status/result to the PC terminal while it also shows on the Switch console.
static int g_nxlink_fd = -1;

// Set in main(); read by the hold + cleanup paths. homebrew = plain NRO (heap override + nxlink + romfs).
static bool g_homebrew = false;
static bool g_have_romfs = false;

// Print to the on-screen console AND, when launched via nxlink, mirror the same text to the host PC.
static void kout(const char *fmt, ...) {
    char buf[512];
    va_list ap; va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    if (n < 0) return;
    if (n > (int)sizeof buf - 1) n = (int)sizeof buf - 1;
    fputs(buf, stdout);
    fflush(stdout);
    if (g_nxlink_fd >= 0) write(g_nxlink_fd, buf, (size_t)n);
}

// Hold the screen until the user presses +, so a hardware run's output stays readable and the user closes
// it themselves. Called from the guest's stdout write (nx_guest_output, fd 1) — NOT from any exit path.
// Why: a hold only works while the guest is still running, because THEN box64 is a normal foreground app
// (appletMainLoop() true, input flows). Once the guest calls exit_group the OS has already queued box64's
// Exit (it force-reaps an emulator whose guest finished, ~3 s later), so a hold there just shows HOME.
// Gated: only on real HW (Ryujinx has no controller anyway; pad support is declared once in main()),
// only with KX_WAIT_EXIT set, only from the console-owning thread (the in-process wineserver must never
// drive HID/console). Runs at most once (g_hold_done). Blocks the write() until +, then the guest resumes.
void nx_wait_for_exit_button(void) {
    if (g_hold_done) return;
    if (!getenv("KX_WAIT_EXIT") || !detectMesosphere()) return;
    if (threadGetCurHandle() != g_main_thread) return;
    g_hold_done = 1;
    rlog("hold: waiting for + button");
    kout("\n[ press + to exit ]\n");
    consoleUpdate(NULL);
    // No padConfigureInput here: main() already declared 8 players (re-declaring 1 here would SHRINK
    // the supported set mid-run and disconnect a pad sitting on No2+ at the exact moment of the hold).
    // padInitializeAny: sample + from whichever slot the physical or switch-mcp virtual pad landed in.
    PadState pad; padInitializeAny(&pad);
    // Pump appletMainLoop() so our layer stays composited (an application must service the applet channel
    // to hold the screen). This is called from the guest's stdout write — i.e. BEFORE the guest exits —
    // so the OS has not yet queued our Exit and appletMainLoop() returns true; the app stays foreground
    // and receives +. (At/after exit_group the OS has already queued Exit -> appletMainLoop() goes false
    // and Horizon force-reaps us, so a hold there just shows HOME. That is why the hook lives in the write.)
    while (appletMainLoop()) {
        padUpdate(&pad);
        if (padGetButtonsDown(&pad) & HidNpadButton_Plus) break;
        consoleUpdate(NULL);
        svcSleepThread(16000000ULL);
    }
    rlog("hold: + pressed, exiting");
}

// Keep the application in the foreground DURING a long guest run. box64 emulates in a tight loop and
// never returns to an appletMainLoop()-driven main loop, so on a multi-second run (Wine loading ~10 DLLs)
// the OS stops compositing our layer and shows HOME — so the guest's output is produced off-screen and
// the exit hold then can't reclaim focus. Pumping appletMainLoop() + re-presenting the console on a
// throttle keeps our layer alive. Called from the hot mmap path (nx_virtmem.c). Main thread only (the
// wineserver thread must never touch applet/console); throttled to ~30 ms so it's cheap on the hot path.
void nx_applet_keepalive(void) {
    if (threadGetCurHandle() != g_main_thread) return;
    static u64 last = 0;
    u64 now = svcGetSystemTick();
    if (now - last < 576000ULL) return;   // 19200 ticks/ms * 30 ms
    last = now;
    appletMainLoop();
    consoleUpdate(NULL);
}

// main()'s tail hold (guests that DO unwind back to main — a simple static guest, unlike Wine cmd.exe).
// Waits for + when KX_WAIT_EXIT is set; otherwise a fixed on-screen hold so the result is screenshot-
// readable. Then tears down. Idempotent.
static void nx_hold_and_exit(void) {
    static int done = 0; if (done) return; done = 1;
    nx_wait_for_exit_button();                 // + hold (real HW + KX_WAIT_EXIT); no-op / already-done otherwise
    if (!g_hold_done) {
        kout("\n(returning to the menu shortly)\n");
        consoleUpdate(NULL);
        if (g_homebrew) for (int i = 0; i < 8 * 60 && appletMainLoop(); ++i) svcSleepThread(16000000ULL);
        else            for (int i = 0; i < 30 * 60; ++i) svcSleepThread(16000000ULL);
    }
    if (g_have_romfs) romfsExit();
    if (g_nxlink_fd >= 0) close(g_nxlink_fd);
    if (g_homebrew) socketExit();
    consoleExit(NULL);
}

int main(int argc, char **argv) {
    // Drop a COMMITTED marker before anything else. consoleInit()'s first malloc is exactly where a
    // null-heap title used to Data-Abort, so writing this first lets us tell "crashed before main"
    // (no file) from "crashed in consoleInit" (file has only this line) from "reached the backend".
    { int fd = open("sdmc:/box64/box64-result.txt", O_WRONLY | O_CREAT | O_TRUNC, 0666);
      if (fd >= 0) { write(fd, "main:entered\n", 13); close(fd); } fsdevCommitDevice("sdmc"); }
    consoleInit(NULL);
    g_main_thread = threadGetCurHandle();   // only this thread may drive the console (see nx_guest_output)
    // nxlink is a homebrew-only channel (the netloader host address comes from the hbloader ABI). An
    // installed title (NSP) has no bsd/nifm services in its NPDM, so socketInitializeDefault() would
    // HANG it on a black screen — do socket/nxlink ONLY for a homebrew NRO (which has a heap override).
    // A title just prints to its own console (read via a screenshot). Connect WITHOUT redirecting
    // stdout (kout mirrors manually) so the console keeps the screen; g_nxlink_fd <0 when not netloaded.
    bool homebrew = envHasHeapOverride();
    g_homebrew = homebrew;
    if (homebrew) {
        socketInitializeDefault();
        g_nxlink_fd = nxlinkConnectToHost(false, false);
    }
    // Pad/HID setup happens after load_env_file() below (padConfigureInput(8, ...)): an application
    // that never declares supported npad styles/IDs gets its Bluetooth controllers POWERED OFF by the
    // npad arbiter on real HW (no assignable slot — the retail "extra controller in a 1-player game"
    // behavior; a paired Pro-Controller-alike drops into a wake/re-pair/drop loop the moment box64
    // takes foreground). Gated off Ryujinx: padConfigureInput crashes Ryujinx 1.2.72's HID service
    // (KeyNotFoundException) before we ever reach the guest; KX_PAD_CONFIG=1 forces it there.

    // Mount the romfs embedded in the NRO (holds the x86-64 guests: romfs:/hello, /loop, /churn), so a
    // single nxlink push carries box64 + its guest. Only the homebrew NRO has embedded romfs; a title
    // (NSP) has none and loads its guest from the SD — and calling romfsInit() there CRASHES Ryujinx
    // (GetRomFs KeyNotFoundException) instead of erroring, so gate it on the homebrew case.
    bool have_romfs = homebrew && R_SUCCEEDED(romfsInit());
    g_have_romfs = have_romfs;
    // Guest path: argv[1] when a launcher provides one (e.g. `nxlink --args romfs:/loop box64.nro`),
    // else the embedded romfs:/hello, else the SD compile default when romfs is unavailable.
    const char *guest = (argc >= 2 && argv[1] && argv[1][0]) ? argv[1]
                        : (have_romfs ? "romfs:/hello" : NX_GUEST_PATH);

    { char b[256]; snprintf(b, sizeof b, "nx_main: start guest=%s argc=%d romfs=%d\n", guest, argc, (int)have_romfs); kdbg(b); }
    { char b[256]; snprintf(b, sizeof b, "start guest=%s argc=%d homebrew=%d", guest, argc, (int)homebrew); rlog(b); }
    kout("box64 (Horizon)\nguest: %s\n\n", guest);

    // Report the active memory backend up front: UNSAFE (real svcMapPhysicalMemoryUnsafe arena — an
    // Applet-pool NSP on real HW), PHYS (svcMapPhysicalMemory arena — Ryujinx / provisioned title), or
    // heap-fallback (plain NRO). Forces backend selection; sysres is non-zero only on the PHYS path.
    // heap = the newlib heap libnx handed us (svcSetHeapSize on a title). On the heap-fallback backend
    // THIS is the guest's real memory, so report it: it distinguishes a real Application-pool heap
    // (hundreds of MiB) from the 16 MiB static-.bss last resort.
    extern char *fake_heap_start, *fake_heap_end;
    // Memory-budget diagnostics from __libnx_initheap (svcGetInfo Total/UsedMemorySize): memtotal is the
    // process's whole pool, memused the code+stacks used before our heap — so memtotal-memused is the
    // grantable heap ceiling, and heap is what we actually took (ceiling minus a safety margin).
    extern u64 nx_mem_total_size, nx_mem_used_at_init;
    unsigned long long memtot = (unsigned long long)nx_mem_total_size, memuse = (unsigned long long)nx_mem_used_at_init;
    unsigned long long heap_sz = (unsigned long long)(fake_heap_end - fake_heap_start);
    // Load box64.env BEFORE the backend probe: nx_vm_status() -> vm_ensure_init() picks the mmap backend on
    // its FIRST call and must already see env overrides like KX_FORCE_HEAP (else it commits to PHYS before
    // the env is read). Idempotent setenv, so it's safe that we don't call load_env_file again later.
    load_env_file();
    // Declare supported pads to Horizon ASAP (after load_env_file so KX_PAD_CONFIG can force it on):
    // without a hidSetSupportedNpadStyleSet/IdType call the npad arbiter cannot bind a Bluetooth
    // controller to any slot and powers it off (see the comment above). 8 players so a switch-mcp
    // HDLS virtual pad sitting on No1 can't bump the physical pad out of the supported range.
    // hidInitialize() itself already ran in libnx's default __appInit ("hid" is in the NPDM).
    if (detectMesosphere() || getenv("KX_PAD_CONFIG"))
        padConfigureInput(8, HidNpadStyleSet_NpadStandard);
    { uintptr_t vb = 0; size_t vs = 0; unsigned long long sr = 0;
      int st = nx_vm_status(&vb, &vs, &sr);
      const char *name = (st == 2) ? "UNSAFE" : (st == 1) ? "PHYS" : "heap-fallback";
      kout("nx_vm: %s heap=0x%llx memtotal=0x%llx memused=0x%llx sysres=0x%llx base=0x%llx size=0x%llx\n\n",
           name, heap_sz, memtot, memuse, sr, (unsigned long long)vb, (unsigned long long)vs);
      char rb[256]; snprintf(rb, sizeof rb, "backend=%s heap=0x%llx memtotal=0x%llx memused=0x%llx sysres=0x%llx base=0x%llx size=0x%llx",
           name, heap_sz, memtot, memuse, sr, (unsigned long long)vb, (unsigned long long)vs); rlog(rb); }
    // M2.7 (Wine address-space diagnosis): dump the process memory regions so we know whether Wine's
    // fixed low VAs (KUSER_SHARED_DATA @0x7ffe0000, the low-4GB reservation) fall inside any region that
    // svcMapMemory can target (Alias/Stack). If they don't, box64-nx's 1:1 mapping can't satisfy Wine.
    { u64 aslr_a=0,aslr_s=0,stk_a=0,stk_s=0,ali_a=0,ali_s=0,heap_a=0,heap_s=0;
      svcGetInfo(&aslr_a, InfoType_AslrRegionAddress,  CUR_PROCESS_HANDLE, 0);
      svcGetInfo(&aslr_s, InfoType_AslrRegionSize,     CUR_PROCESS_HANDLE, 0);
      svcGetInfo(&stk_a,  InfoType_StackRegionAddress, CUR_PROCESS_HANDLE, 0);
      svcGetInfo(&stk_s,  InfoType_StackRegionSize,    CUR_PROCESS_HANDLE, 0);
      svcGetInfo(&ali_a,  InfoType_AliasRegionAddress, CUR_PROCESS_HANDLE, 0);
      svcGetInfo(&ali_s,  InfoType_AliasRegionSize,    CUR_PROCESS_HANDLE, 0);
      svcGetInfo(&heap_a, InfoType_HeapRegionAddress,  CUR_PROCESS_HANDLE, 0);
      svcGetInfo(&heap_s, InfoType_HeapRegionSize,     CUR_PROCESS_HANDLE, 0);
      char rb[256]; snprintf(rb, sizeof rb,
        "regions aslr=[0x%llx+0x%llx) stack=[0x%llx+0x%llx) alias=[0x%llx+0x%llx) heap=[0x%llx+0x%llx)",
        (unsigned long long)aslr_a,(unsigned long long)aslr_s,(unsigned long long)stk_a,(unsigned long long)stk_s,
        (unsigned long long)ali_a,(unsigned long long)ali_s,(unsigned long long)heap_a,(unsigned long long)heap_s);
      rlog(rb); }
    consoleUpdate(NULL);

    // box64 rewrites argv in place assuming the strings are contiguous (as a Linux kernel lays
    // them out): it computes diff = prog - argv[0] and shifts. Separate string literals break that
    // (garbage diff -> huge memset), so pack "box64\0<guest path>\0<arg>\0..." into one buffer.
    static char  argbuf[4096];
    static char *b_argv[64];
    size_t o = 0; int ac = 0;
    #define NX_PUSH_ARG(...) do { \
        b_argv[ac++] = &argbuf[o]; \
        o += 1 + (size_t)snprintf(&argbuf[o], sizeof(argbuf) - o, __VA_ARGS__); \
    } while (0)
    NX_PUSH_ARG("box64");
    NX_PUSH_ARG("%s", guest);
    // Extra GUEST args from sdmc:/box64/box64-args (one per line) — FTP-flippable without a rebuild.
    // e.g. to run `wine64 --version`: stage the wine64 loader as box64-guest and put "--version" here.
    { int afd = open("sdmc:/box64/box64-args", O_RDONLY);
      if (afd >= 0) {
        static char fb[2048]; ssize_t n = read(afd, fb, sizeof fb - 1); close(afd);
        if (n > 0) { fb[n] = '\0'; char *p = fb;
          while (*p && ac < 62) {
            while (*p=='\n'||*p=='\r'||*p==' '||*p=='\t') p++;   // skip leading whitespace
            char *s = p;
            while (*p && *p!='\n' && *p!='\r') p++;              // to end of line
            char *e = p; if (*p) *p++ = '\0';
            while (e>s && (e[-1]==' '||e[-1]=='\t')) *--e = '\0'; // trim trailing whitespace
            if (*s) NX_PUSH_ARG("%s", s);
          }
        }
      }
    }
    b_argv[ac] = NULL;
    { char b[128]; snprintf(b, sizeof b, "guest argc=%d argv1=%s", ac, ac>2?b_argv[2]:"(none)"); rlog(b); }
    x64emu_t   *emu = NULL;
    elfheader_t *elf = NULL;
    int code = -1;

    rlog("pre-initialize");
    // M2.1 bring-up: no shell env on Horizon, so inject box64's log level here (printf_log ->
    // svcOutputDebugString, which Ryujinx logs). 2=verbose (lib load, reloc, KX reroute markers).
    // Default 0 (quiet) — verbose per-instruction/reloc logging via svcOutputDebugString throttles
    // Ryujinx to a crawl for a big guest like Wine+cmd.exe. Override with BOX64_LOG in box64.env when
    // debugging a specific load/reloc issue.
    setenv("BOX64_LOG", "0", 1);
    // Fix 1: place the un-relocatable EXE base (start.exe @0x140000000) + KUSER on the CodeMemory slab
    // FIRST — before initialize()/the wineserver spawn/any Wine module — so their MapOwner is deterministic
    // (nothing adjacent to trigger 0xdc01). This is the residual ASLR-flakiness fix (see nx_virtmem.c).
    { extern void nx_prereserve_fixed(void); nx_prereserve_fixed(); }
    // (box64.env already loaded above, before the backend probe, so KX_FORCE_HEAP applies to vm_init.)
    if (initialize(ac, (const char **)b_argv, environ, &emu, &elf, 1)) {
        kdbg("nx_main: initialize failed\n");
        kout("box64: initialize failed (guest missing or not a valid x86-64 ELF?)\n");
        rlog("initialize FAILED");
    } else {
        kdbg("nx_main: emulate\n");
        rlog("initialize ok, emulate");
        // M2.5 process model: if this is a Wine run that will need the wineserver (WINEPREFIX set),
        // pre-start wineserver64 as an in-process second guest (nx_spawn.c) and wait briefly for it
        // to bind+listen, so the wine client's server_connect() finds the socket and never forks.
        // Gated on KX_WINESERVER=1 in box64.env so plain guests are unaffected.
        if (getenv("KX_WINESERVER")) {
            extern int nx_spawn_wineserver(const char** envp);
            extern int nx_spawn_server_ready(void);
            if (nx_spawn_wineserver((const char**)environ) == 0) {
                rlog("nx_spawn: wineserver launched, waiting for listen");
                for (int i = 0; i < 400 && !nx_spawn_server_ready(); ++i)
                    svcSleepThread(10000000ULL);   // up to ~4 s
                rlog(nx_spawn_server_ready() ? "nx_spawn: wineserver LISTENING"
                                             : "nx_spawn: wineserver not listening (continuing anyway)");
            }
        }
        code = emulate(emu, elf);
        kout("\nguest exited: %d\n", code);
        { char b[48]; snprintf(b, sizeof b, "nx_main: guest exited %d\n", code); kdbg(b); }
        { char b[64]; snprintf(b, sizeof b, "guest exited=%d", code); rlog(b); }
    }
    consoleUpdate(NULL);   // present the final frame
    // A guest that unwinds back here (a simple static guest) holds + cleans up now. Wine cmd.exe instead
    // exits from inside emulate() (exit_group) and never reaches this line — it already held during its
    // stdout write (nx_guest_output -> nx_wait_for_exit_button). g_hold_done keeps it to a single hold.
    nx_hold_and_exit();
    return (code < 0) ? 0 : code;
}

#endif // __SWITCH__
