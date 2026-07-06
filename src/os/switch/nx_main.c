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

// nxlink host socket (>=0 only when launched via nxlink) — lets a hardware run stream box64's
// status/result to the PC terminal while it also shows on the Switch console.
static int g_nxlink_fd = -1;

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

int main(int argc, char **argv) {
    // Drop a COMMITTED marker before anything else. consoleInit()'s first malloc is exactly where a
    // null-heap title used to Data-Abort, so writing this first lets us tell "crashed before main"
    // (no file) from "crashed in consoleInit" (file has only this line) from "reached the backend".
    { int fd = open("sdmc:/box64/box64-result.txt", O_WRONLY | O_CREAT | O_TRUNC, 0666);
      if (fd >= 0) { write(fd, "main:entered\n", 13); close(fd); } fsdevCommitDevice("sdmc"); }
    consoleInit(NULL);
    // nxlink is a homebrew-only channel (the netloader host address comes from the hbloader ABI). An
    // installed title (NSP) has no bsd/nifm services in its NPDM, so socketInitializeDefault() would
    // HANG it on a black screen — do socket/nxlink ONLY for a homebrew NRO (which has a heap override).
    // A title just prints to its own console (read via a screenshot). Connect WITHOUT redirecting
    // stdout (kout mirrors manually) so the console keeps the screen; g_nxlink_fd <0 when not netloaded.
    bool homebrew = envHasHeapOverride();
    if (homebrew) {
        socketInitializeDefault();
        g_nxlink_fd = nxlinkConnectToHost(false, false);
    }
    // NB: no HID init — box64 doesn't poll a pad (the hold loop below is appletMainLoop-only), and
    // padConfigureInput crashes Ryujinx 1.2.72's HID service (KeyNotFoundException) before we ever
    // reach the guest. Real HW doesn't need it either.

    // Mount the romfs embedded in the NRO (holds the x86-64 guests: romfs:/hello, /loop, /churn), so a
    // single nxlink push carries box64 + its guest. Only the homebrew NRO has embedded romfs; a title
    // (NSP) has none and loads its guest from the SD — and calling romfsInit() there CRASHES Ryujinx
    // (GetRomFs KeyNotFoundException) instead of erroring, so gate it on the homebrew case.
    bool have_romfs = homebrew && R_SUCCEEDED(romfsInit());
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
    unsigned long long heap_sz = (unsigned long long)(fake_heap_end - fake_heap_start);
    { uintptr_t vb = 0; size_t vs = 0; unsigned long long sr = 0;
      int st = nx_vm_status(&vb, &vs, &sr);
      const char *name = (st == 2) ? "UNSAFE" : (st == 1) ? "PHYS" : "heap-fallback";
      kout("nx_vm: %s heap=0x%llx sysres=0x%llx base=0x%llx size=0x%llx\n\n",
           name, heap_sz, sr, (unsigned long long)vb, (unsigned long long)vs);
      char rb[192]; snprintf(rb, sizeof rb, "backend=%s heap=0x%llx sysres=0x%llx base=0x%llx size=0x%llx",
           name, heap_sz, sr, (unsigned long long)vb, (unsigned long long)vs); rlog(rb); }
    consoleUpdate(NULL);

    // box64 rewrites argv in place assuming the strings are contiguous (as a Linux kernel lays
    // them out): it computes diff = prog - argv[0] and shifts. Separate string literals break that
    // (garbage diff -> huge memset), so pack "box64\0<guest path>\0" into one buffer.
    static char argbuf[600];
    size_t o = 0;
    char *a0 = &argbuf[o]; o += 1 + (size_t)snprintf(a0, sizeof(argbuf) - o, "box64");
    char *a1 = &argbuf[o]; o += 1 + (size_t)snprintf(a1, sizeof(argbuf) - o, "%s", guest);
    (void)o;
    const char *b_argv[] = { a0, a1, NULL };
    x64emu_t   *emu = NULL;
    elfheader_t *elf = NULL;
    int code = -1;

    rlog("pre-initialize");
    if (initialize(2, b_argv, environ, &emu, &elf, 1)) {
        kdbg("nx_main: initialize failed\n");
        kout("box64: initialize failed (guest missing or not a valid x86-64 ELF?)\n");
        rlog("initialize FAILED");
    } else {
        kdbg("nx_main: emulate\n");
        rlog("initialize ok, emulate");
        code = emulate(emu, elf);
        kout("\nguest exited: %d\n", code);
        { char b[48]; snprintf(b, sizeof b, "nx_main: guest exited %d\n", code); kdbg(b); }
        { char b[64]; snprintf(b, sizeof b, "guest exited=%d", code); rlog(b); }
    }
    kout("\n(returning to the menu shortly)\n");
    consoleUpdate(NULL);   // present the final frame ONCE

    // Hold the result on screen. An NRO returns to hbmenu when the OS asks (or after ~8 s). A title
    // (application) can't return to a menu on its own — a self-exiting application makes am show "The
    // software was closed because an error occurred", and appletMainLoop() returns false for it right
    // away — so hold ~30 s with a fixed sleep (pumping appletMainLoop but not exiting on it) so the
    // result is readable via a screenshot. Do NOT re-present/poll HID here (Ryujinx aborts on those).
    if (homebrew) {
        for (int i = 0; i < 8 * 60 && appletMainLoop(); ++i)
            svcSleepThread(16000000ULL);
    } else {
        for (int i = 0; i < 30 * 60; ++i) { appletMainLoop(); svcSleepThread(16000000ULL); }
    }
    if (have_romfs) romfsExit();
    if (g_nxlink_fd >= 0) close(g_nxlink_fd);
    if (homebrew) socketExit();
    consoleExit(NULL);
    return (code < 0) ? 0 : code;
}

#endif // __SWITCH__
