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
#include <unistd.h>   // environ

#include "core.h"     // initialize(), emulate(), x64emu_t, elfheader_t

// Default guest path on the SD card. Overridable at build time (-DNX_GUEST_PATH=... /
// the NX_GUEST_PATH CMake cache var) or at runtime via argv[1].
#ifndef NX_GUEST_PATH
#define NX_GUEST_PATH "sdmc:/box64/box64-guest"
#endif

static void kdbg(const char *s) { svcOutputDebugString(s, strlen(s)); }

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
    consoleInit(NULL);
    // Connect to the nxlink host WITHOUT redirecting stdout (kout mirrors manually), so the Switch
    // console keeps the screen and results also stream to the PC. <0 when not launched via nxlink.
    socketInitializeDefault();
    g_nxlink_fd = nxlinkConnectToHost(false, false);
    PadState pad;
    padConfigureInput(1, HidNpadStyleSet_NpadStandard);
    padInitializeDefault(&pad);

    // Mount the romfs embedded in this NRO (holds the x86-64 guests: romfs:/hello, /loop, /churn),
    // so a single nxlink push carries box64 + its guest — no SD staging needed for a hardware test.
    bool have_romfs = R_SUCCEEDED(romfsInit());
    // Guest path: argv[1] when a launcher provides one (e.g. `nxlink --args romfs:/loop box64.nro`),
    // else the embedded romfs:/hello, else the SD compile default when romfs is unavailable.
    const char *guest = (argc >= 2 && argv[1] && argv[1][0]) ? argv[1]
                        : (have_romfs ? "romfs:/hello" : NX_GUEST_PATH);

    kdbg("nx_main: start\n");
    kout("box64 (Horizon)\nguest: %s\n\n", guest);
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

    if (initialize(2, b_argv, environ, &emu, &elf, 1)) {
        kdbg("nx_main: initialize failed\n");
        kout("box64: initialize failed (guest missing or not a valid x86-64 ELF?)\n");
    } else {
        kdbg("nx_main: emulate\n");
        code = emulate(emu, elf);
        kout("\nguest exited: %d\n", code);
        { char b[48]; snprintf(b, sizeof b, "nx_main: guest exited %d\n", code); kdbg(b); }
    }
    kout("\n(returning to the menu shortly)\n");
    consoleUpdate(NULL);   // present the final frame ONCE
    (void)pad;

    // Hold the result on screen briefly, then exit cleanly. We deliberately do NOT poll HID
    // (padUpdate) or re-present (consoleUpdate) in this loop: on Ryujinx those libnx service
    // calls (_hidGetNpadInternalState / framebufferBegin) abort (svcBreak) after the app goes
    // idle for a few seconds. appletMainLoop() alone is stable and lets the OS request exit.
    for (int i = 0; i < 8 * 60 && appletMainLoop(); ++i)
        svcSleepThread(16000000ULL);   // ~16 ms; ~8 s total, or until the OS asks us to quit
    if (have_romfs) romfsExit();
    if (g_nxlink_fd >= 0) close(g_nxlink_fd);
    socketExit();
    consoleExit(NULL);
    return (code < 0) ? 0 : code;
}

#endif // __SWITCH__
