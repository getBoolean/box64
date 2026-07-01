// KurokoNX — libnx NRO entry for box64 on Horizon (replaces src/main.c on __SWITCH__).
//
// box64's normal main() takes (argc, argv, env) from the shell. A homebrew NRO has no
// shell, so we synthesize argv = {"box64", "<guest path>"} and drive box64's own
// initialize()/emulate() (src/core.c). Guest stdout (write(1)) and box64's logs surface
// on the libnx console; a couple of svcOutputDebugString markers also land in the Ryujinx
// log for headless tracing (mirrors the M0 kdbg approach).
#ifdef __SWITCH__

#include <switch.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>   // environ

#include "core.h"     // initialize(), emulate(), x64emu_t, elfheader_t

// Guest path on the SD card. Overridable at build time; default mirrors the M0 convention.
#ifndef KURO_GUEST_PATH
#define KURO_GUEST_PATH "sdmc:/kurokonx/m1-hello"
#endif

static void kdbg(const char *s) { svcOutputDebugString(s, strlen(s)); }

int main(int argc, char **argv) {
    (void)argc; (void)argv;

    consoleInit(NULL);
    PadState pad;
    padConfigureInput(1, HidNpadStyleSet_NpadStandard);
    padInitializeDefault(&pad);

    kdbg("kuro_main: start\n");
    printf("KurokoNX \xe2\x80\x94 box64 (M1.1)\nguest: %s\n\n", KURO_GUEST_PATH);
    consoleUpdate(NULL);

    // box64 rewrites argv in place assuming the strings are contiguous (as a Linux kernel lays
    // them out): it computes diff = prog - argv[0] and shifts. Separate string literals break that
    // (garbage diff -> huge memset), so pack "box64\0<guest path>\0" into one buffer.
    static char argbuf[600];
    size_t o = 0;
    char *a0 = &argbuf[o]; o += 1 + (size_t)snprintf(a0, sizeof(argbuf) - o, "box64");
    char *a1 = &argbuf[o]; o += 1 + (size_t)snprintf(a1, sizeof(argbuf) - o, "%s", KURO_GUEST_PATH);
    (void)o;
    const char *b_argv[] = { a0, a1, NULL };
    x64emu_t   *emu = NULL;
    elfheader_t *elf = NULL;
    int code = -1;

    if (initialize(2, b_argv, environ, &emu, &elf, 1)) {
        kdbg("kuro_main: initialize failed\n");
        printf("box64: initialize failed (guest missing or not a valid x86-64 ELF?)\n");
    } else {
        kdbg("kuro_main: emulate\n");
        code = emulate(emu, elf);
        printf("\nguest exited: %d\n", code);
        { char b[48]; snprintf(b, sizeof b, "kuro_main: guest exited %d\n", code); kdbg(b); }
    }
    printf("\n(returning to the menu shortly)\n");
    consoleUpdate(NULL);   // present the final frame ONCE
    (void)pad;

    // Hold the result on screen briefly, then exit cleanly. We deliberately do NOT poll HID
    // (padUpdate) or re-present (consoleUpdate) in this loop: on Ryujinx those libnx service
    // calls (_hidGetNpadInternalState / framebufferBegin) abort (svcBreak) after the app goes
    // idle for a few seconds. appletMainLoop() alone is stable and lets the OS request exit.
    for (int i = 0; i < 8 * 60 && appletMainLoop(); ++i)
        svcSleepThread(16000000ULL);   // ~16 ms; ~8 s total, or until the OS asks us to quit
    consoleExit(NULL);
    return (code < 0) ? 0 : code;
}

#endif // __SWITCH__
