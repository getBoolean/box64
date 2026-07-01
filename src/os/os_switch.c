// box64 — Horizon/Switch OS backend (box64-nx port).
//
// Implements the src/include/os.h interface for Nintendo Switch's Horizon OS (devkitA64 + libnx).
// Based on os_linux.c: the box64-internal wrappers are kept verbatim; only the handful of
// host-OS-touching functions are swapped to the libnx-backed "kuro-posix" shim (see
// src/os/switch/nx_posix.h). Built only for __SWITCH__ (CMake selects this instead of os_linux.c).
#ifdef __SWITCH__

#include <unistd.h>
#include <stdint.h>
#include <sys/stat.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#ifdef __SWITCH__
#include <switch.h>   // svcOutputDebugString
#endif

#include "os.h"
#include "signals.h"
#include "emu/x64int_private.h"
#include "bridge.h"
#include "elfloader.h"
#include "env.h"
#include "debug.h"
#include "x64tls.h"
#include "librarian.h"
#include "emu/x64emu_private.h"

#include "switch/nx_posix.h"   // libnx-backed host primitives

// --- host-OS functions: routed to kuro-posix -------------------------------------------------
int GetTID(void) { return nx_gettid(); }
int SchedYield(void) { return nx_sched_yield(); }

void* InternalMmap(void* addr, unsigned long length, int prot, int flags, int fd, ssize_t offset) {
    return nx_mmap(addr, length, prot, flags, fd, offset);
}
int InternalMunmap(void* addr, unsigned long length) {
    return nx_munmap(addr, length);
}

// Horizon is 64-bit only and has no process "personality"/mallopt — no-op.
void PersonalityAddrLimit32Bit(void) {}

// --- box64-internal wrappers: identical to os_linux.c ----------------------------------------
int IsBridgeSignature(char s, char c) { return s == 'S' && c == 'C'; }
void EmuInt3(void* emu, void* addr) { return x64Int3((x64emu_t*)emu, (uintptr_t*)addr); }
int IsNativeCall(uintptr_t addr, int is32bits, uintptr_t* calladdress, uint16_t* retn) {
    return isNativeCallInternal(addr, is32bits, calladdress, retn);
}
void* EmuFork(void* emu, int forktype) { return x64emu_fork((x64emu_t*)emu, forktype); }
void EmuX64Syscall(void* emu) { x64Syscall((x64emu_t*)emu); }
void EmuX64Syscall_linux(void* emu) { x64Syscall_linux((x64emu_t*)emu); }
void EmuX86Syscall(void* emu) { x86Syscall((x64emu_t*)emu); }

extern int box64_is32bits;

void* GetSeg43Base(void* emu) {
    tlsdatasize_t* ptr = ((x64emu_t*)emu)->tlsdata;
    return ptr ? ptr->data : NULL;
}

void* GetSegmentBase(void* emu, uint32_t desc) {
    if (!desc) {
        printf_log(LOG_NONE, "Warning, accessing segment NULL\n");
        return NULL;
    }
    int base = desc >> 3;
    int is_ldt = !!(desc & 4);
    if (!box64_nolibs) {
        if (!box64_is32bits && (base == 0x8)) return GetSeg43Base((x64emu_t*)emu);
        if (box64_is32bits && (base == 0x6)) return GetSeg43Base((x64emu_t*)emu);
    }
    if (base > 15) {
        printf_log(LOG_NONE, "Warning, accessing segment unknown 0x%x or unset\n", desc);
        return NULL;
    }
    base_segment_t* segs = is_ldt ? ((x64emu_t*)emu)->segldt
                                  : ((base > 5) ? ((x64emu_t*)emu)->seggdt : my_context->seggdt);
    return (void*)segs[base].base;
}

const char* GetBridgeName(void* p) { return getBridgeName(p); }

static __thread char native_name[500] = { 0 };

// No dladdr on Horizon (no dlopen): resolve via the bridge + box64's own maplib only.
const char* GetNativeName(void* p, int lib) {
    (void)lib;
    const char* n = GetBridgeName(p);
    if (n) return n;
    const char* ret = GetNameOffset(my_context->maplib, p);
    if (ret) return ret;
    sprintf(native_name, "%s(%p)", "???", p);
    return native_name;
}

int IsAddrElfOrFileMapped(uintptr_t addr) {
    return FindElfAddress(my_context, addr) || IsAddrFileMappedNoMemFD(addr);
}

extern FILE* ftrace;
extern char* ftrace_name;
static int trace_fd = -1;

static void checkFtrace() {
    trace_fd = fileno(ftrace);
    if (trace_fd < 0 || lseek(trace_fd, 0, SEEK_CUR) == (off_t)-1) {
        ftrace = fopen(ftrace_name, "a");
        trace_fd = fileno(ftrace);
        printf_log(LOG_INFO, "%04d|Recreated trace because fd was invalid\n", GetTID());
    }
}

void PrintfFtrace(int prefix, const char* fmt, ...) {
    if (ftrace_name) checkFtrace();
    else if (trace_fd == -1) trace_fd = fileno(ftrace);

    static const char* names[2] = { "BOX64", "BOX32" };
    char tmp[8192];
    if (prefix && (ftrace == stdout || ftrace == stderr)) {
        if (prefix > 1) sprintf(tmp, "[\033[31m%s\033[0m] ", names[box64_is32bits]);
        else            sprintf(tmp, "[%s] ", names[box64_is32bits]);
        write(trace_fd, tmp, strlen(tmp));
    }
    va_list args;
    va_start(args, fmt);
    vsprintf(tmp, fmt, args);
    fflush(ftrace);
    va_end(args);
    write(trace_fd, tmp, strlen(tmp));
#ifdef __SWITCH__
    // Also emit to the debug log so box64's diagnostics are visible in the Ryujinx log / on a
    // debugger (the console fd only reaches the on-screen framebuffer).
    svcOutputDebugString(tmp, strlen(tmp));
#endif
}

void* GetEnv(const char* name) { return getenv(name); }

int FileExist(const char* filename, int flags) {
    struct stat sb;
    if (stat(filename, &sb) == -1) return 0;
    if (flags == -1) return 1;
    if (flags & IS_FILE) {
        if (!S_ISREG(sb.st_mode)) return 0;
    } else if (!S_ISDIR(sb.st_mode)) return 0;
#ifndef __SWITCH__
    // On Horizon the guest lives on the SD card (FAT via libnx), which reports no Unix execute
    // bit, so an ELF would wrongly fail box64's IS_EXECUTABLE check. Any readable regular file
    // is considered executable here.
    if (flags & IS_EXECUTABLE) {
        if ((sb.st_mode & S_IXUSR) != S_IXUSR) return 0;
    }
#endif
    return 1;
}

int MakeDir(const char* folder) {
    int ret = mkdir(folder, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
    if (!ret || ret == EEXIST) return 1;
    return 0;
}

size_t FileSize(const char* filename) {
    struct stat sb;
    if (stat(filename, &sb) == -1) return 0;
    if (!S_ISREG(sb.st_mode)) return 0;
    return sb.st_size;
}

#endif // __SWITCH__
