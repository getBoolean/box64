// box64-nx shim — <asm/stat.h>. box64 includes it but the kernel struct stat is
// only referenced in commented-out alignment notes; newlib's <sys/stat.h> suffices.
#pragma once
#ifdef __SWITCH__
#include <sys/stat.h>
#endif // __SWITCH__
