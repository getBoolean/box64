// KurokoNX shim — <sys/reg.h> (glibc register defs; only __WORDSIZE is needed,
// as elfhacks.c falls back to it for __ELF_NATIVE_CLASS). 64-bit target.
#pragma once
#ifdef __SWITCH__
#ifndef __WORDSIZE
#define __WORDSIZE 64
#endif
#endif // __SWITCH__
