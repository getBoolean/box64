#ifndef __OS_H_
#define __OS_H_

#include <stdint.h>
#include <sys/types.h>

#ifndef _WIN32
#include <dlfcn.h>
#include <sys/mman.h>
#else
#include <windows.h>
typedef __int64 ssize_t;
#define dlsym(a, b) NULL
#define box_strdup(a) strdup(a)

#define PROT_READ  0x1
#define PROT_WRITE 0x2
#define PROT_EXEC  0x4

#define MAP_FAILED    ((void*)-1)
#define MAP_PRIVATE   0x02
#define MAP_FIXED     0x10
#define MAP_ANONYMOUS 0x20
#define MAP_32BIT     0x40
#define MAP_NORESERVE 0

void* mmap(void* addr, size_t length, int prot, int flags, int fd, off_t offset);
int munmap(void* addr, size_t length);
int mprotect(void* addr, size_t len, int prot);

void x86Int(void* emu, int code);

void* WinMalloc(size_t size);
void* WinRealloc(void* ptr, size_t size);
void* WinCalloc(size_t nmemb, size_t size);
void WinFree(void* ptr);
#endif

void* InternalMmap(void* addr, unsigned long length, int prot, int flags, int fd, ssize_t offset);
int InternalMunmap(void* addr, unsigned long length);

int GetTID(void);
int SchedYield(void);

void EmuX64Syscall(void* emu);
void EmuX64Syscall_linux(void* emu);
void EmuX86Syscall(void* emu);

void* GetSeg43Base(void* emu);
void* GetSegmentBase(void* emu, uint32_t desc);

// These functions only applies to Linux --------------------------
int IsBridgeSignature(char s, char c);
int IsNativeCall(uintptr_t addr, int is32bits, uintptr_t* calladdress, uint16_t* retn);
void EmuInt3(void* emu, void* addr);
void* EmuFork(void* emu, int forktype);

void PersonalityAddrLimit32Bit(void);

int IsAddrElfOrFileMapped(uintptr_t addr);
const char* GetNativeName(void* p, int lib);
const char* GetBridgeName(void* p);
// ----------------------------------------------------------------

#ifndef _WIN32
#include <setjmp.h>
#ifdef __SWITCH__
// newlib provides setjmp/longjmp + jmp_buf, but not glibc's sigsetjmp/struct
// __jmp_buf_tag. Emulate glibc's tag struct over newlib's jmp_buf so box64's
// (non-ANDROID) jmpbuf code compiles unchanged. Single-threaded interpreter
// needs no signal-mask save/restore, so sig* collapse to plain setjmp/longjmp.
typedef struct __kuro_jmp_buf_tag { jmp_buf __jb; } __kuro_jmp_buf_tag;
#define LongJmp(env, val)        longjmp(((__kuro_jmp_buf_tag*)(env))->__jb, (val))
#define SigSetJmp(env, savemask) setjmp(((__kuro_jmp_buf_tag*)(env))->__jb)
#define sigsetjmp(env, savemask) setjmp(((__kuro_jmp_buf_tag*)(env))->__jb)
#define siglongjmp(env, val)     longjmp(((__kuro_jmp_buf_tag*)(env))->__jb, (val))
#else
#define LongJmp longjmp
#define SigSetJmp sigsetjmp
#endif
#else
#define LongJmp(a, b)
#define SigSetJmp(a, b) 0
#endif

#ifndef _WIN32
#include <setjmp.h>
#define NEW_JUMPBUFF(name) \
    static __thread JUMPBUFF name
#if defined(ANDROID)
#define JUMPBUFF sigjmp_buf
#define GET_JUMPBUFF(name) name
#elif defined(__SWITCH__)
#define JUMPBUFF __kuro_jmp_buf_tag
#define GET_JUMPBUFF(name) &name
#else
#define JUMPBUFF struct __jmp_buf_tag
#define GET_JUMPBUFF(name) &name
#endif
#else
#define JUMPBUFF int
#define NEW_JUMPBUFF(name)
#define GET_JUMPBUFF(name) NULL
#endif

#define PROT_READ  0x1
#define PROT_WRITE 0x2
#define PROT_EXEC  0x4

#if defined(__clang__) && !defined(_WIN32)
extern int isinff(float);
extern int isnanf(float);
#elif defined(_WIN32)
#define isnanf isnan
#define isinff isinf
#endif

void PrintfFtrace(int prefix, const char* fmt, ...);

void* GetEnv(const char* name);

#define IS_EXECUTABLE (1 << 0)
#define IS_FILE       (1 << 1)

// 0 : doesn't exist, 1: does exist.
int FileExist(const char* filename, int flags);
int MakeDir(const char* folder);    // return 1 for success, 0 else

#ifdef _WIN32
#define BOXFILE_BUFSIZE 4096
typedef struct {
    HANDLE hFile;
    char buffer[BOXFILE_BUFSIZE];
    size_t buf_pos;
    size_t buf_size;
    int eof;
} BOXFILE;

BOXFILE* box_fopen(const char* filename, const char* mode);
char* box_fgets(char* str, int num, BOXFILE* stream);
int box_fclose(BOXFILE* stream);
#else
#define BOXFILE    FILE
#define box_fopen  fopen
#define box_fgets  fgets
#define box_fclose fclose
#endif

#endif //__OS_H_
