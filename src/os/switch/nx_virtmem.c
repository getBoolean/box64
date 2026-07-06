// box64-nx — real virtual memory backend for the Horizon port (phase 1b / M1.3).
//
// Page-granular anonymous memory via Horizon's svcMapPhysicalMemory, over a reserved slice of the
// process **Alias region**. This works only when the process declares system_resource_size > 0 in
// its NPDM — i.e. box64 packaged as an NSP/title (see src/os/switch/box64.json). A plain hbloader
// NRO has no such resource, so svcMapPhysicalMemory fails with KernelError_InvalidState. We detect
// that at init with a one-page TRIAL MAP and, if it fails, fall back to the M1.1 heap allocator so
// box64.nro keeps working (heap-backed, no real page permissions).
//
// On the arena path we get: real fixed-address placement, real reclaim (svcUnmapPhysicalMemory),
// and — because these pages are svcSetMemoryPermission-capable — a foundation for real mprotect and
// SMC detection (wired in phase 3, once the fault handler exists; mprotect stays a no-op until then).
//
// box64 reserves a whole-image span with a non-FIXED map, then MAP_FIXED-places PT_LOAD segments
// inside it: a non-FIXED map allocates+backs an arena range; a MAP_FIXED anonymous map lands inside
// an already-backed range and just zeroes it; a file-backed / NULL MAP_FIXED is refused so box64
// uses its own anon-map + fread fallback. Address-space accounting is a coalescing free list (static
// node pool, so nothing here re-enters box64's allocator). Single-threaded for the M1 scope.

#ifdef __SWITCH__

#include "nx_posix.h"

#include <switch.h>
#include <stdlib.h>
#include <stdio.h>      // snprintf (bring-up marker)
#include <malloc.h>     // memalign (fallback path)
#include <string.h>
#include <errno.h>
#include <sys/mman.h>   // PROT_*/MAP_* (box64-nx shim)

#define VM_PAGE     0x1000UL
#define VM_PAGEMASK (VM_PAGE - 1)
#define VM_ROUND(x) (((x) + VM_PAGEMASK) & ~VM_PAGEMASK)

// libnx's default __libnx_initheap sizes the newlib heap to (almost) all available physical memory,
// leaving nothing for svcMapPhysicalMemory to map — so the guest arena would OutOfResource on its
// first real allocation. Bound the newlib heap (used by box64's own malloc + the NRO heap-fallback
// path) so the rest of physical RAM stays free for the arena (guest mmap). 2 MiB-aligned.
#define NX_NEWLIB_HEAP 0x20000000ULL   // 512 MiB
void __libnx_initheap(void) {
    extern char* fake_heap_start;
    extern char* fake_heap_end;

    // When launched as an NRO, hbloader hands us a heap region via the homebrew ABI and has already
    // mapped it. We MUST use that region (like libnx's default initheap does): calling svcSetHeapSize
    // ourselves instead yields a heap that libnx's own argvSetup then memsets and faults on real
    // hardware (Data Abort — the emulator tolerated it). Only when there is no loader override
    // (i.e. box64 packaged as an NSP/title) do we carve our own bounded heap so the rest of physical
    // RAM stays free for the svcMapPhysicalMemory arena.
    if (envHasHeapOverride()) {
        fake_heap_start = (char*)envGetHeapOverrideAddr();
        fake_heap_end   = (char*)envGetHeapOverrideAddr() + envGetHeapOverrideSize();
        return;
    }
    void* base = NULL;
    if (R_SUCCEEDED(svcSetHeapSize(&base, NX_NEWLIB_HEAP)) && base) {
        fake_heap_start = (char*)base;
        fake_heap_end   = (char*)base + NX_NEWLIB_HEAP;
    }
}

static int vm_ready = 0;   // 0 = uninit, 1 = arena (svcMapPhysicalMemory), -1 = heap fallback

// ---------------------------------------------------------------------------------------------
// Arena allocator over [vm_base, vm_end): a coalescing free list of address-space intervals.
// Nodes come from a static pool (never malloc), so this can be called from inside box64's own
// allocator without re-entrancy.
// ---------------------------------------------------------------------------------------------
typedef struct vm_span_s { uintptr_t start; size_t len; struct vm_span_s* next; } vm_span_t;

#define VM_NODES 2048
static vm_span_t  vm_pool[VM_NODES];
static vm_span_t* vm_nodefree = NULL;
static vm_span_t* vm_free     = NULL;   // free intervals, sorted by start, coalesced
static uintptr_t  vm_base = 0, vm_end = 0;
static VirtmemReservation* vm_resv = NULL;

static vm_span_t* node_get(uintptr_t start, size_t len) {
    if (!vm_nodefree) return NULL;
    vm_span_t* n = vm_nodefree; vm_nodefree = n->next;
    n->start = start; n->len = len; n->next = NULL;
    return n;
}
static void node_put(vm_span_t* n) { n->next = vm_nodefree; vm_nodefree = n; }

// First-fit; carve from the front. Returns 0 on exhaustion. Address space only — does not map pages.
static uintptr_t vm_reserve(size_t len) {
    for (vm_span_t** pp = &vm_free; *pp; pp = &(*pp)->next) {
        vm_span_t* s = *pp;
        if (s->len >= len) {
            uintptr_t a = s->start;
            s->start += len; s->len -= len;
            if (s->len == 0) { *pp = s->next; node_put(s); }
            return a;
        }
    }
    return 0;
}

// Return [start,start+len) to the free list, coalescing with neighbours.
static void vm_release(uintptr_t start, size_t len) {
    vm_span_t** pp = &vm_free;
    while (*pp && (*pp)->start < start) pp = &(*pp)->next;
    vm_span_t* next = *pp;
    vm_span_t* prev = NULL;
    for (vm_span_t* s = vm_free; s != *pp; s = s->next) prev = s;

    if (prev && prev->start + prev->len == start) {           // merge into prev
        prev->len += len;
        if (next && prev->start + prev->len == next->start) { // and into next
            prev->len += next->len; prev->next = next->next; node_put(next);
        }
        return;
    }
    if (next && start + len == next->start) {                 // merge into next
        next->start = start; next->len += len;
        return;
    }
    vm_span_t* n = node_get(start, len);                      // standalone
    if (!n) return;   // pool exhausted: drop the range (leaks address space; pages already freed)
    n->next = *pp; *pp = n;
}

static int vm_in_arena(uintptr_t a, size_t len) {
    return vm_base && a >= vm_base && a + len <= vm_end && a + len >= a;
}

static void vm_init(void) {
    for (int i = 0; i < VM_NODES - 1; i++) vm_pool[i].next = &vm_pool[i + 1];
    vm_pool[VM_NODES - 1].next = NULL;
    vm_nodefree = &vm_pool[0];

    u64 abase = 0, asize = 0;
    if (R_FAILED(svcGetInfo(&abase, InfoType_AliasRegionAddress, CUR_PROCESS_HANDLE, 0)) ||
        R_FAILED(svcGetInfo(&asize, InfoType_AliasRegionSize,    CUR_PROCESS_HANDLE, 0)) ||
        !abase || asize < 0x200000) {
        vm_ready = -1; return;
    }
    virtmemLock();
    vm_resv = virtmemAddReservation((void*)(uintptr_t)abase, (size_t)asize);
    virtmemUnlock();
    if (!vm_resv) { vm_ready = -1; return; }

    vm_base = (uintptr_t)abase; vm_end = (uintptr_t)(abase + asize);
    vm_free = node_get(vm_base, (size_t)asize);
    if (!vm_free) { vm_ready = -1; return; }

    // Trial map one page: on an NRO (no system_resource_size) this fails -> heap fallback; on the
    // NSP it succeeds -> real arena.
    uintptr_t t = vm_reserve(VM_PAGE);
    if (!t || R_FAILED(svcMapPhysicalMemory((void*)t, VM_PAGE))) {
        if (t) vm_release(t, VM_PAGE);
        virtmemLock(); virtmemRemoveReservation(vm_resv); virtmemUnlock();
        vm_resv = NULL; vm_free = NULL; vm_base = vm_end = 0;
        vm_ready = -1; return;
    }
    svcUnmapPhysicalMemory((void*)t, VM_PAGE);
    vm_release(t, VM_PAGE);
    vm_ready = 1;
    { char b[96]; int n = snprintf(b, sizeof b, "nx_vm: ARENA ready base=0x%llx size=0x%llx\n", (unsigned long long)vm_base, (unsigned long long)asize); svcOutputDebugString(b, n); }
}

static inline void vm_ensure_init(void) { if (!vm_ready) vm_init(); }

// Report the active memory backend for a startup diagnostic (nx_main.c prints it to the console and,
// on the NRO, streams it over nxlink). Forces arena init if it hasn't run yet (idempotent — vm_init
// only reserves address space + trial-maps one page). Returns vm_ready (1 = real svcMapPhysicalMemory
// arena, -1 = heap fallback); fills the arena span (0 on the fallback path) and the process
// SystemResourceSize (the NPDM pool the arena needs; 0 on a plain NRO).
int nx_vm_status(uintptr_t* base, size_t* size, unsigned long long* sysres) {
    vm_ensure_init();
    if (base) *base = vm_base;
    if (size) *size = (size_t)(vm_end - vm_base);
    if (sysres) {
        u64 v = 0;
        svcGetInfo(&v, InfoType_SystemResourceSizeTotal, CUR_PROCESS_HANDLE, 0);
        *sysres = (unsigned long long)v;
    }
    return vm_ready;
}

// ---------------------------------------------------------------------------------------------
// Heap fallback (box64.nro path): memalign-backed, with real free()-on-munmap for whole mappings.
// ---------------------------------------------------------------------------------------------
#define HB_MAX 512
typedef struct { uintptr_t base; size_t len; } hb_block_t;
static hb_block_t hb_blocks[HB_MAX];
static int        hb_n = 0;

static void  hb_track(uintptr_t b, size_t l) { if (hb_n < HB_MAX) { hb_blocks[hb_n].base = b; hb_blocks[hb_n].len = l; hb_n++; } }
static int   hb_untrack(uintptr_t b) { for (int i = 0; i < hb_n; i++) if (hb_blocks[i].base == b) { hb_blocks[i] = hb_blocks[--hb_n]; return 1; } return 0; }

static void* nx_mmap_heap(void* addr, size_t rounded, int flags) {
    if (flags & MAP_FIXED) {
        if (!(flags & MAP_ANONYMOUS) || !addr) { errno = ENODEV; return MAP_FAILED; }
        memset(addr, 0, rounded);
        return addr;
    }
    void* p = memalign(VM_PAGE, rounded);
    if (!p) { errno = ENOMEM; return MAP_FAILED; }
    if (flags & MAP_ANONYMOUS) memset(p, 0, rounded);
    hb_track((uintptr_t)p, rounded);
    return p;
}

// ---------------------------------------------------------------------------------------------
// Public mmap / munmap / mprotect
// ---------------------------------------------------------------------------------------------
void* nx_mmap(void* addr, unsigned long length, int prot, int flags, int fd, ssize_t offset) {
    (void)prot; (void)fd; (void)offset;
    if (!length) return MAP_FAILED;
    size_t rounded = VM_ROUND(length);

    vm_ensure_init();
    if (vm_ready != 1)
        return nx_mmap_heap(addr, rounded, flags);

    if (flags & MAP_FIXED) {
        if (!(flags & MAP_ANONYMOUS) || !addr) { errno = ENODEV; return MAP_FAILED; }
        uintptr_t a = (uintptr_t)addr;
        if (vm_in_arena(a, rounded)) { memset(addr, 0, rounded); return addr; }   // pages already backed
        if (R_FAILED(svcMapPhysicalMemory(addr, rounded))) { errno = ENOMEM; return MAP_FAILED; }
        memset(addr, 0, rounded);
        return addr;
    }

    uintptr_t a = vm_reserve(rounded);
    if (!a) { errno = ENOMEM; return MAP_FAILED; }
    if (R_FAILED(svcMapPhysicalMemory((void*)a, rounded))) {
        vm_release(a, rounded);
        errno = ENOMEM;
        return MAP_FAILED;
    }
    if (flags & MAP_ANONYMOUS) memset((void*)a, 0, rounded);
    return (void*)a;
}

int nx_munmap(void* addr, unsigned long length) {
    if (!addr || !length) return 0;
    size_t rounded = VM_ROUND(length);
    uintptr_t a = (uintptr_t)addr;

    if (vm_ready == 1 && vm_in_arena(a, rounded)) {
        svcUnmapPhysicalMemory(addr, rounded);   // real reclaim of the physical pages...
        vm_release(a, rounded);                  // ...and the address range
        return 0;
    }
    if (hb_untrack(a)) free(addr);               // heap-fallback whole-block reclaim
    return 0;
}

// Page permissions. Real svcSetMemoryPermission works on arena pages (NSP), but enforcing RO before
// the phase-2 fault handler exists would crash box64's protectDB path — so this stays a no-op until
// phase 3 wires it up together with SMC detection. Surface any executable request once.
int nx_vm_protect(void* addr, size_t len, int prot) {
    (void)addr; (void)len;
    if (prot & PROT_EXEC) {
        static int warned = 0;
        if (!warned) { warned = 1; svcOutputDebugString("nx_vm: mprotect(PROT_EXEC) no-op (real perms land in phase 3)\n", 61); }
    }
    return 0;
}

#endif // __SWITCH__
