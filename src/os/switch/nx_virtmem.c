// box64-nx — real virtual memory backend for the Horizon port (M1.3).
//
// Page-granular anonymous memory at box64's chosen guest addresses, via a RUNTIME-SELECTED backend
// (tried in order at init, one-page map+readback each):
//   * UNSAFE — svcMapPhysicalMemoryUnsafe over a virtmemFindCodeMemory (ASLR/code) reservation. The
//     only backend that yields REAL memory to a normally-launched application on real hardware: it
//     needs NO system_resource_size, but the process must be in a non-Application memory pool
//     (box64.json declares MemoryRegion=Applet -> pool_partition 1) and grant svc 0x48/0x49/0x4a, and
//     the target VA must be in the AliasCode region (hence virtmemFindCodeMemory, not the Alias region).
//   * PHYS — svcMapPhysicalMemory over the process Alias region. Needs system_resource_size>0, which a
//     normal app CANNOT declare on real hardware (rejected at process creation) — but WORKS in Ryujinx
//     (which never enforces that, implements 0x2c/0x2d, and does NOT implement the unsafe 0x48 trio).
//     Kept for emulator arena testing and any ns-provisioned title.
//   * HEAP — memalign-backed fallback (plain hbloader NRO, or when neither real backend is available).
//
// box64 reserves a whole-image span with a non-FIXED map, then MAP_FIXED-places PT_LOAD segments inside
// it. Address-space accounting is a coalescing free list (static node pool, so nothing here re-enters
// box64's allocator). Single-threaded for the M1 scope.

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

// --- newlib heap ---------------------------------------------------------------------------------
// On an NRO, hbloader hands us a pre-mapped heap via the homebrew ABI — we MUST reuse it (calling
// svcSetHeapSize instead yields a heap libnx's argvSetup then Data-Aborts on). As a title there is no
// override, so we carve our own heap with svcSetHeapSize — but the amount available depends on the
// process memory pool (an Applet-pool title has a smaller budget than the old Application-pool
// assumption), so we retry DOWN from a generous size and NEVER leave the heap NULL (a null heap makes
// the first malloc — inside consoleInit — Data-Abort, which is exactly the crash we saw as a title).
// The guest arena no longer comes from this heap (it's the UNSAFE/PHYS pool), so it needn't be bounded
// to "leave RAM for the arena".
void __libnx_initheap(void) {
    extern char* fake_heap_start;
    extern char* fake_heap_end;

    if (envHasHeapOverride()) {
        fake_heap_start = (char*)envGetHeapOverrideAddr();
        fake_heap_end   = (char*)envGetHeapOverrideAddr() + envGetHeapOverrideSize();
        return;
    }
    // Descending: a consistent Application-pool NSP (pool_partition 0 + application_type Application)
    // can carve a large heap from the ~3.2 GiB Application pool, so start at 1 GiB of REAL memory and
    // fall back if the pool is tighter. (An Applet-pool/album host has far less; the retry covers it.)
    static const u64 sizes[] = {
        0x40000000ULL, 0x20000000ULL, 0x10000000ULL, 0x08000000ULL, 0x04000000ULL, 0x02000000ULL, 0x01000000ULL, 0x00200000ULL
    };
    for (unsigned i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
        void* base = NULL;
        if (R_SUCCEEDED(svcSetHeapSize(&base, sizes[i])) && base) {
            fake_heap_start = (char*)base;
            fake_heap_end   = (char*)base + sizes[i];
            return;
        }
    }
    // Last resort: a static .bss heap so newlib ALWAYS has a valid arena. If svcSetHeapSize grants
    // nothing in this memory pool (an Applet-pool application appears to get no svcSetHeapSize budget
    // on real HW), a null fake_heap_start makes the FIRST malloc — inside libnx's pre-main __appInit,
    // before fsdev even mounts — Data-Abort with no possible diagnostics. A .bss buffer is mapped at
    // load, so this can't fail; small, but enough to reach main, mount the SD, and run a tiny guest.
    static __attribute__((aligned(0x1000))) char s_static_heap[16 * 1024 * 1024];
    fake_heap_start = s_static_heap;
    fake_heap_end   = s_static_heap + sizeof(s_static_heap);
}

// --- backend selection ---------------------------------------------------------------------------
enum { VM_UNINIT = -1, VM_HEAP = 0, VM_PHYS = 1, VM_UNSAFE = 2 };
static int vm_backend = VM_UNINIT;

#define VM_UNSAFE_LIMIT  0x10000000ULL    // 256 MiB system-wide unsafe cap (svcSetUnsafeLimit). Modest
                                          // on purpose: the unsafe pool IS the Application pool, so an
                                          // over-large cap destabilises the system (audio/omm) when an
                                          // app is suspended there. Tunable up once launched app-pool-free.
#define VM_RESERVE_SIZE  0x40000000ULL    // 1 GiB VA reservation for the guest arena; physical use is
                                          // bounded by VM_UNSAFE_LIMIT / the pool, not this. Tunable.

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

// Map/unmap one arena range with the active backend's SVC.
static Result vm_map(void* addr, size_t size) {
    return (vm_backend == VM_UNSAFE) ? svcMapPhysicalMemoryUnsafe(addr, size)
                                     : svcMapPhysicalMemory(addr, size);
}
static Result vm_unmap(void* addr, size_t size) {
    return (vm_backend == VM_UNSAFE) ? svcUnmapPhysicalMemoryUnsafe(addr, size)
                                     : svcUnmapPhysicalMemory(addr, size);
}

// Reset the node pool + free list over [base, base+size), tag the backend, and TRIAL-map one page:
// map + write + readback (confirms real memory even if an emulator no-ops the SVC) + unmap. Returns 1
// if the backend is usable (committed state left in vm_base/vm_end/vm_free/vm_backend), else 0.
static int vm_try(uintptr_t base, size_t size, int backend) {
    for (int i = 0; i < VM_NODES - 1; i++) vm_pool[i].next = &vm_pool[i + 1];
    vm_pool[VM_NODES - 1].next = NULL;
    vm_nodefree = &vm_pool[0];

    vm_base = base; vm_end = base + size;
    vm_free = node_get(base, size);
    if (!vm_free) return 0;
    vm_backend = backend;

    uintptr_t t = vm_reserve(VM_PAGE);
    if (!t || R_FAILED(vm_map((void*)t, VM_PAGE))) {
        if (t) vm_release(t, VM_PAGE);
        return 0;
    }
    volatile u32* p = (volatile u32*)t; *p = 0xC0DE1234u;
    int ok = (*p == 0xC0DE1234u);
    vm_unmap((void*)t, VM_PAGE);
    vm_release(t, VM_PAGE);
    return ok;
}

static void vm_reset_state(void) {
    if (vm_resv) { virtmemLock(); virtmemRemoveReservation(vm_resv); virtmemUnlock(); vm_resv = NULL; }
    vm_free = NULL; vm_base = vm_end = 0; vm_backend = VM_UNINIT;
}

static void vm_init(void) {
    // --- 1) UNSAFE (real-HW application path) ---------------------------------------------------
    // Gate on detectMesosphere(): only real hardware (Atmosphère) implements the unsafe SVCs — Ryujinx
    // THROWS NotImplementedException on svcSetUnsafeLimit/svcMapPhysicalMemoryUnsafe (a crash, not an
    // error), so we must never call them there. Then require the SVC be granted (an ungranted SVC also
    // FAULTS): a title (no hbloader heap override) has it from box64.json; an NRO must be syscall-hinted.
    if (detectMesosphere() && (!envHasHeapOverride() || envIsSyscallHinted(0x48))) {
        svcSetUnsafeLimit(VM_UNSAFE_LIMIT);   // system-wide cap; harmless/no-op where unimplemented
        void* rbase = NULL;
        virtmemLock();
        rbase = virtmemFindCodeMemory(VM_RESERVE_SIZE, 0);
        if (rbase) vm_resv = virtmemAddReservation(rbase, VM_RESERVE_SIZE);
        virtmemUnlock();
        if (rbase && vm_resv) {
            if (vm_try((uintptr_t)rbase, VM_RESERVE_SIZE, VM_UNSAFE)) {
                char b[112]; int n = snprintf(b, sizeof b,
                    "nx_vm: UNSAFE ready base=0x%llx size=0x%llx\n",
                    (unsigned long long)vm_base, (unsigned long long)VM_RESERVE_SIZE);
                svcOutputDebugString(b, n);
                return;
            }
        }
        vm_reset_state();
    }

    // --- 2) PHYS (Ryujinx / ns-provisioned title with system_resource_size>0) -------------------
    u64 abase = 0, asize = 0;
    if (R_SUCCEEDED(svcGetInfo(&abase, InfoType_AliasRegionAddress, CUR_PROCESS_HANDLE, 0)) &&
        R_SUCCEEDED(svcGetInfo(&asize, InfoType_AliasRegionSize,    CUR_PROCESS_HANDLE, 0)) &&
        abase && asize >= 0x200000) {
        virtmemLock();
        vm_resv = virtmemAddReservation((void*)(uintptr_t)abase, (size_t)asize);
        virtmemUnlock();
        if (vm_resv && vm_try((uintptr_t)abase, (size_t)asize, VM_PHYS)) {
            char b[112]; int n = snprintf(b, sizeof b,
                "nx_vm: PHYS ready base=0x%llx size=0x%llx\n",
                (unsigned long long)vm_base, (unsigned long long)asize);
            svcOutputDebugString(b, n);
            return;
        }
        vm_reset_state();
    }

    // --- 3) HEAP fallback -----------------------------------------------------------------------
    vm_backend = VM_HEAP;
    svcOutputDebugString("nx_vm: heap-fallback\n", 20);
}

static inline void vm_ensure_init(void) { if (vm_backend == VM_UNINIT) vm_init(); }

// Report the active memory backend for a startup diagnostic (nx_main.c prints it to the console and,
// on the NRO, streams it over nxlink). Forces backend selection if it hasn't run yet. Returns the
// backend (VM_HEAP=0, VM_PHYS=1, VM_UNSAFE=2); fills the arena span (0 on heap) and the process
// SystemResourceSize (0 on a normal app / NRO; non-zero only on a PHYS/provisioned title).
int nx_vm_status(uintptr_t* base, size_t* size, unsigned long long* sysres) {
    vm_ensure_init();
    if (base) *base = vm_base;
    if (size) *size = (size_t)(vm_end - vm_base);
    if (sysres) {
        u64 v = 0;
        svcGetInfo(&v, InfoType_SystemResourceSizeTotal, CUR_PROCESS_HANDLE, 0);
        *sysres = (unsigned long long)v;
    }
    return vm_backend;
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
    if (vm_backend == VM_HEAP)
        return nx_mmap_heap(addr, rounded, flags);

    // PHYS or UNSAFE arena
    if (flags & MAP_FIXED) {
        if (!(flags & MAP_ANONYMOUS) || !addr) { errno = ENODEV; return MAP_FAILED; }
        uintptr_t a = (uintptr_t)addr;
        if (vm_in_arena(a, rounded)) { memset(addr, 0, rounded); return addr; }   // pages already backed
        if (R_FAILED(vm_map(addr, rounded))) { errno = ENOMEM; return MAP_FAILED; }
        memset(addr, 0, rounded);
        return addr;
    }

    uintptr_t a = vm_reserve(rounded);
    if (!a) { errno = ENOMEM; return MAP_FAILED; }
    if (R_FAILED(vm_map((void*)a, rounded))) {
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

    if (vm_backend != VM_HEAP && vm_in_arena(a, rounded)) {
        vm_unmap(addr, rounded);   // real reclaim of the physical pages...
        vm_release(a, rounded);    // ...and the address range
        return 0;
    }
    if (hb_untrack(a)) free(addr); // heap-fallback whole-block reclaim
    return 0;
}

// Page permissions. Real svcSetMemoryPermission works on arena pages (None/R/RW), but enforcing RO
// before the SMC fault handler exists would crash box64's protectDB path — so this stays a no-op until
// that lands. Surface any executable request once (box64 never executes guest pages; exec is the jit
// code-memory path, not this).
int nx_vm_protect(void* addr, size_t len, int prot) {
    (void)addr; (void)len;
    if (prot & PROT_EXEC) {
        static int warned = 0;
        if (!warned) { warned = 1; svcOutputDebugString("nx_vm: mprotect(PROT_EXEC) no-op\n", 32); }
    }
    return 0;
}

#endif // __SWITCH__
