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
// box64's allocator). The free-list/heap-table mutations are serialized by vm_lock (M2.2 guest threads).

#ifdef __SWITCH__

#include "nx_posix.h"

#include <switch.h>
#include <stdlib.h>
#include <stdio.h>      // snprintf (bring-up marker)
#include <malloc.h>     // memalign (fallback path)
#include <string.h>
#include <errno.h>
#include <sys/mman.h>   // PROT_*/MAP_* (box64-nx shim)
#include <unistd.h>     // read/lseek (M2.1 file-backed mmap)

extern void nx_result_log(const char*);   // nx_main.c: heap-free SD result line (HW crash-diag channel)

#define VM_PAGE     0x1000UL
#define VM_PAGEMASK (VM_PAGE - 1)
#define VM_ROUND(x) (((x) + VM_PAGEMASK) & ~VM_PAGEMASK)

// --- newlib heap ---------------------------------------------------------------------------------
// On an NRO, hbloader hands us a pre-mapped heap via the homebrew ABI — we MUST reuse it (calling
// svcSetHeapSize instead yields a heap libnx's argvSetup then Data-Aborts on). As a title there is no
// override, so we carve our own heap with svcSetHeapSize, sized to the process's actual memory budget.
// The guest arena no longer comes from this heap (it's the UNSAFE/PHYS pool), so it needn't be bounded
// to "leave RAM for the arena" — but this heap IS the guest's whole working set on the heap-fallback
// path (malloc, the jit code cache, AND guest mmap all draw from it), so we want as much as the pool
// allows. newlib can't grow the heap after init, hence up front.

// Startup diagnostics for the memory budget (nx_main.c prints them). Filled in __libnx_initheap.
u64 nx_mem_total_size   = 0;   // svcGetInfo TotalMemorySize — the process's whole pool budget
u64 nx_mem_used_at_init = 0;   // svcGetInfo UsedMemorySize BEFORE we set the heap (code+stacks)

void __libnx_initheap(void) {
    extern char* fake_heap_start;
    extern char* fake_heap_end;

    if (envHasHeapOverride()) {
        fake_heap_start = (char*)envGetHeapOverrideAddr();
        fake_heap_end   = (char*)envGetHeapOverrideAddr() + envGetHeapOverrideSize();
        return;
    }

    // Preferred path: ask the kernel exactly how much this process may use, and take (almost) all of it
    // in ONE svcSetHeapSize — no probing. TotalMemorySize is the process memory resource limit (the
    // Application pool for a HOME-launched app); UsedMemorySize is what's already mapped (code, .data,
    // .bss, initial stacks). The grantable heap ceiling is (total - used). We keep a MARGIN below it for
    // box64's post-init out-of-heap allocations (extra thread stacks/guard pages, libnx service buffers,
    // any nvmap the console needs that isn't heap-backed) — without it, grabbing the last byte risks a
    // later OOM in consoleInit/fsdev. Both InfoTypes are documented (switchbrew SVC / libnx svc.h).
    {
        u64 total = 0, used = 0;
        if (R_SUCCEEDED(svcGetInfo(&total, InfoType_TotalMemorySize, CUR_PROCESS_HANDLE, 0)) &&
            R_SUCCEEDED(svcGetInfo(&used,  InfoType_UsedMemorySize,  CUR_PROCESS_HANDLE, 0)) &&
            total > used) {
            nx_mem_total_size = total; nx_mem_used_at_init = used;
            const u64 MARGIN = 0x01000000ULL;               // 16 MiB safety reserve for out-of-heap allocs
            u64 want = total - used;
            want = (want > MARGIN) ? (want - MARGIN) : want;
            want &= ~(u64)VM_PAGEMASK; want &= ~0x1FFFFFULL;  // round down to 2 MiB (svcSetHeapSize rule)
            void* base = NULL;
            if (want >= 0x00200000ULL && R_SUCCEEDED(svcSetHeapSize(&base, want)) && base) {
                fake_heap_start = (char*)base;
                fake_heap_end   = (char*)base + want;
                return;
            }
        }
    }

    // Fallback (svcGetInfo failed or the computed request didn't take): walk DOWN a coarse ladder and
    // take the first svcSetHeapSize that succeeds. Every entry is 2 MiB-aligned. Covers an Applet-pool/
    // album host too (far smaller budget). (On the NRO we never reach here — hbloader's heap override.)
    static const u64 sizes[] = {
        0xD8000000ULL, 0xD0000000ULL, 0xC8000000ULL, 0xC0000000ULL,
        0xA0000000ULL, 0x80000000ULL, 0x60000000ULL,
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

// M2.2: guest threads call mmap/munmap concurrently (glibc arenas, per-thread stacks), so the free
// list + node pool + heap-block table must be serialized. vm_init/vm_try run once at startup (before
// any guest thread), so they stay unlocked; only the runtime mmap/munmap mutation sites take this.
static Mutex vm_lock;   // libnx Mutex; zero-initialized == unlocked

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
    // KX_FORCE_HEAP: stay on the HEAP backend even when a PHYS/UNSAFE arena is available. Wine's Win32
    // low-VA FIXED maps (0x10000.., KUSER @0x7ffe0000, PE reserves) need box64's nx_map_lowva_fixed
    // (svcControlCodeMemory) path, which ONLY runs on VM_HEAP; the arena backends (svcMapPhysicalMemory)
    // map the guest's HIGH VAs but can't place those low fixed maps (-> wild-pointer crash). We still want
    // system_resource_size>0 for the bigger memory-block budget those CodeMemory maps consume — that's an
    // NPDM property, independent of which mmap backend box64 picks — so force HEAP but keep sysres>0.
    if (getenv("KX_FORCE_HEAP")) { vm_backend = VM_HEAP; svcOutputDebugString("nx_vm: heap-forced (KX_FORCE_HEAP)\n", 34); return; }

    // --- 1) UNSAFE (real-HW non-Application-pool path) ------------------------------------------
    // Gate on detectMesosphere(): only real hardware (Atmosphère) implements the unsafe SVCs — Ryujinx
    // THROWS NotImplementedException on svcSetUnsafeLimit/svcMapPhysicalMemoryUnsafe (a crash, not an
    // error), so we must never call them there. Then require a POSITIVE signal that the host is a
    // non-Application-pool UNSAFE vehicle: the homebrew syscall hint envIsSyscallHinted(0x48), which a
    // custom/album-mode hbloader sets when it grants 0x48. A HOME-launched Application NSP is the WRONG
    // vehicle for UNSAFE — Pool_Unsafe==Pool_Application, so svcMapPhysicalMemoryUnsafe fails there and
    // svcSetUnsafeLimit would needlessly cap the shared Application pool (destabilising audio/omm) — and
    // it carries no such hint, so it skips this entirely and uses the Application-pool heap instead.
    // (Open design point: an UNSAFE host that is a custom-NPDM *title* wouldn't surface the hint and
    // would need a pool probe instead — M2, see the plan.)
    if (detectMesosphere() && envIsSyscallHinted(0x48)) {
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

extern char* fake_heap_start;
extern char* fake_heap_end;

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

// M2.7 (Wine): track the low-VA regions we svcMapMemory'd so Wine's reserve-then-commit pattern (map
// PROT_NONE over a range, then MAP_FIXED_NOREPLACE a sub-range) doesn't re-map (svcMapMemory of an
// already-mapped VA fails). A hit means the VA is already backed — just return it.
#define NX_LOWVA_MAX 2048
static struct { uintptr_t base, end; } g_lowva[NX_LOWVA_MAX];
static int g_lowva_n = 0;
static int nx_lowva_covered(uintptr_t a, size_t len) {
    for (int i = 0; i < g_lowva_n; i++)
        if (a >= g_lowva[i].base && a + len <= g_lowva[i].end) return 1;
    return 0;
}

// PROT_NONE reservations: Wine reserves the WHOLE low Win32 window up-front (the preload areas box64 hands
// it, plus its own low reserves). We must NOT back these with CodeMemory — one svcCreateCodeMemory per
// chunk over ~1.5 GiB of reservation exhausts Horizon's memory-block resource (svcCreateCodeMemory ->
// 0xce01 OutOfResource), which then fails the CRITICAL *committed* maps (KUSER @0x7ffe0000 -> fatal).
// Track reservations instead and back only the sub-ranges Wine actually COMMITS (mmap PROT_RW reaches
// nx_map_lowva_fixed; mprotect PROT_RW reaches nx_vm_protect).
#define NX_LOWVA_RESV_MAX 256
static struct { uintptr_t base, end; } g_lowva_resv[NX_LOWVA_RESV_MAX];
static int g_lowva_resv_n = 0;
static void nx_lowva_resv_track(uintptr_t a, size_t len) {
    if (g_lowva_resv_n < NX_LOWVA_RESV_MAX) { g_lowva_resv[g_lowva_resv_n].base = a; g_lowva_resv[g_lowva_resv_n].end = a + len; g_lowva_resv_n++; }
}
static int nx_lowva_reserved(uintptr_t a, size_t len) {   // does [a,a+len) overlap a deferred reservation?
    for (int i = 0; i < g_lowva_resv_n; i++)
        if (a < g_lowva_resv[i].end && a + len > g_lowva_resv[i].base) return 1;
    return 0;
}

// Back a low VA (outside the heap: Win32 KSHARED_USER_DATA @0x7ffe0000, PE image bases, Wine's low
// reservations) with svcMapMemory (mirror fresh heap pages to the exact VA). Returns addr or MAP_FAILED
// (Horizon rejects a non-mappable region). Guest pages are never executed natively, so RW backing +
// box64's no-op mprotect is enough; a later commit at the same VA is already covered.
static void nx_lowva_track(uintptr_t a, size_t len) {
    if (g_lowva_n < NX_LOWVA_MAX) { g_lowva[g_lowva_n].base = a; g_lowva[g_lowva_n].end = a + len; g_lowva_n++; }
}

// KUSER_SHARED_DATA lives at the immutable Win32 VA 0x7ffe0000. Its `SystemCall` field (+0x308) is a
// wineserver-set constant: 1 = "route NT syscalls through the dispatcher pointer at 0x7ffe1000"
// (`call *0x7ffe1000` in every PE ntdll thunk), 0 = "raw x86-64 `syscall` and rely on seccomp/SIGSYS".
// On KurokoNX raw NT syscalls are meaningless (box64 would read the Windows NT number as a Linux one),
// and the wineserver's write never reaches the client (file-backed mmap copies per instance; the
// client's KUSER page is a fresh CodeMemory page). So force SystemCall=1 the moment box64-nx backs the
// KUSER page for the client — semantically exactly what the wineserver intends, and the ONLY viable
// dispatch mode here. (The dispatcher-pointer page 0x7ffe1000 is wine's own anon_mmap_fixed.)
#define NX_KUSER_VA        0x7ffe0000UL
#define NX_KUSER_SYSCALL   0x308
static void nx_kuser_fixup(void* addr, size_t rounded) {
    uintptr_t a = (uintptr_t)addr;
    if (a <= NX_KUSER_VA && a + rounded > NX_KUSER_VA + NX_KUSER_SYSCALL + 4) {
        *(volatile uint32_t*)(NX_KUSER_VA + NX_KUSER_SYSCALL) = 1;   // SystemCall = 1 (use dispatcher)
        char b[80]; int n = snprintf(b, sizeof b, "nx_vm: KUSER SystemCall=1 @0x7ffe0308\n");
        if (n > 0) svcOutputDebugString(b, n);
    }
}
// Back ONE chunk [addr, addr+len) with a CodeMemory MapOwner mapping (Perm_Rw). len must be page-
// rounded. Returns 0 on success (keeps cm+src alive for the run), -1 on failure.
static int g_lowva_cm_live = 0;   // # of live low-VA CodeMemory maps (diagnostic: leak vs hard slab limit)
static int g_lowva_slab_full = 0; // set once svcCreateCodeMemory hits 0xce01 OutOfResource (system KCodeMemory
                                  // slab exhausted) — stop pointless shrink-retries (shrinking can't help a
                                  // resource shortage) that otherwise flood the result file / livelock.

// Registry of live low-VA backings so nx_munmap can RECLAIM the (system-wide, ~a dozen) KCodeMemory objects
// on VirtualFree(MEM_RELEASE). Without this every Wine free LEAKS its object and the slab exhausts as the
// process runs. code=1 => svcControlCodeMemory owner map (free via UnmapOwner + close(cm)); code=0 =>
// svcMapMemory mirror (free via svcUnmapMemory). Also drops the matching g_lowva coverage entry.
#define NX_LOWVA_CM_REG_MAX 512
static struct { uintptr_t addr; size_t len; Handle cm; void* src; int code; } g_lowva_cm_reg[NX_LOWVA_CM_REG_MAX];
static int g_lowva_cm_reg_n = 0;
static void nx_lowva_cm_reg_add(uintptr_t a, size_t l, Handle cm, void* src, int code) {
    if (g_lowva_cm_reg_n < NX_LOWVA_CM_REG_MAX) {
        g_lowva_cm_reg[g_lowva_cm_reg_n].addr=a; g_lowva_cm_reg[g_lowva_cm_reg_n].len=l;
        g_lowva_cm_reg[g_lowva_cm_reg_n].cm=cm; g_lowva_cm_reg[g_lowva_cm_reg_n].src=src;
        g_lowva_cm_reg[g_lowva_cm_reg_n].code=code; g_lowva_cm_reg_n++;
    }
}

static int nx_lowva_map_one(uintptr_t addr, size_t len) {
    void* src = memalign(VM_PAGE, len);
    if (!src) return -1;
    if (R_SUCCEEDED(svcMapMemory((void*)addr, src, len))) {   // Stack-region VAs: fast path
        memset((void*)addr, 0, len); nx_lowva_cm_reg_add(addr, len, INVALID_HANDLE, src, 0); return 0;
    }
    Handle cm = INVALID_HANDLE;
    Result rc = svcCreateCodeMemory(&cm, src, len);
    if (R_SUCCEEDED(rc)) {
        Result rc2 = svcControlCodeMemory(cm, CodeMapOperation_MapOwner, (void*)addr, len, Perm_Rw);
        if (R_SUCCEEDED(rc2)) { memset((void*)addr, 0, len); g_lowva_cm_live++;
                                nx_lowva_cm_reg_add(addr, len, cm, src, 1); return 0; }   // keep cm+src alive (freed on munmap)
        svcCloseHandle(cm);
        // ONE-SHOT the MapOwner-failure log. MapOwner=0xdc01 InvalidCurrentMemory is a PLACEMENT/boundary
        // failure (you can't map a CodeMemory page abutting an existing CodeMemory region); it fails at EVERY
        // size, so the caller's adaptive-halve retries it ~13x, and the guest then re-commits/re-faults in a
        // loop — logging it each time floods the result file (60k+ lines) and hangs the run. Log once.
        static int logged_mo = 0;
        if (!logged_mo) {
            logged_mo = 1;
            MemoryInfo mi; u32 pi;
            Result qr = svcQueryMemory(&mi, &pi, addr);
            char b[220]; int n = snprintf(b, sizeof b,
                         "nx_vm: lowVA 0x%lx+0x%lx MapOwner=0x%x live=%d | q=0x%x region[0x%lx+0x%lx] type=0x%x perm=0x%x",
                         (unsigned long)addr, (unsigned long)len, (unsigned)rc2, g_lowva_cm_live, (unsigned)qr,
                         (unsigned long)mi.addr, (unsigned long)mi.size, (unsigned)mi.type, (unsigned)mi.perm);
            if (n>0) { svcOutputDebugString(b,n); nx_result_log(b); }
        }
    } else {
        int oor = (((unsigned)rc >> 9) & 0x1FFF) == 103;    // Kernel desc 103 (0xce01) = OutOfResource
        if (oor) g_lowva_slab_full = 1;                      // KCodeMemory slab exhausted
        static int logged_cc = 0;
        if (!logged_cc || !oor) {
            logged_cc = 1;
            char b[140]; int n = snprintf(b, sizeof b, "nx_vm: lowVA 0x%lx+0x%lx CreateCodeMemory=0x%x live=%d",
                         (unsigned long)addr, (unsigned long)len, (unsigned)rc, g_lowva_cm_live);
            if (n>0) { svcOutputDebugString(b,n); nx_result_log(b); }
        }
    }
    free(src); return -1;
}

// Back a low VA (outside the heap: Win32 KUSER_SHARED_DATA @0x7ffe0000, PE image bases, Wine's low
// reservations) with CodeMemory MapOwner. The KCodeMemory slab is TINY and system-wide (~a dozen objects;
// svcCreateCodeMemory returns 0xce01 OutOfResource once exhausted — NOT governed by system_resource_size),
// so ONE object per Wine commit exhausts it (cmd.exe needs ~9 distinct low-VA regions). To fit, COALESCE:
// back a coarse ALIGNED window (clipped to the enclosing reservation) so clustered commits share one large
// object, and use a LARGE per-object chunk (adaptively halved if MapOwner rejects the size). Guest pages are
// never executed natively, so RW backing + box64's no-op mprotect suffices.
#define NX_LOWVA_CHUNK     (32UL*1024*1024)   // MapOwner size (adaptive-halve if Horizon/memalign balk)
#define NX_LOWVA_COALESCE  (32UL*1024*1024)   // round each commit's backing out to this granule (merge clusters)
#define NX_LOWVA_RELOC_THRESH 4               // once this many CodeMemory slab objects are live, bounce further
                                              // MAP_FIXED_NOREPLACE image reservations (Wine relocates them to
                                              // the heap — no slab cost). Keeps the slab for early/essential
                                              // modules (start.exe/ntdll — the main EXE has no .reloc and CANNOT
                                              // be relocated, so it must stay on the slab at its base) + the
                                              // tiny fixed pages (KUSER/TEB). Setting this too low bounces the
                                              // EXE -> Wine can't relocate it -> STATUS_DLL_NOT_FOUND.
static void* nx_map_lowva_fixed(void* addr, size_t rounded, int prot, int flags) {
    if (nx_lowva_covered((uintptr_t)addr, rounded)) { memset(addr, 0, rounded); nx_kuser_fixup(addr, rounded); return addr; }
    uintptr_t base = (uintptr_t)addr;

    // KCodeMemory-slab relief — THE cmd.exe-on-real-HW fix. A PE image reservation uses MAP_FIXED_NOREPLACE
    // ("map here if free, else fail and I'll cope"); Wine's virtual_map_image retries the mapping at NULL
    // when the preferred ImageBase fails (wine-8.0 dlls/ntdll/unix/virtual.c:2479), and a NULL-hint mmap on
    // Horizon lands in box64's memalign heap — which costs NO KCodeMemory slab object. The slab is only
    // ~a dozen objects system-wide and cmd.exe pulls in ~10 modules (both guests share the space), so once
    // the slab is under pressure we REFUSE new image reservations with EEXIST and let Wine relocate the
    // module into the heap for free. Guard on size (>=64 KiB) so the tiny must-be-fixed pages (KUSER
    // @0x7ffe0000, TEB) are never bounced; early/essential modules load below the threshold and keep their
    // preferred base. Returning EEXIST for MAP_FIXED_NOREPLACE is exactly that flag's contract.
    if ((flags & MAP_FIXED_NOREPLACE) && rounded >= 0x10000 && g_lowva_cm_live >= NX_LOWVA_RELOC_THRESH) {
        static int logged_reloc = 0;
        if (!logged_reloc) { logged_reloc = 1; char b[128];
            int n = snprintf(b, sizeof b, "nx_vm: bounce img 0x%lx+0x%lx (slab live=%d) -> Wine relocates to heap",
                     (unsigned long)base, (unsigned long)rounded, g_lowva_cm_live); if (n > 0) nx_result_log(b); }
        errno = EEXIST; return MAP_FAILED;
    }

    // Cheaply reject fixed low VAs OUTSIDE the process's mappable ASLR region. Wine's ntdll reserves the
    // ENTIRE low Win32 space during virtual_init — thousands of best-effort PROT_NONE ranges from 0x10000
    // up (esp. the whole 0x10000..aslr_base window BELOW where anything can be mapped). svcControlCodeMemory
    // MapOwner can only map INSIDE the ASLR region, so every out-of-region address fails anyway (0xdc01) —
    // but running the svcCreateCodeMemory+MapOwner+close dance ~2000x churns the CodeMemory resource to
    // EXHAUSTION (svcCreateCodeMemory then returns 0xce01 OutOfResource), which breaks the CRITICAL
    // in-region maps that follow — notably KUSER_SHARED_DATA @0x7ffe0000, whose failure is FATAL
    // (virtual_alloc_first_teb -> "failed to map the shared user data: c000000d" -> exit(1)). Wine tolerates
    // a failed reservation, so reject out-of-region low VAs immediately and keep the budget for real maps.
    {
        static uintptr_t asb = 0, ase = 0;
        if (!ase) {
            u64 a = 0, s = 0;
            svcGetInfo(&a, InfoType_AslrRegionAddress, CUR_PROCESS_HANDLE, 0);
            svcGetInfo(&s, InfoType_AslrRegionSize,    CUR_PROCESS_HANDLE, 0);
            asb = (uintptr_t)a; ase = (uintptr_t)(a + s);
        }
        if (ase && (base < asb || base + rounded > ase)) { errno = ENOMEM; return MAP_FAILED; }
    }

    // PROT_NONE reservation: record it but DEFER real backing until Wine commits a sub-range (mmap PROT_RW
    // here, or mprotect PROT_RW -> nx_vm_protect). Backing the whole reservation now would exhaust the
    // CodeMemory resource (see g_lowva_resv note). Return the VA unmapped (Wine never touches a reservation).
    if (!(prot & (PROT_READ | PROT_WRITE))) { nx_lowva_resv_track(base, rounded); return addr; }

    // Coalesce the backing to a COARSE-aligned window so ADJACENT commits (esp. separate Wine DLL images,
    // each its own reservation) share ONE large CodeMemory object — critical because the KCodeMemory slab
    // is ~a dozen system-wide and cmd.exe pulls in ~8 DLLs. We do NOT clip to base's reservation (that
    // stops adjacent reservations from merging); box64's own regions live in the HIGH ASLR area, never in
    // this low Win32 window, so a low-VA window can't collide with them. The per-page backing loop below
    // skips any already-mapped page, so overlapping an earlier window is harmless. Clip only to the ASLR
    // region, and always cover the whole request.
    uintptr_t wbeg = base & ~(NX_LOWVA_COALESCE - 1);
    uintptr_t wend = (base + rounded + NX_LOWVA_COALESCE - 1) & ~(NX_LOWVA_COALESCE - 1);
    if (wbeg > base) wbeg = base;
    if (wend < base + rounded) wend = base + rounded;
    { static uintptr_t asb = 0, ase = 0;
      if (!ase) { u64 a=0,s=0; svcGetInfo(&a,InfoType_AslrRegionAddress,CUR_PROCESS_HANDLE,0);
                  svcGetInfo(&s,InfoType_AslrRegionSize,CUR_PROCESS_HANDLE,0); asb=(uintptr_t)a; ase=(uintptr_t)(a+s); }
      if (ase) { if (wbeg < asb) wbeg = asb; if (wend > ase) wend = ase; } }

    // Back the window, skipping already-mapped PAGES (a commit's window routinely OVERLAPS an earlier
    // window — Wine commits ranges that straddle regions we already backed; mapping over an occupied page
    // fails MapOwner). Map each contiguous UNCOVERED run as one object (adaptive-shrink if MapOwner balks).
    int orig_ok = 1;
    uintptr_t p = wbeg;
    while (p < wend && !g_lowva_slab_full) {
        if (nx_lowva_covered(p, VM_PAGE)) { p += VM_PAGE; continue; }   // already backed
        uintptr_t q = p + VM_PAGE;                                      // extent of the uncovered run
        while (q < wend && (q - p) < NX_LOWVA_CHUNK && !nx_lowva_covered(q, VM_PAGE)) q += VM_PAGE;
        size_t m = q - p;
        while (m >= VM_PAGE && !g_lowva_slab_full && nx_lowva_map_one(p, m) != 0)
            m = (m > VM_PAGE) ? ((m >> 1) & ~VM_PAGEMASK) : 0;
        if (m >= VM_PAGE && !g_lowva_slab_full) { nx_lowva_track(p, m); p += m; }
        else { if (p < base + rounded && p + VM_PAGE > base) orig_ok = 0; p += VM_PAGE; }  // request page unmappable
    }
    if (!orig_ok || g_lowva_slab_full) { errno = ENOMEM; return MAP_FAILED; }
    nx_kuser_fixup(addr, rounded);
    return addr;
}

static void* nx_mmap_heap(void* addr, size_t rounded, int flags, int prot) {
    if (flags & (MAP_FIXED | MAP_FIXED_NOREPLACE)) {
        if (!(flags & MAP_ANONYMOUS) || !addr) { errno = ENODEV; return MAP_FAILED; }
        // A low VA outside the heap must be explicitly backed (Wine's Win32 address space). A high
        // MAP_FIXED (the guest ELF/arena at 0x2xx… heap addresses) is already heap-backed -> just zero it.
        if ((uintptr_t)addr < (uintptr_t)fake_heap_start || (uintptr_t)addr >= (uintptr_t)fake_heap_end)
            return nx_map_lowva_fixed(addr, rounded, prot, flags);
        memset(addr, 0, rounded);
        return addr;
    }
    // 64 KiB-align: a NULL-hint mmap is Wine's map_view fallback (incl. a RELOCATED image, our slab fix),
    // which over-allocates size+granularity then munmap-trims to 64 KiB alignment. If the block is already
    // 64 KiB-aligned the head-trim is empty and the tail-trim (an interior munmap) is a no-op in nx_munmap
    // (not the tracked base) — so the whole memalign block stays intact and is freed on the module's final
    // munmap. A 4 KiB-aligned block would let Wine munmap the block BASE (freeing it out from under itself).
    void* p = memalign(0x10000, rounded);   // newlib malloc is itself thread-safe
    if (!p) { errno = ENOMEM; return MAP_FAILED; }
    if (flags & MAP_ANONYMOUS) memset(p, 0, rounded);
    mutexLock(&vm_lock); hb_track((uintptr_t)p, rounded); mutexUnlock(&vm_lock);
    return p;
}

// ---------------------------------------------------------------------------------------------
// Public mmap / munmap / mprotect
// ---------------------------------------------------------------------------------------------
void* nx_mmap(void* addr, unsigned long length, int prot, int flags, int fd, ssize_t offset) {
    if (!length) return MAP_FAILED;
    { extern void nx_applet_keepalive(void); nx_applet_keepalive(); }   // keep our layer on screen during a long run

    // M2.5: mmap of a wineserver SHMEM vfd (tmpmap-*) returns the SINGLE in-process shared buffer, so
    // the client and wineserver map the SAME memory (real shared memory in the one address space).
    extern int nx_vfd_is(int fd);
    extern void* nx_vfd_mmap(int fd, size_t length, off_t offset);
    if (fd >= 0 && nx_vfd_is(fd)) return nx_vfd_mmap(fd, (size_t)length, (off_t)offset);

    // M2.1: Horizon has no file-backed mmap. The guest's real ld.so maps libc's segments with
    // MAP_PRIVATE(|MAP_FIXED), fd, offset, so emulate it: map anonymous memory, then read the file
    // content at `offset` into it (the tail past EOF stays zero = bss). Mirrors box64's own elf-loader
    // fallback. box64's mprotect is a no-op on Switch, so mapping the page RW then reading is fine.
    if (fd >= 0 && !(flags & MAP_ANONYMOUS)) {
        void* p = nx_mmap(addr, length, prot, flags | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) return MAP_FAILED;
        off_t save = lseek(fd, 0, SEEK_CUR);
        if (lseek(fd, (off_t)offset, SEEK_SET) != (off_t)-1) {
            // Read via a HEAP bounce buffer, not directly into the mapped region. The region is
            // CodeMemory (svcControlCodeMemory MapOwner) on Horizon; fsdev's ReadFile IPC receive
            // buffer must be in a Normal/heap memory state. Passing a Code-state buffer makes
            // svcSendSyncRequest fail — Ryujinx returns InvalidCurrentMemory and, for a
            // get_handle_fd-passed section fd, the read HANGS instead of returning an error, wedging
            // the wine client mid-DLL-load (e.g. the 0x8330000 section after kernelbase). A heap
            // bounce buffer is always a valid IPC state; memcpy into the region afterwards (CPU, no
            // IPC). If the tiny malloc ever fails, fall back to the old direct read.
            size_t done = 0;
            size_t bufsz = 256 * 1024; if (bufsz > length) bufsz = length;
            char* bounce = (char*)malloc(bufsz);
            while (done < length) {
                size_t want = length - done; if (want > bufsz) want = bufsz;
                ssize_t r = bounce ? read(fd, bounce, want)
                                   : read(fd, (char*)p + done, length - done);
                if (r <= 0) break;
                if (bounce) memcpy((char*)p + done, bounce, (size_t)r);
                done += (size_t)r;
            }
            free(bounce);
        }
        if (save != (off_t)-1) lseek(fd, save, SEEK_SET);
        // KUSER_SHARED_DATA is file-backed MAP_SHARED at 0x7ffe0000; the file read above just wrote
        // the wineserver's per-instance copy (SystemCall=0) over the page, so re-assert SystemCall=1
        // AFTER the read (see nx_kuser_fixup — the client must use the dispatcher, not raw syscalls).
        nx_kuser_fixup(p, VM_ROUND(length));
        // Marker: the guest ld.so file-backs libc's (and other .so) segments here — the runtime load base
        // of each .so, so a creport's guest RIP (X[27]) resolves to lib+offset. Useful for a JIT/loader
        // crash but it's ~hundreds of lines that bury guest (Wine) error output, so gate it: set KX_MMAP_LOG
        // in box64.env to re-enable when chasing a load-base fault. (Read once; cached.)
        { static int mlog = -1; if (mlog < 0) mlog = getenv("KX_MMAP_LOG") ? 1 : 0;
          if (mlog) { char b[128]; snprintf(b, sizeof b, "mmap file fd=%d off=0x%lx len=0x%lx -> 0x%lx",
                   fd, (unsigned long)offset, (unsigned long)length, (unsigned long)p); nx_result_log(b); } }
        return p;
    }
    (void)offset;
    size_t rounded = VM_ROUND(length);

    vm_ensure_init();
    if (vm_backend == VM_HEAP)
        return nx_mmap_heap(addr, rounded, flags, prot);

    // PHYS or UNSAFE arena
    if (flags & MAP_FIXED) {
        if (!(flags & MAP_ANONYMOUS) || !addr) { errno = ENODEV; return MAP_FAILED; }
        uintptr_t a = (uintptr_t)addr;
        if (vm_in_arena(a, rounded)) { memset(addr, 0, rounded); return addr; }   // pages already backed
        if (R_FAILED(vm_map(addr, rounded))) { errno = ENOMEM; return MAP_FAILED; }
        memset(addr, 0, rounded);
        return addr;
    }

    mutexLock(&vm_lock);
    uintptr_t a = vm_reserve(rounded);
    mutexUnlock(&vm_lock);
    if (!a) { errno = ENOMEM; return MAP_FAILED; }
    if (R_FAILED(vm_map((void*)a, rounded))) {
        mutexLock(&vm_lock); vm_release(a, rounded); mutexUnlock(&vm_lock);
        errno = ENOMEM;
        return MAP_FAILED;
    }
    if (flags & MAP_ANONYMOUS) memset((void*)a, 0, rounded);   // page already reserved to this thread
    return (void*)a;
}

// Reclaim registered low-VA CodeMemory chunks fully inside [a, a+len) — a Wine VirtualFree/MEM_RELEASE.
// Returns the count freed. Frees the kernel object + src heap and drops the g_lowva coverage entry, and
// clears g_lowva_slab_full so the freed slot can be reused (the KCodeMemory slab is the scarce resource).
static int nx_lowva_free_range(uintptr_t a, size_t len) {
    int freed = 0;
    for (int i = 0; i < g_lowva_cm_reg_n; ) {
        uintptr_t ca = g_lowva_cm_reg[i].addr; size_t cl = g_lowva_cm_reg[i].len;
        if (ca >= a && ca + cl <= a + len) {
            if (g_lowva_cm_reg[i].code) {
                svcControlCodeMemory(g_lowva_cm_reg[i].cm, CodeMapOperation_UnmapOwner, (void*)ca, cl, 0);
                svcCloseHandle(g_lowva_cm_reg[i].cm);
                if (g_lowva_cm_live > 0) g_lowva_cm_live--;
                g_lowva_slab_full = 0;
            } else {
                svcUnmapMemory((void*)ca, g_lowva_cm_reg[i].src, cl);
            }
            free(g_lowva_cm_reg[i].src);
            for (int j = 0; j < g_lowva_n; j++)
                if (g_lowva[j].base == ca) { g_lowva[j] = g_lowva[--g_lowva_n]; break; }
            g_lowva_cm_reg[i] = g_lowva_cm_reg[--g_lowva_cm_reg_n];   // swap-remove
            freed++;
        } else i++;
    }
    return freed;
}

int nx_munmap(void* addr, unsigned long length) {
    if (!addr || !length) return 0;
    size_t rounded = VM_ROUND(length);
    uintptr_t a = (uintptr_t)addr;

    if (vm_backend != VM_HEAP && vm_in_arena(a, rounded)) {
        vm_unmap(addr, rounded);   // real reclaim of the physical pages...
        mutexLock(&vm_lock); vm_release(a, rounded); mutexUnlock(&vm_lock);   // ...and the address range
        return 0;
    }
    mutexLock(&vm_lock);
    int freed = nx_lowva_free_range(a, rounded);   // reclaim low-VA CodeMemory (Wine VirtualFree)
    int found = freed ? 0 : hb_untrack(a);
    mutexUnlock(&vm_lock);
    if (found) free(addr);         // heap-fallback whole-block reclaim
    return 0;
}

// Page permissions. DE-RISKED (M2.2c2, 2026-07-09): svcSetMemoryPermission DOES work on the guest's
// heap-backed/file-mmap'd pages on real HW (R and Rw both return 0x0). BUT making this real for ALL mprotect
// destabilizes box64: it also honors the guest's own read-only mappings (mmap PROT_READ / ld.so RELRO), and
// box64's native loader/helpers then Data-Abort writing into those pages (seen: a WnR=1 fault at a
// non-PROT_DYNAREC guest addr from box64 native code -> unhandled -> crash). So this stays a no-op: the SMC
// backend must protect ONLY box64's protectDB code pages (a dedicated svcSetMemoryPermission path in
// custommem.c's protectDB/unprotectDB), NOT the guest's own mappings. [full-c2 Stage 3 — focused follow-up;
// see tests/m2/smc.c + docs/porting-log.md]. box64 never executes guest pages (exec is the jit path).
int nx_vm_protect(void* addr, size_t len, int prot) {
    // Commit within a deferred PROT_NONE reservation: Wine reserves a big low-VA range (PROT_NONE, which we
    // did NOT back — see nx_lowva_resv), then commits sub-ranges by mprotect'ing them PROT_RW. Back the
    // sub-range NOW (once). This is the ONLY place nx_vm_protect actually maps memory; it does NOT enforce
    // permissions on already-backed pages (making that real destabilizes box64 — see note below), so it
    // can't fault box64's own writes into guest RO/RELRO pages.
    if ((prot & (PROT_READ | PROT_WRITE)) && addr && len) {
        uintptr_t start = (uintptr_t)addr & ~((uintptr_t)VM_PAGE - 1);
        size_t rounded = VM_ROUND(len + ((uintptr_t)addr - start));
        // Any RW/R mprotect on a low VA OUTSIDE box64's heap that isn't backed yet = Wine committing into
        // its Win32 space (reserve PROT_NONE -> commit by mprotect). Back it (nx_map_lowva_fixed re-checks
        // covered + the ASLR-region gate + coalesces). Gate on outside-heap so the guest's own high-VA
        // heap/arena mprotects (already heap-backed) stay no-ops.
        extern char *fake_heap_start, *fake_heap_end;
        if ((start < (uintptr_t)fake_heap_start || start >= (uintptr_t)fake_heap_end)
            && !nx_lowva_covered(start, rounded))
            nx_map_lowva_fixed((void*)start, rounded, prot, 0);   // flags=0: a commit must succeed (not a
                                                                  // relocatable image); back it + track

    } else if (!(prot & (PROT_READ | PROT_WRITE | PROT_EXEC)) && addr && len) {
        // PROT_NONE mprotect on a low VA = Wine DECOMMITTING (VirtualFree MEM_DECOMMIT). Reclaim the backing
        // CodeMemory NOW — the KCodeMemory slab is the scarce resource, and Wine decommits temp buffers
        // during startup; a re-commit later re-backs it. Only whole registered chunks fully inside the
        // range are freed (partial decommits keep their object). Frees a slab slot for the next map.
        uintptr_t start = (uintptr_t)addr & ~((uintptr_t)VM_PAGE - 1);
        size_t rounded = VM_ROUND(len + ((uintptr_t)addr - start));
        extern char *fake_heap_start, *fake_heap_end;
        if (start < (uintptr_t)fake_heap_start || start >= (uintptr_t)fake_heap_end)
            nx_lowva_free_range(start, rounded);
    }
    if (prot & PROT_EXEC) {
        static int warned = 0;
        if (!warned) { warned = 1; svcOutputDebugString("nx_vm: mprotect(PROT_EXEC) no-op\n", 32); }
    }
    return 0;
}

// SMC / Stage 3 (M2.2, 2026-07-09): apply REAL page permissions to box64's own translated-code pages ONLY —
// called from custommem.c's protectDB/unprotectDB, NOT from the general nx_vm_protect above (which stays a
// no-op: making that real destabilizes box64, as it would honor the guest's own RO mmap/RELRO and box64
// native writes then fault). A guest write to a protected code page then Data-Aborts and nx_exception.c's
// SMC branch unprotects it + re-runs the store. box64 never executes guest x86 pages natively (exec is the
// jit path), so R (protect) / Rw (unprotect) are the only perms needed — which is exactly what
// svcSetMemoryPermission accepts (it rejects X). addr/len arrive page-aligned from protectDB; align anyway.
int nx_vm_protect_code(void* addr, size_t len, int prot) {
    extern uintptr_t box64_pagesize;
    uintptr_t a = (uintptr_t)addr & ~(box64_pagesize - 1);
    uintptr_t e = ((uintptr_t)addr + len + box64_pagesize - 1) & ~(box64_pagesize - 1);
    Permission perm = (prot & PROT_WRITE) ? Perm_Rw : Perm_R;
    Result rc = svcSetMemoryPermission((void*)a, e - a, perm);
    if (rc) {
        static int warned = 0;
        if (!warned) {
            warned = 1;
            char b[120];
            int n = snprintf(b, sizeof b, "nx_vm: protectDB svcSetMemoryPermission(%p,0x%lx,%d)=0x%x\n",
                             (void*)a, (unsigned long)(e - a), (int)perm, (unsigned)rc);
            if (n > 0) svcOutputDebugString(b, n);
        }
        return -1;
    }
    return 0;
}

#endif // __SWITCH__
