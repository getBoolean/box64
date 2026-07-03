// box64-nx — libnx jit-backed W^X code memory for the ARM64 dynarec (M1.2). See nx_jit.h.
//
// Wraps libnx `jit` (switch/kernel/jit.h) so box64's dynarec can obtain executable memory on
// Horizon's W^X memory model. The Phase-0 spike (tests/m1/jitprobe) established that after a single
// `jitTransitionToExecutable`, the `rw` (write) and `rx` (execute) aliases stay simultaneously
// valid, so we transition once at chunk creation and thereafter write via `rw` / execute via `rx`
// with only a cache flush in between — no further transitions.

#ifdef __SWITCH__

#include "nx_jit.h"

#include <switch.h>
#include <stdlib.h>

#define NX_JIT_PAGE 0x1000ULL

// Each dynarec chunk keeps its Jit alive for the whole run (the dynarec never releases a chunk in
// the M1 scope). A small intrusive list is enough — chunk creation is rare (2 MiB at a time).
typedef struct nx_jit_node_s {
    Jit                    jit;
    struct nx_jit_node_s*  next;
} nx_jit_node_t;

static nx_jit_node_t* nx_jit_list = NULL;

void* nx_jit_alloc(size_t size, int64_t* out_rw_bias)
{
    if (!size)
        return NULL;
    size = (size + (NX_JIT_PAGE - 1)) & ~(NX_JIT_PAGE - 1);

    nx_jit_node_t* node = (nx_jit_node_t*)calloc(1, sizeof(nx_jit_node_t));
    if (!node)
        return NULL;

    Result r = jitCreate(&node->jit, size);
    if (R_FAILED(r)) {
        free(node);
        return NULL;
    }
    // Establish the executable (`rx`) mapping once. Per the Phase-0 spike the `rw` alias stays
    // writable afterwards, so no further jitTransition* calls are needed for the chunk's lifetime.
    r = jitTransitionToExecutable(&node->jit);
    if (R_FAILED(r)) {
        jitClose(&node->jit);
        free(node);
        return NULL;
    }

    node->next = nx_jit_list;
    nx_jit_list = node;

    void* rw = jitGetRwAddr(&node->jit);
    void* rx = jitGetRxAddr(&node->jit);
    if (out_rw_bias)
        *out_rw_bias = (int64_t)((intptr_t)rw - (intptr_t)rx);
    return rw;
}

#endif // __SWITCH__
