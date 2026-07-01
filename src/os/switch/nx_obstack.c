// box64-nx — host GNU obstack implementation for the Switch build.
//
// box64's src/libtools/obstack.c wraps the *guest's* obstack usage and calls the
// host out-of-line obstack functions (_obstack_begin/_obstack_newchunk/...), which
// glibc provides but newlib does not. This is the canonical FSF obstack algorithm
// (pure userspace memory management, no OS dependency). A static M1 guest never
// exercises it, but box64 must link.
#ifdef __SWITCH__

#include <obstack.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

// <obstack.h> defines obstack_free / __obstack_free as macros (the inline fast
// path); undef them so we can define the real out-of-line free function symbol.
#undef obstack_free
#undef __obstack_free

// Default alignment + rounding, as in glibc's obstack.c.
struct fooalign { char x; double d; };
#define DEFAULT_ALIGNMENT ((PTR_INT_TYPE)((char*)&((struct fooalign*)0)->d - (char*)0))
union fooround { uintmax_t i; long double d; void* p; };
#define DEFAULT_ROUNDING ((PTR_INT_TYPE)sizeof(union fooround))

int obstack_exit_failure = 1;

static void print_and_abort(void);
void (*obstack_alloc_failed_handler)(void) = print_and_abort;

// Call the chunk alloc/free funcs with or without the extra arg.
#define CALL_CHUNKFUN(h, size) \
  (((h)->use_extra_arg) \
   ? (*(h)->chunkfun)((h)->extra_arg, (size)) \
   : (*(struct _obstack_chunk *(*)(long))(void*)(h)->chunkfun)((size)))

#define CALL_FREEFUN(h, old_chunk) \
  do { \
    if ((h)->use_extra_arg) \
      (*(h)->freefun)((h)->extra_arg, (old_chunk)); \
    else \
      (*(void (*)(void *))(void*)(h)->freefun)((old_chunk)); \
  } while (0)

static int _obstack_begin_worker(struct obstack* h, int size, int alignment, int use_extra_arg, void* arg)
{
    struct _obstack_chunk* chunk;

    if (alignment == 0)
        alignment = (int)DEFAULT_ALIGNMENT;
    if (size == 0) {
        // Default: big enough for a few chunk headers, rounded.
        int extra = ((((12 + DEFAULT_ROUNDING - 1) & ~(DEFAULT_ROUNDING - 1)) + 4 + DEFAULT_ROUNDING - 1)
                     & ~(DEFAULT_ROUNDING - 1));
        size = 4096 - extra;
    }

    h->chunk_size = size;
    h->alignment_mask = alignment - 1;
    h->use_extra_arg = use_extra_arg ? 1 : 0;
    h->extra_arg = arg;

    chunk = h->chunk = CALL_CHUNKFUN(h, h->chunk_size);
    if (!chunk) {
        (*obstack_alloc_failed_handler)();
        return 0;
    }
    h->next_free = h->object_base =
        __PTR_ALIGN((char*)chunk, chunk->contents, h->alignment_mask);
    h->chunk_limit = chunk->limit = (char*)chunk + h->chunk_size;
    chunk->prev = 0;
    h->maybe_empty_object = 0;
    h->alloc_failed = 0;
    return 1;
}

int _obstack_begin(struct obstack* h, int size, int alignment,
                   void* (*chunkfun)(long), void (*freefun)(void*))
{
    h->chunkfun = (struct _obstack_chunk* (*)(void*, long))chunkfun;
    h->freefun = (void (*)(void*, struct _obstack_chunk*))freefun;
    return _obstack_begin_worker(h, size, alignment, 0, NULL);
}

int _obstack_begin_1(struct obstack* h, int size, int alignment,
                     void* (*chunkfun)(void*, long),
                     void (*freefun)(void*, void*), void* arg)
{
    h->chunkfun = (struct _obstack_chunk* (*)(void*, long))chunkfun;
    h->freefun = (void (*)(void*, struct _obstack_chunk*))freefun;
    return _obstack_begin_worker(h, size, alignment, 1, arg);
}

void _obstack_newchunk(struct obstack* h, int length)
{
    struct _obstack_chunk* old_chunk = h->chunk;
    struct _obstack_chunk* new_chunk;
    long new_size;
    long obj_size = h->next_free - h->object_base;
    char* object_base;

    // Compute size for new chunk.
    new_size = (obj_size + length) + (obj_size >> 3) + h->alignment_mask + 100;
    if (new_size < h->chunk_size)
        new_size = h->chunk_size;

    new_chunk = CALL_CHUNKFUN(h, new_size);
    if (!new_chunk) {
        (*obstack_alloc_failed_handler)();
        return;
    }
    h->chunk = new_chunk;
    new_chunk->prev = old_chunk;
    new_chunk->limit = h->chunk_limit = (char*)new_chunk + new_size;

    object_base = __PTR_ALIGN((char*)new_chunk, new_chunk->contents, h->alignment_mask);

    // Move the existing object into the new chunk.
    {
        long i;
        for (i = obj_size - 1; i >= 0; i--)
            object_base[i] = h->object_base[i];
    }

    // If the old chunk now holds only this object, free it.
    if (!h->maybe_empty_object
        && (h->object_base
            == __PTR_ALIGN((char*)old_chunk, old_chunk->contents, h->alignment_mask))) {
        new_chunk->prev = old_chunk->prev;
        CALL_FREEFUN(h, old_chunk);
    }

    h->object_base = object_base;
    h->next_free = h->object_base + obj_size;
    h->maybe_empty_object = 0;
}

int _obstack_allocated_p(struct obstack* h, void* obj)
{
    struct _obstack_chunk* lp;
    struct _obstack_chunk* plp;
    lp = h->chunk;
    while (lp != 0 && ((void*)lp >= obj || (void*)(lp)->limit < obj)) {
        plp = lp->prev;
        lp = plp;
    }
    return lp != 0;
}

// Real out-of-line free function. The header aliases __obstack_free -> obstack_free.
void obstack_free(struct obstack* h, void* obj)
{
    struct _obstack_chunk* lp;
    struct _obstack_chunk* plp;

    lp = h->chunk;
    while (lp != 0 && ((void*)lp >= obj || (void*)(lp)->limit < obj)) {
        plp = lp->prev;
        CALL_FREEFUN(h, lp);
        lp = plp;
        h->maybe_empty_object = 1;
    }
    if (lp) {
        h->object_base = h->next_free = (char*)(obj);
        h->chunk_limit = lp->limit;
        h->chunk = lp;
    } else if (obj != 0) {
        h->chunk = 0;
    }
}

// NB: public obstack_free() is a macro in <obstack.h> that calls __obstack_free.

int _obstack_memory_used(struct obstack* h)
{
    struct _obstack_chunk* lp;
    int nbytes = 0;
    for (lp = h->chunk; lp != 0; lp = lp->prev)
        nbytes += lp->limit - (char*)lp;
    return nbytes;
}

static void print_and_abort(void)
{
    fprintf(stderr, "nx_obstack: memory exhausted\n");
    exit(obstack_exit_failure);
}

// --- glibc obstack <-> stdio extensions -------------------------------------------------------
#include <stdarg.h>
#include <string.h>

int obstack_vprintf(struct obstack* h, const char* fmt, va_list ap)
{
    va_list ap2;
    va_copy(ap2, ap);
    int n = vsnprintf(NULL, 0, fmt, ap2);
    va_end(ap2);
    if (n < 0)
        return -1;
    char* buf = (char*)malloc((size_t)n + 1);
    if (!buf)
        return -1;
    vsnprintf(buf, (size_t)n + 1, fmt, ap);
    obstack_grow(h, buf, n);   // append (without the NUL), matching glibc semantics
    free(buf);
    return n;
}

int obstack_printf(struct obstack* h, const char* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int n = obstack_vprintf(h, fmt, ap);
    va_end(ap);
    return n;
}

#endif // __SWITCH__
