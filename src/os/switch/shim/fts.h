// KurokoNX shim — <fts.h> (filesystem-tree walk). Horizon has no fts; box64 only
// forwards the fts_* calls (no field access), so minimal structs + stubs suffice.
#pragma once
#ifdef __SWITCH__
#include <sys/types.h>
#include <sys/stat.h>

typedef struct _ftsent {
    unsigned short  fts_info;
    char           *fts_accpath;
    char           *fts_path;
    char           *fts_name;
    int             fts_level;
    int             fts_errno;
    long            fts_number;
    void           *fts_pointer;
    struct _ftsent *fts_parent;
    struct _ftsent *fts_link;
    struct stat    *fts_statp;
} FTSENT;

typedef struct _fts {
    FTSENT *fts_cur;
    FTSENT *fts_child;
    int     fts_options;
} FTS;

FTS    *fts_open(char *const *path_argv, int options, int (*compar)(const FTSENT **, const FTSENT **));
FTSENT *fts_read(FTS *ftsp);
FTSENT *fts_children(FTS *ftsp, int options);
int     fts_set(FTS *ftsp, FTSENT *f, int options);
int     fts_close(FTS *ftsp);

#endif // __SWITCH__
