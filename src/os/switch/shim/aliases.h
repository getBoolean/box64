// KurokoNX shim — <aliases.h> (glibc mail aliases; stubbed for link).
#pragma once
#ifdef __SWITCH__
#include <stdio.h>
struct aliasent {
    char    *alias_name;
    size_t   alias_members_len;
    char   **alias_members;
    int      alias_local;
};
void setaliasent(void);
void endaliasent(void);
struct aliasent *getaliasent(void);
struct aliasent *getaliasbyname(const char *name);
int getaliasent_r(struct aliasent *result, char *buffer, size_t buflen, struct aliasent **res);
int getaliasbyname_r(const char *name, struct aliasent *result, char *buffer, size_t buflen, struct aliasent **res);
#endif // __SWITCH__
