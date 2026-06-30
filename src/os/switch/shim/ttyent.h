// KurokoNX shim — <ttyent.h> (BSD/glibc ttys db; stubbed for link).
#pragma once
#ifdef __SWITCH__
#define _PATH_TTYS "/etc/ttys"
#define TTY_ON   0x01
#define TTY_SECURE 0x02

struct ttyent {
    char *ty_name;
    char *ty_getty;
    char *ty_type;
    int   ty_status;
    char *ty_window;
    char *ty_comment;
};

struct ttyent *getttyent(void);
struct ttyent *getttynam(const char *tty);
int setttyent(void);
int endttyent(void);
#endif // __SWITCH__
