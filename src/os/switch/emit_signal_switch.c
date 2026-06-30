// box64 Horizon port — guest fault/interrupt emitters (KurokoNX).
// A clean static M1 guest doesn't fault, so these log loudly rather than deliver a host signal
// (Horizon has no POSIX signal delivery). Real guest-signal emulation is M2+ work.
#ifdef __SWITCH__

#include "emit_signals.h"
#include "x64emu.h"
#include "debug.h"

void EmitSignal(x64emu_t* emu, int sig, void* addr, int code) {
    (void)emu;
    printf_log(LOG_NONE, "[switch] EmitSignal sig=%d at %p code=%d (unhandled)\n", sig, addr, code);
}
void EmitInterruption(x64emu_t* emu, int num, void* addr) {
    (void)emu;
    printf_log(LOG_NONE, "[switch] EmitInterruption %d at %p (unhandled)\n", num, addr);
}
void EmitWineInt(x64emu_t* emu, int num, void* addr) {
    (void)emu;
    printf_log(LOG_NONE, "[switch] EmitWineInt %d at %p (unhandled)\n", num, addr);
}
void EmitDiv0(x64emu_t* emu, void* addr, int code) {
    (void)emu; (void)code;
    printf_log(LOG_NONE, "[switch] EmitDiv0 at %p (unhandled)\n", addr);
}
void CheckExec(x64emu_t* emu, uintptr_t addr) { (void)emu; (void)addr; }

#endif // __SWITCH__
