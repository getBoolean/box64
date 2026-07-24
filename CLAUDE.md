IMPORTANT: Ensure you’ve thoroughly reviewed the [AGENTS.md](AGENTS.md) file before beginning any work.

---

## KurokoNX fork (`kurokonx-horizon` branch) — code style

> Scope: applies to KurokoNX-port work on the `kurokonx-horizon` fork branch (the Switch/Horizon `src/os/switch/`
> layer + the dynarec/W^X adaptations). It does not alter upstream box64's contribution policy in `AGENTS.md`.

Write self-documenting code — clarity a reader gets without decoding:

- **Name every non-obvious literal** as a `#define`/`enum` constant — buffer sizes, limits, tunable
  defaults, bit masks, unit conversions, and especially exit/return codes (an `enum { EXIT_FOO = 3, … }`,
  never a bare `return 3`). A magic number in an expression is a bug waiting to be miscopied.
- **Descriptive names** for variables and struct fields (`num_threads`, `working_set`, `result_code`),
  not single letters — EXCEPT genuinely idiomatic ones (`i`/`j` loop counters, `fd`, `argc`/`argv`),
  where a long name is noise. Don't lean on a comment to explain a name a better name would carry.
- **Comments carry WHY** (rationale, gotchas, invariants, HW-verified facts); **names carry WHAT.**
  Don't over-comment self-evident code.