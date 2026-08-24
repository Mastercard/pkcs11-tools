# Copilot / AI agent instructions — pkcs11-tools

## Repository layout

- `lib/`   — `libp11`, the core PKCS#11 library (all the real logic lives here).
- `src/`   — the command-line tools (`p11keygen`, `p11wrap`, …); thin `main()`s
  over `libp11`.
- `include/` — public headers. `include/pkcs11lib.h` is the library's API.
  `include/oasis-pkcs11/` is a **git submodule** (vendored OASIS PKCS#11
  headers) — do not edit it.
- `tests/unit/` — compiled C unit tests over `libp11` (+ the mock).
  `tests/integration/` — shell tests against SoftHSM2 / NSS.
- `gl/`     — gnulib sources, **generated** by `gnulib-tool`; never edit by hand.
- `.gnulib/` — the gnulib **git submodule** (pinned commit).

## Build & test workflow

After a fresh clone (and whenever `configure.ac` / a `Makefile.am` changes):

```sh
./bootstrap.sh                         # gnulib-tool --import + autoreconf -vfi
./configure                            # add --enable-coverage for coverage runs
make
```

- **Edit `Makefile.am` / `configure.ac`, never the generated `Makefile.in`,
  `configure`, or anything under `gl/`.** Regenerate with `./bootstrap.sh` (or
  `autoreconf -vfi`). Editing a generated file directly is only ever a temporary
  stop-gap.
- Tests: `make check` runs everything; a single test is
  `make check TESTS=integration/keygen_options.sh`. The summary and failure
  details land in `tests/test-suite.log`.
- Integration tests **self-skip** (Automake exit code 77) when SoftHSM2/NSS or a
  built binary is absent — a SKIP is not a failure, only exit 1 is.
- Coverage: configure with `--enable-coverage`, then `make check` followed by
  `make coverage`. Reports are written under `coverage/`.

## Error handling convention

`libp11` functions return `func_rc` (`rc_ok`, `rc_error_*`; see
`include/pkcs11lib.h`), **not** raw `CK_RV`. The pervasive pattern is a single
cleanup path per function:

```c
if ((rv = p11->C_Foo(...)) != CKR_OK) { pkcs11_error(rv, "C_Foo"); rc = rc_error_pkcs11_api; goto err; }
...
err:
    /* release handles/buffers acquired above */
    return rc;
```

Use `pkcs11_error()` / `pkcs11_warning()` to report a `CK_RV`; follow the
existing `goto err;` cleanup style rather than early `return`s that leak.

## Portability: `getopt(3)` and argument ordering (IMPORTANT)

The command-line tools in `src/` parse options with `getopt(3)`. Argument
ordering behaves differently across platforms:

- **glibc** (`getopt`) permutes `argv`, so options and non-option operands
  (e.g. key attributes like `extractable=true`, object labels) may appear in
  **any order**.
- **POSIX `getopt`** — which is what gnulib's `getopt-gnu` provides on
  **non-glibc** platforms (FreeBSD and the other *BSDs, macOS, Cygwin) — stops
  at the **first** non-option operand. On these systems gnulib's standalone
  `getopt` is compiled with `posixly_correct=1` (`gl/getopt.c`), so it does
  **not** permute. A trailing option placed after an operand is then handed to
  the wrong parser and rejected (e.g. `-W` after key attributes fails with
  `Error during parsing ... unexpected invalid token`).

**Rule:** in tests and any example invocations, **always put every option
before the non-option operands.**

```sh
# WRONG — breaks on FreeBSD/macOS/Cygwin (option -W after operands)
p11keygen -l "$LIB" -k aes -b 128 -i k  extractable=true encrypt=true \
    -W 'wrappingkey="kek",algorithm=rfc5649,filename="out.wrap"'

# RIGHT — options first, operands last
p11keygen -l "$LIB" -k aes -b 128 -i k \
    -W 'wrappingkey="kek",algorithm=rfc5649,filename="out.wrap"' \
    extractable=true encrypt=true
```

See the gnulib manual, "Getopt"
(<https://www.gnu.org/software/gnulib/manual/html_node/getopt.html>): this is
explicitly called out as something to watch for in a project's testsuite. The
non-permutation of plain `getopt()` on non-glibc platforms is a **known,
accepted limitation**, not a per-case bug to work around. Do **not** "fix" it by
switching all tools to `getopt_long` unless a maintainer asks for that broader
change.

## Portability: gnulib overrides in standalone modules

gnulib may replace libc functions on some platforms (e.g. on FreeBSD it defines
`free` as `rpl_free` via `gl/stdlib.h`). Standalone loadable modules that are
**not** linked against `libgnu` (such as the test mock `tests/mock/mock_pkcs11.so`)
must be compiled **without** the gnulib include directories (`-I.../gl`),
otherwise they end up referencing `rpl_free` & friends and fail to `dlopen()`
with `Undefined symbol "rpl_free"`. Use plain libc includes for such modules.

## Portability & genericity (general)

- The project targets **multiple platforms and both endiannesses**. Never assume
  little-endian byte order or a specific word size; serialize/parse binary data
  explicitly (this matters most in the on-disk **wrapped-key format** and other
  binary serialization paths). Keep code working on Linux, the *BSDs, macOS,
  Cygwin/MinGW and the "difficult" Unixes (AIX, Solaris).
- **Prefer gnulib** whenever a portable replacement exists. Reaching for a gnulib
  module is preferred over sprinkling `#ifdef`s to paper over platform
  differences — the goal is a single, uniform behaviour everywhere.
- Keep the tooling **generic**. Avoid baking in vendor-specific atavisms; the
  tools should work against any conformant PKCS#11 module. Vendor quirks belong
  behind the existing abstraction points, not in the generic code paths.
- When adding support for a **vendor mechanism**, first make sure the required
  header/source material is **free of licensing restrictions** (redistributable)
  before importing or referencing it.

## Testing

- **Every new feature ships with tests.** Prefer **unit tests** driven by the
  programmable mock (`tests/mock/mock_pkcs11.so`) when feasible. If a unit test
  is impractical, add an **integration test** against SoftHSM2 and/or NSS.
- **Every bug fix ships with a regression test** that fails before the fix and
  passes after it.
- **Maintain or increase code coverage** after any change; do not let a change
  reduce coverage.

## Code style

- Files are edited under Emacs with the **stroustrup** C style, **4-space**
  offset. Emacs collapses two 4-space indent levels into a hard **tab** (tab
  width 8), so existing files mix leading tabs and 4-space alignment — match the
  surrounding file exactly. The mode line
  `/* -*- mode: c; c-file-style:"stroustrup"; -*- */` at the top of a file drives
  this; keep it.
- **Avoid macros** where a function (often `static inline`) will do.
- Give local, file-scope functions **internal linkage** (`static`) so they do not
  pollute the global namespace.
- **Document functions** and add **reasonable comments** for non-obvious code
  sections. Do not over-comment trivial code. The project uses plain block/line
  comments (no Doxygen); match that.
- Every file carries the **license + copyright header**. The **copyright year is
  the year the file was first created** (do not bump it on later edits).

## Documentation & versioning

- Follow **SemVer**. A user-visible change bumps the version (see
  `docs/CONTRIBUTING.md`), including in `README.md`/example snippets.
- Record notable changes in `CHANGELOG.md`, and update the manual
  (`docs/MANUAL.md`) when adding options, env variables, or file formats.
- PRs target the `master` branch.

## Grammars & `MAINTAINER_MODE`

The lexers/parsers (`lib/*.l`, `lib/*.y`) are **committed pre-generated**
(`*_lexer.c/.h`, `*_parser.c/.h`) so the project builds on platforms lacking a
usable `flex`/`bison` (AIX, Solaris). Regeneration only happens in
`MAINTAINER_MODE`. **If you change a grammar, regenerate and commit the
corresponding generated files** so non-maintainer-mode builds stay consistent.
