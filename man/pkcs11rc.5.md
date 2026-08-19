% PKCS11RC(5) | pkcs11-tools

# NAME

pkcs11rc - configuration file for the pkcs11-tools wrapper scripts

# DESCRIPTION

The `.pkcs11rc` file is a POSIX shell script fragment sourced automatically by
each **with_***xxx* wrapper script before executing the requested
**pkcs11-tools** command.  Its primary purpose is to set environment variables
(token PIN, library path, slot index, etc.) so they do not need to be repeated
on every invocation.

# SEARCH ORDER

The wrapper walks the directory tree from the current working directory
(**\$PWD**) up to **\$HOME**, testing each directory level in turn.  The
search **never** goes above **\$HOME**: sourcing a file found outside the
user's home tree would allow another user to inject code into the wrapper
process (e.g. via a world-writable `/tmp/.pkcs11rc`).  When **\$PWD** is not
located under **\$HOME**, no `.pkcs11rc` is sourced at all.

At each directory level the following files are tested in order; the first
match wins and the search stops:

1. `.pkcs11rc.`*vendor* — vendor-specific file (e.g. `.pkcs11rc.softhsm`,
   `.pkcs11rc.nss`).  Only probed when the wrapper exports `$_p11_vendor`.
2. `.pkcs11rc` — generic file shared by all vendors.

Setting the **NORC** environment variable to `1` skips this step entirely.

## Example search (with_softhsm from ~/projects/foo)

    ~/projects/foo/.pkcs11rc.softhsm   (checked first)
    ~/projects/foo/.pkcs11rc
    ~/projects/.pkcs11rc.softhsm
    ~/projects/.pkcs11rc
    ~/.pkcs11rc.softhsm
    ~/.pkcs11rc                        (last chance)

# SYNTAX

The file is sourced as a POSIX shell script inside the wrapper process, so it
may contain any valid POSIX shell constructs: variable assignments, `case`
statements, comments, and function calls.  Only simple variable assignments
are needed in the common case.

Lines beginning with `#` are comments.

## Vendor dispatch

Because the same generic `.pkcs11rc` may serve multiple vendors, the wrapper
exports `$_p11_vendor` (a short identifier such as `softhsm`, `nss`, `luna`,
`aws`, `beid`, `kryoptic`, `nfast`, `utimaco`, `yubico`) before sourcing the
file.  Use a `case` block to dispatch on it:

    case ${_p11_vendor:-} in
        softhsm) SOFTHSM2_CONF=$HOME/.config/softhsm2/softhsm2.conf ;;
        luna)    PKCS11TOKENLABEL=mytoken ;;
        nss)     PKCS11NSSDIR=sql:$HOME/nssdb ;;
    esac

# RECOGNIZED VARIABLES

The following variables are read by the wrapper after the file is sourced.
Setting them in `.pkcs11rc` is equivalent to exporting them in the environment
before invoking the wrapper.

**PKCS11LIB**
:   Full path to the PKCS#11 shared library.  Overrides auto-detection.
    Equivalent to the **-l** option of every command.

**PKCS11SLOT**
:   Slot index (0-based integer).  Used unless **PKCS11TOKENLABEL** is also
    set, in which case the token label takes precedence.  Equivalent to **-s**.

**PKCS11TOKENLABEL**
:   Token label string.  When set, slot selection is by label rather than
    index.  Equivalent to **-t**.

**PKCS11PASSWORD**
:   Token PIN.  Accepts the same syntax as the **-p** command-line option:
    a literal PIN, `:::exec:`*command* to fetch the PIN from a subprocess, or
    `:::nologin` to skip **C_Login()**.

**PKCS11NSSDIR**
:   NSS database directory.  Required when the library is **libsoftokn3**.
    May be prefixed with `sql:` for SQLite-style databases.  Equivalent
    to **-m**.

**NSS_LIB_PARAMS**
:   Forwarded as-is by **with_nss**; its `configDir=` field is used only as
    a fallback when **PKCS11NSSDIR** is unset or empty.  Mainly relevant
    with recent NSS versions.

Vendor-specific variables recognized by individual wrappers (not interpreted
by the commands themselves):

**SOFTHSM2_CONF**
:   Path to the SoftHSM2 configuration file (`with_softhsm`).

**KRYOPTIC_CONF**
:   Path to the Kryoptic TOML configuration file (`with_kryoptic`).

**CS_PKCS11_R3_CFG** / **CS_PKCS11_R2_CFG**
:   Utimaco configuration files for the R3 and R2 library variants
    (`with_utimaco`).

**YUBIHSM_PKCS11_CONF**
:   Path to the YubiHSM PKCS#11 configuration file (`with_yubico`).

**CKNFAST_LOADSHARING**, **CKNFAST_FAKE_ACCELERATOR_LOGIN**, **CKNFAST_DEBUG**, **CKNFAST_DEBUGDIR**, **CKNFAST_OVERRIDE_SECURITY_ASSURANCES**
:   Entrust nFast/nShield tuning variables (`with_nfast`).

Wrapper-control variables (effective before the command is executed):

**NOSLOT**
:   Set to `1` to unset **PKCS11SLOT** and **PKCS11TOKENLABEL**, triggering
    interactive slot selection.  Equivalent to the **-n** wrapper option.

**NORC**
:   Set to `1` to skip sourcing any `.pkcs11rc` file for the current
    invocation.

**SHIM**
:   Set to a file path or `/dev/stdout`/`/dev/stderr` to interpose
    **libpkcs11shim** and trace every PKCS#11 call.  Equivalent to the
    **-S** *dest* wrapper option.

**HOMEBREW_PREFIX**
:   When set (typically by `eval "$(brew shellenv)"`), the directories
    `$HOMEBREW_PREFIX/lib` and `$HOMEBREW_PREFIX/lib/pkcs11` are added to
    the library search path.

# PRECEDENCE

The precedence order, from lowest to highest, is:

1. Wrapper defaults (hard-coded in each `with_xxx` script, e.g.
   `PKCS11SLOT=1` in `with_nss`).
2. Variables sourced from `.pkcs11rc` or `.pkcs11rc.`*vendor*.
3. Environment variables exported by the caller before invoking the wrapper.
4. Command-line options passed directly to the pkcs11-tools command (**-l**,
   **-s**, **-t**, **-p**, **-m**).

Variables that are set by the caller in the environment when the wrapper is
invoked are *already* in the environment and will therefore not be overwritten
by the `.pkcs11rc` assignment, because a POSIX shell assignment to an
*already-exported* variable has no effect on the exported value from the
parent.

# CREATING AND EDITING

Each wrapper provides two convenience sub-commands:

`with_xxx -c`
:   Create a fully commented `.pkcs11rc` template in the current directory.
    Exits immediately.  Fails if a `.pkcs11rc` already exists.

`with_xxx -e`
:   Open `.pkcs11rc` in `$VISUAL` / `$EDITOR` (falling back to `vi`),
    creating a template first if no `.pkcs11rc` is found walking up from
    the current directory.

# EXAMPLES

Minimal file for SoftHSM2:

    PKCS11TOKENLABEL=my-token
    PKCS11PASSWORD=my-password

Multi-vendor file in `$HOME/.pkcs11rc`:

    case ${_p11_vendor:-} in
        softhsm)
            SOFTHSM2_CONF=$HOME/.config/softhsm2/softhsm2.conf
            PKCS11TOKENLABEL=my-token
            PKCS11PASSWORD=changeit
            ;;
        nss)
            PKCS11NSSDIR=sql:$HOME/.pki/nssdb
            PKCS11SLOT=1
            PKCS11PASSWORD=ch@nge1t
            ;;
        luna)
            PKCS11TOKENLABEL=production-partition
            ;;
    esac

Fetch the PIN from a subprocess:

    PKCS11PASSWORD=:::exec:'vault read -field=value secret/pkcs11/pin'

# FILES

`$PWD/.pkcs11rc.`*vendor*
:   Vendor-specific configuration (highest priority at CWD level).

`$PWD/.pkcs11rc`
:   Generic configuration at CWD level.

`$HOME/.pkcs11rc`
:   User-wide fallback configuration.

# SEE ALSO

**pkcs11-tools**(7), **with_pkcs11_common**(1)

# AUTHOR

Mastercard, and the pkcs11-tools contributors.
