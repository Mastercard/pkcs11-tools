% WITH_PKCS11_COMMON(1) | pkcs11-tools

# NAME

with_pkcs11_common, with_softhsm, with_nss, with_luna, with_nfast, with_utimaco, with_beid, with_aws, with_kryoptic, with_yubico - wrapper scripts for pkcs11-tools commands

# SYNOPSIS

**with_softhsm** \[*options*] *command* \[*args...*]

**with_nss** \[*options*] *command* \[*args...*]

**with_luna** \[*options*] *command* \[*args...*]

**with_nfast** \[*options*] *command* \[*args...*]

**with_utimaco** \[*options*] *command* \[*args...*]

**with_beid** \[*options*] *command* \[*args...*]

**with_aws** \[*options*] *command* \[*args...*]

**with_kryoptic** \[*options*] *command* \[*args...*]

**with_yubico** \[*options*] *command* \[*args...*]

# DESCRIPTION

The **with_***xxx* scripts are thin POSIX shell wrappers that simplify the
use of **pkcs11-tools** commands against specific PKCS#11 libraries.  Each
wrapper:

1. Locates the vendor PKCS#11 library via auto-detection (see **LIBRARY
   AUTO-DETECTION** below).
2. Sources the user configuration file (`.pkcs11rc` or `.pkcs11rc.`*vendor*);
   see **pkcs11rc**(5).
3. Processes a small set of wrapper-specific options (see **OPTIONS**).
4. Sets **PKCS11LIB** and other environment variables.
5. Executes the requested **pkcs11-tools** command with the prepared
   environment.

All wrappers are implemented using a common library script,
**with_pkcs11_common**, which is sourced by each `with_xxx` script and is
not intended to be invoked directly.

The following table summarises the available wrappers:

**with_aws**
:   AWS CloudHSM (`libcloudhsm_pkcs11.so` / `.dylib`).

**with_beid**
:   Belgian national electronic ID card PKCS#11 interface (`libbeidpkcs11.so`
    / `.dylib`).

**with_kryoptic**
:   Kryoptic software token (`libkryoptic_pkcs11.so` / `.dylib`).

**with_luna**
:   Thales (Gemalto) SafeNet Luna HSM (`libCryptoki2_64.so` / `.dylib`).

**with_nfast**
:   Entrust (nCipher) nShield HSM (`libcknfast.so` / `.dylib`).

**with_nss**
:   Mozilla NSS soft token (`libsoftokn3.so` / `.dylib`).  Slot 1 is
    selected by default (slot 0 is the NSS internal slot).

**with_softhsm**
:   OpenDNSSEC SoftHSM v2 (`libsofthsm2.so` — keeps `.so` on all platforms).

**with_utimaco**
:   Utimaco SecurityServer HSM (`libcs_pkcs11_R3.so` preferred;
    `libcs_pkcs11_R2.so` as fallback).

**with_yubico**
:   Yubico YubiHSM 2 (`yubihsm_pkcs11.so` / `.dylib`).

# OPTIONS

Wrapper options are consumed by the wrapper itself and are never forwarded to
the executed command.

**-n**
:   No slot: unset **PKCS11SLOT** and **PKCS11TOKENLABEL**, forcing
    interactive slot selection.  Equivalent to `NOSLOT=1`.

**-s**
:   SHIM mode: interpose **libpkcs11shim** and send trace output to
    `/dev/stderr`.  Equivalent to `SHIM=/dev/stderr`.

**-S** *dest*
:   SHIM mode: interpose **libpkcs11shim** and send trace output to *dest*
    (a file path, `/dev/stdout`, or `/dev/stderr`).  Equivalent to
    `SHIM=`*dest*.

**-c**
:   Create a fully commented `.pkcs11rc` template in the current directory
    and exit immediately.  Fails if a `.pkcs11rc` file already exists.

**-e**
:   Open `.pkcs11rc` in `$VISUAL` / `$EDITOR` (falling back to `vi`).  If
    no `.pkcs11rc` is found walking up from the current directory to
    `$HOME`, a template is created first.

**-h**
:   Print a usage summary and exit.

# ENVIRONMENT

**PKCS11LIB**
:   Override the auto-detected library with an explicit path.  When set,
    library auto-detection is skipped entirely.

**PKCS11SLOT**
:   Slot index to use.  Default is `0` unless **PKCS11TOKENLABEL** is set.
    Overridden by **-t** or **-s** when passed to the command.

**PKCS11TOKENLABEL**
:   Select the slot by token label instead of by index.  When set,
    **PKCS11SLOT** is ignored.

**PKCS11PASSWORD**
:   Token PIN.  Vendor-specific defaults apply (e.g. `changeit` for
    SoftHSM2 and Luna; `0001password` for YubiHSM).  Accepts the same
    extended syntax as the **-p** command-line option: a literal PIN,
    `:::exec:`*command* to fetch the PIN from a subprocess, or
    `:::nologin` to skip **C_Login()**.

**PKCS11NSSDIR**
:   NSS database directory (NSS wrappers only).  Defaults to
    `sql:$HOME/.pki/nssdb`.  May be prefixed with `sql:`.

**NSS_LIB_PARAMS**
:   Forwarded as-is by **with_nss**.  The `configDir=` field is used only
    as a fallback when **PKCS11NSSDIR** is unset or empty; mainly relevant
    with recent NSS versions.

**NOSLOT**
:   Set to `1` to force interactive slot selection (equivalent to **-n**).

**NORC**
:   Set to `1` to skip sourcing any `.pkcs11rc` file.

**SHIM**
:   Set to a destination (file path, `/dev/stdout`, or `/dev/stderr`) to
    interpose **libpkcs11shim**, a separate Mastercard open-source PKCS#11
    shim that traces every PKCS#11 call.  Equivalent to **-S** *dest*.
    **libpkcs11shim** must be installed and reachable in the library search
    path.

**HOMEBREW_PREFIX**
:   When set (typically by `eval "$(brew shellenv)"`), adds
    `$HOMEBREW_PREFIX/lib` and `$HOMEBREW_PREFIX/lib/pkcs11` to the
    library search path.

Vendor-specific environment variables (set in `.pkcs11rc` or the calling
environment):

**SOFTHSM2_CONF**
:   SoftHSM2 configuration file path (`with_softhsm`).

**KRYOPTIC_CONF**
:   Kryoptic TOML configuration file path (`with_kryoptic`).

**CS_PKCS11_R3_CFG** / **CS_PKCS11_R2_CFG**
:   Utimaco SecurityServer configuration files (`with_utimaco`).

**YUBIHSM_PKCS11_CONF**
:   YubiHSM PKCS#11 configuration file path (`with_yubico`).

**CKNFAST_LOADSHARING**
:   Enable load-sharing mode on nShield (`with_nfast`).

**CKNFAST_FAKE_ACCELERATOR_LOGIN**
:   Allow login on the nShield accelerator slot (`with_nfast`).

**CKNFAST_DEBUG** / **CKNFAST_DEBUGDIR**
:   nShield debug level and output directory (`with_nfast`).

**CKNFAST_OVERRIDE_SECURITY_ASSURANCES**
:   Override nShield security assurance checks (`with_nfast`).

# LIBRARY AUTO-DETECTION

Each wrapper knows the filename(s) of its vendor library and a list of
vendor-specific directories to search.  If the library is not found in
those directories, the following common locations are probed in order:

1. `/usr/lib` and `/usr/lib/pkcs11`
2. `/usr/lib64` and `/usr/lib64/pkcs11` (Linux only)
3. `/usr/lib/`*arch*`-linux-gnu` and its `pkcs11` subdirectory (Linux only)
4. `/usr/local/lib` and `/usr/local/lib/pkcs11`
5. `$HOME/.local/lib`
6. `$HOMEBREW_PREFIX/lib` and `$HOMEBREW_PREFIX/lib/pkcs11` (when
   **HOMEBREW_PREFIX** is set)

On macOS the wrappers search for `.dylib` libraries first; SoftHSM2 is
an exception and uses the `.so` extension on all platforms.

Setting **PKCS11LIB** to an explicit path bypasses auto-detection entirely.

For **with_utimaco**, the R3 library (`libcs_pkcs11_R3.so`) is preferred;
the R2 library (`libcs_pkcs11_R2.so`) is used as a fallback.

# SHIM MODE

When **-s**, **-S** *dest*, or `SHIM=`*dest* is used, the wrapper
interposes **libpkcs11shim** between the command and the vendor library.
Every PKCS#11 call is logged to the specified destination before being
forwarded to the vendor library.  This is useful for debugging
interactions with a token.

**libpkcs11shim** is a separate open-source project by Mastercard
(https://github.com/Mastercard/libpkcs11shim); it must be installed
and discoverable through the library search path described above.

# FILES

`.pkcs11rc`, `.pkcs11rc.`*vendor*
:   Configuration files sourced before executing the command.
    See **pkcs11rc**(5) for the full search order, syntax, and
    recognized variables.

# EXIT STATUS

The wrapper itself exits with status **1** on errors (library not found,
unknown option, missing arguments).  Otherwise, the exit status of the
wrapper is the exit status of the executed **pkcs11-tools** command.
See **pkcs11-tools**(7) for the meaning of non-zero exit codes.

# EXAMPLES

List the content of the default SoftHSM2 token:

    with_softhsm p11ls

Select a token interactively (useful to check available slots):

    NOSLOT=1 with_softhsm p11slotinfo

Generate a 2048-bit RSA key pair on a Luna HSM:

    with_luna p11keygen -k rsa -b 2048 -i my-rsa-key sign verify

Wrap a key on an NSS token and write the file:

    with_nss p11wrap -i my-aes-key -w my-rsa-key -o my-aes-key.wrap

Unwrap a key on SoftHSM2:

    with_softhsm p11unwrap -f my-aes-key.wrap

Trace all PKCS#11 calls to a log file:

    with_softhsm -S p11calls.log p11ls

Override the library and use a specific token label:

    PKCS11LIB=/opt/vendor/lib/libpkcs11.so PKCS11TOKENLABEL=mytoken \
        with_softhsm p11ls

Create a `.pkcs11rc` template and customise it:

    with_softhsm -c
    with_softhsm -e

# SEE ALSO

**pkcs11-tools**(7), **pkcs11rc**(5), **pkcs11-wrap**(5),
**p11ls**(1), **p11keygen**(1), **p11wrap**(1), **p11unwrap**(1),
**p11slotinfo**(1)

# AUTHOR

Mastercard, and the pkcs11-tools contributors.
