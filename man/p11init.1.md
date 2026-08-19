% P11INIT(1) | pkcs11-tools

# NAME

p11init - initialize a PKCS#11 token and/or its user PIN

# SYNOPSIS

**p11init**
\[**-l** *pkcs11library*]
\[**-m** *nssconfigdir*]
\[**-s** *slotindex* | **-t** *tokenlabel*]
\[**-I**]
\[**-R**]
\[**-U**]
\[**-O** *sopin* | **:::exec:***command*]
\[**-P** *userpin* | **:::exec:***command*]
\[**-T** *tokenlabel*]
\[**-B**]
\[**-h**]
\[**-V**]

# DESCRIPTION

**p11init** initializes a PKCS#11 token and/or its user (crypto officer) PIN.
It maps directly to the PKCS#11 **C_InitToken** and **C_InitPIN** functions.
One or more operations must be requested via **-I** and/or **-U**.

Unlike the other commands in the toolkit, **p11init** intentionally ignores the
**PKCS11SLOT**, **PKCS11TOKENLABEL**, and **PKCS11PASSWORD** environment
variables. Because its operations are destructive, the target token must always
be specified explicitly on the command line (**-s** or **-t**), or selected
from the interactive slot list, and the PINs must always be passed as
arguments or entered at the prompt — there are no hidden defaults coming from
the environment.

When running interactively (the default, i.e. without **-B**), any value not
supplied on the command line is prompted for. When neither **-s** nor **-t** is
given, **p11init** prints the full slot list and prompts for a slot index —
exactly as **p11slotinfo**(1) does. The SO PIN and user PIN are read with echo
turned off, requiring a terminal. Any PIN that is being **defined**
interactively (the SO PIN when initializing a token, and the new user PIN) is
asked **twice** and the two entries must match; a mismatch aborts the command
without performing any action.

In batch mode (**-B**), nothing is prompted: every required value must be
supplied on the command line and the command fails safely if anything is
missing or inconsistent.

Operations:

**-I** (token initialization)
:   Calls **C_InitToken** on the chosen slot. The slot must hold an
    **uninitialized** token, unless **-R** is given to authorize resetting an
    already initialized one. Needs a token label (**-T**) and the SO PIN
    (**-O**). Cannot be combined with **-t** (a token must be addressed by
    slot index for initialization).

**-U** (user PIN initialization or change)
:   Calls **C_InitPIN** using the SO PIN (**-O**) to authenticate, then sets
    the user (crypto officer) PIN to the value given with **-P**. A standalone
    **-U** (without **-I**) asks for an explicit `(y/N)` confirmation in
    interactive mode. Can be addressed by token label (**-t**) when the token
    is already initialized.

**-I -U** (combined)
:   Both operations in sequence: the token is initialized first, then the user
    PIN is set on the freshly created token.

**-I -R** (reset / reinitialize)
:   Calls **C_InitToken** on an already initialized token, erasing all its
    content. The SO PIN passed with **-O** must match the token's current SO
    PIN.

The `:::exec:`*command* convention is supported for **-O** and **-P**: the
command's standard output is used as the PIN. The `:::nologin` convention is
**not** supported.

# OPTIONS

**-l** *pkcs11library*
:   Path to the PKCS#11 library (shared object or DLL) to use. Mandatory,
    unless the **PKCS11LIB** environment variable is set.

**-m** *nssconfigdir*
:   NSS configuration directory, when the library is an NSS softoken. The
    directory can be prefixed with `sql:` for SQLite-style databases.
    Overrides **PKCS11NSSDIR**.

**-s** *slotindex*
:   Slot index (a non-negative integer) of the token to address. For **-I**,
    the slot must be selected before initialization. In batch mode, mandatory
    for **-I** and for **-U** unless **-t** is used.

**-t** *tokenlabel*
:   Token label to address. Allowed only with **-U** alone, to address an
    already initialized token. Cannot be used with **-I**.

**-I**
:   Initialize a token (**C_InitToken**). The slot must hold an uninitialized
    token, unless **-R** is also given.

**-R**
:   Authorize reinitialization (reset) of an already initialized token.
    Destructive — all token content is erased. Must be combined with **-I**.
    In interactive mode a warning and `(y/N)` confirmation are displayed.

**-U**
:   Initialize or change the user (crypto officer) PIN (**C_InitPIN**). Uses
    the SO PIN (**-O**) for authentication and sets the user PIN to **-P**.

**-O** *sopin* | **:::exec:***command*
:   Security Officer PIN. If the value begins with `:::exec:`, the remainder
    is executed as a shell command and its standard output is used. Mandatory
    in batch mode; prompted for (with confirmation when defining it) in
    interactive mode.

**-P** *userpin* | **:::exec:***command*
:   New user (crypto officer) PIN. Used by **-U**. If the value begins with
    `:::exec:`, the remainder is executed as a shell command. Mandatory in
    batch mode when **-U** is requested; prompted for (with confirmation) in
    interactive mode.

**-T** *tokenlabel*
:   Token label to set when initializing a token with **-I**. Mandatory in
    batch mode; prompted for in interactive mode.

**-B**
:   Batch mode: never prompt. All required values must be passed as arguments.
    The command fails safely if anything is missing or inconsistent.

**-h**
:   Print usage information and exit.

**-V**
:   Print version information and exit.

# ENVIRONMENT

**PKCS11LIB**
:   Path to the PKCS#11 library. Overridden by **-l**.

**PKCS11NSSDIR**
:   NSS configuration directory. Overridden by **-m**.

**PKCS11SLOT**, **PKCS11TOKENLABEL**, **PKCS11PASSWORD**
:   These variables are intentionally **ignored** by **p11init**. The target
    slot and all PINs must be provided explicitly on the command line or at
    the interactive prompt.

# EXIT STATUS

**0**
:   Success.

Any non-zero value indicates an error; see **pkcs11-tools**(7) for the meaning
of the exit codes.

# EXAMPLES

Initialize a blank token at slot index 0, setting its label and SO PIN in
batch mode:

    p11init -l /path/to/libpkcs11.so -I -B -s 0 \
        -O 12345678 -T "my token"

Set the user (crypto officer) PIN of an already initialized token, addressed
by label:

    p11init -l /path/to/libpkcs11.so -U -t "my token" \
        -O 12345678 -P 87654321

Initialize a token and set its user PIN in a single invocation:

    p11init -l /path/to/libpkcs11.so -I -U -B -s 0 \
        -O 12345678 -P 87654321 -T "my token"

Reset (erase and reinitialize) an already initialized token in batch mode:

    p11init -l /path/to/libpkcs11.so -I -R -B -s 0 \
        -O 12345678 -T "my token"

Fetch the SO PIN from a subprocess:

    p11init -l /path/to/libpkcs11.so -U -t "my token" \
        -O ':::exec:getsopin -label my-token' -P 87654321

Initialize a token interactively (slot list shown, then slot, label and SO
PIN are prompted for):

    p11init -l /path/to/libpkcs11.so -I

# SEE ALSO

**pkcs11-tools**(7), **pkcs11rc**(5), **p11slotinfo**(1), **p11ls**(1)

# AUTHOR

Mastercard, and the pkcs11-tools contributors.
