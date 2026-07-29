% P11IMPORTDATA(1) | pkcs11-tools

# NAME

p11importdata - import an arbitrary data file onto a PKCS#11 token

# SYNOPSIS

**p11importdata**
\[**-l** *pkcs11library*]
\[**-m** *nssconfigdir*]
\[**-s** *slotindex* | **-t** *tokenlabel*]
\[**-p** *pin* | **:::exec:***command* | **:::nologin**]
**-f** *datafile*
**-i** *label*
\[**-n**]
\[**-h**]
\[**-V**]

# DESCRIPTION

**p11importdata** reads the contents of a local file and stores them on a
PKCS#11 token as a **CKO_DATA** object. This allows arbitrary binary or text
files to be stored alongside keys and certificates on the token.

If a data object with the same label already exists on the token, the operation
is aborted unless the toolkit was built with **--enable-duplicates** and the
**-n** flag is given.

When neither **-s** nor **-t** is given, and no corresponding environment
variable is set, the command enters interactive mode and offers the list of
available slots for selection.

# OPTIONS

**-l** *pkcs11library*
:   Path to the PKCS#11 library (shared object or DLL) to use. Mandatory,
    unless the **PKCS11LIB** environment variable is set.

**-m** *nssconfigdir*
:   NSS configuration directory, when the library is an NSS softoken. The
    directory can be prefixed with `sql:` for SQLite-style databases.
    Overrides **PKCS11NSSDIR**.

**-s** *slotindex*
:   Slot index (an integer) of the token to address. Overrides **PKCS11SLOT**.

**-t** *tokenlabel*
:   Label of the token to address. When present, **-s** is ignored. Overrides
    **PKCS11TOKENLABEL**.

**-p** *pin* | **:::exec:***command* | **:::nologin**
:   Token PIN. If the value begins with `:::exec:`, the remainder is executed
    as a shell command and its standard output is used as the PIN. The special
    value `:::nologin` skips login entirely. Overrides **PKCS11PASSWORD**.

**-f** *datafile*
:   Path to the file whose contents are to be imported. Mandatory.

**-i** *label*
:   Label (alias) to assign to the imported data object. Mandatory.

**-n**
:   Allow importing even if a data object with the same label already exists
    (creates a duplicate object). Only available when the toolkit is built
    with **--enable-duplicates**.

**-h**
:   Print usage information and exit.

**-V**
:   Print version information and exit.

# ENVIRONMENT

**PKCS11LIB**
:   Path to the PKCS#11 library. Overridden by **-l**.

**PKCS11NSSDIR**
:   NSS configuration directory. Overridden by **-m**.

**PKCS11SLOT**
:   Slot index. Overridden by **PKCS11TOKENLABEL**, **-t**, or **-s**.

**PKCS11TOKENLABEL**
:   Token label. Overridden by **-t** or **-s**.

**PKCS11PASSWORD**
:   Token PIN. Overridden by **-p**.

A complete description of the environment variables shared by all commands of
the toolkit is given in **pkcs11-tools**(7).

# EXIT STATUS

**0**
:   Success.

Any non-zero value indicates an error; see **pkcs11-tools**(7) for the meaning
of the exit codes.

# EXAMPLES

Import a text file onto the token:

    p11importdata -l /usr/lib/softhsm/libsofthsm2.so -t "my token" \
        -p changeit \
        -f hello.txt \
        -i dummy_data

Import a binary configuration blob:

    p11importdata -l /usr/lib/softhsm/libsofthsm2.so -s 0 \
        -p changeit \
        -f config.bin \
        -i app-config

Retrieve the PIN via a helper command:

    p11importdata -l /usr/lib/softhsm/libsofthsm2.so -t "my token" \
        -p ':::exec:getpin --label my-token' \
        -f policy.json \
        -i security-policy

# SEE ALSO

**pkcs11-tools**(7), **pkcs11rc**(5), **p11ls**(1), **p11importcert**(1),
**p11importpubk**(1), **p11slotinfo**(1)

# AUTHOR

Mastercard, and the pkcs11-tools contributors.
