% P11IMPORTPUBK(1) | pkcs11-tools

# NAME

p11importpubk - import a public key onto a PKCS#11 token

# SYNOPSIS

**p11importpubk**
\[**-l** *pkcs11library*]
\[**-m** *nssconfigdir*]
\[**-s** *slotindex* | **-t** *tokenlabel*]
\[**-p** *pin* | **:::exec:***command* | **:::nologin**]
\[**-S**]
**-f** *pubkeyfile*
**-i** *label*
\[**-T**]
\[**-n**]
\[**-h**]
\[**-V**]
\[*ATTRIBUTE*=*VALUE* ...]

# DESCRIPTION

**p11importpubk** loads a PEM or DER formatted public key from a local file and
imports it onto a PKCS#11 token. The **CKA_ID** attribute is computed according
to IBM PKCS#11 JCE rules (SHA-1 of the public key modulus for RSA keys;
consult the source for other key types), to match a corresponding private key
object.

If no *ATTRIBUTE=VALUE* arguments are given, sensible defaults are applied
depending on the key type:

- RSA, DSA, DH keys: all usage attributes set to `true`.
- EC keys: **CKA_DERIVE=false**, **CKA_VERIFY=true**, **CKA_MODIFIABLE=true**.

When *ATTRIBUTE=VALUE* pairs are specified, they replace the defaults entirely.
Use **-T** to additionally set **CKA_TRUSTED=true** (SO privilege is usually
required).

If a public key with the same label already exists on the token, the operation
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

**-S**
:   Login with Security Officer (SO) privilege instead of user privilege.
    Required when setting the trusted attribute (**-T**) on some tokens.

**-f** *pubkeyfile*
:   Path to the public key file in PEM or DER format. Mandatory.

**-i** *label*
:   Label (alias) to assign to the imported public key object. Mandatory.

**-T**
:   Set **CKA_TRUSTED=true** on the imported public key object. Requires SO
    privilege on most tokens (**-S**).

**-n**
:   Allow importing even if a public key with the same label already exists
    (creates a duplicate object). Only available when the toolkit is built
    with **--enable-duplicates**.

**-h**
:   Print usage information and exit.

**-V**
:   Print version information and exit.

# ARGUMENTS

Zero or more *ATTRIBUTE=VALUE* pairs may be given as positional arguments after
all options. They override the default attributes applied to the imported public
key. Supported attributes:

**CKA_LABEL**, **CKA_ID**
:   String or hex identifier.

**CKA_WRAP**
:   Boolean. Allow the public key to be used for key wrapping.

**CKA_ENCRYPT**
:   Boolean. Allow encryption.

**CKA_VERIFY**, **CKA_VERIFY_RECOVER**
:   Boolean. Allow signature verification.

**CKA_DERIVE**
:   Boolean. Allow key derivation.

**CKA_TRUSTED**, **CKA_MODIFIABLE**
:   Boolean.

**CKA_EXTRACTABLE**, **CKA_SENSITIVE**
:   Boolean.

**CKA_WRAP_WITH_TRUSTED**
:   Boolean.

**CKA_WRAP_TEMPLATE**
:   Attribute template, e.g. `{ not encrypt }`.

See **p11keygen**(1) for the full attribute value syntax.

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

Import an RSA public key with default attributes:

    p11importpubk -l /usr/lib/softhsm/libsofthsm2.so -t "my token" \
        -p changeit \
        -f test-public-rsa-key.rsa \
        -i test-public-rsa-key

Import a public key enabled for wrapping, with a wrap template that restricts
wrapping to keys without the encrypt attribute:

    p11importpubk -l /usr/lib/softhsm/libsofthsm2.so -t "my token" \
        -p changeit \
        -f test-public-rsa-key.rsa \
        -i test-public-rsa-key \
        'wrap=1' 'wrap_template={ not encrypt }'

Import a trusted public key (requires SO login):

    p11importpubk -l /usr/lib/softhsm/libsofthsm2.so -t "my token" \
        -S -p sopin \
        -f trusted-key.pem \
        -i trusted-rsa-key -T

# SEE ALSO

**pkcs11-tools**(7), **pkcs11rc**(5), **p11importcert**(1), **p11keygen**(1),
**p11ls**(1), **p11slotinfo**(1)

# AUTHOR

Mastercard, and the pkcs11-tools contributors.
