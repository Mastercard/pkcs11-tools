% P11IMPORTCERT(1) | pkcs11-tools

# NAME

p11importcert - import an X.509 certificate onto a PKCS#11 token

# SYNOPSIS

**p11importcert**
\[**-l** *pkcs11library*]
\[**-m** *nssconfigdir*]
\[**-s** *slotindex* | **-t** *tokenlabel*]
\[**-p** *pin* | **:::exec:***command* | **:::nologin**]
\[**-S**]
**-f** *certfile*
**-i** *label*
\[**-T**]
\[**-n**]
\[**-h**]
\[**-V**]

# DESCRIPTION

**p11importcert** loads a PEM or DER formatted X.509 certificate from a local
file and imports it onto a PKCS#11 token. The **CKA_ID** attribute of the
imported certificate object is computed according to IBM PKCS#11 JCE rules
(SHA-1 of the public key modulus for RSA keys; consult the source for other
key types), so that it matches a previously imported or generated key pair.

If a certificate with the same label already exists on the token, the operation
is aborted unless the toolkit was built with **--enable-duplicate** and the
**-n** flag is given.

The trust bit (**CKA_TRUST**) can optionally be set using **-T**; this
typically requires SO privilege (**-S**).

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
    Required when setting the trust bit (**-T**) on some tokens.

**-f** *certfile*
:   Path to the certificate file in PEM or DER format. Mandatory.

**-i** *label*
:   Label (alias) to assign to the imported certificate object. Mandatory.

**-T**
:   Set **CKA_TRUST=true** on the imported certificate object. May require
    **-S**.

**-n**
:   Allow importing even if a certificate with the same label already exists
    on the token (creates a duplicate object). Only available when the toolkit
    is built with **--enable-duplicates**.

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

Import a PEM certificate and label it `test-rsa-2048`:

    p11importcert -l /usr/lib/softhsm/libsofthsm2.so -t "my token" \
        -p changeit \
        -f test.crt \
        -i test-rsa-2048

Import a DER certificate and set the trust bit (requires SO login):

    p11importcert -l /usr/lib/softhsm/libsofthsm2.so -t "my token" \
        -S -p sopin \
        -f ca.der \
        -i my-ca -T

Import a certificate from a file whose path is given via a PIN-fetching
command:

    p11importcert -l /usr/lib/softhsm/libsofthsm2.so -t "my token" \
        -p ':::exec:getpin --label my-token' \
        -f server.crt \
        -i server

# SEE ALSO

**pkcs11-tools**(7), **pkcs11rc**(5), **p11mkcert**(1), **p11req**(1),
**p11importpubk**(1), **p11ls**(1), **p11slotinfo**(1)

# AUTHOR

Mastercard, and the pkcs11-tools contributors.
