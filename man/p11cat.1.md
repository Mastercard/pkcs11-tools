% P11CAT(1) | pkcs11-tools

# NAME

p11cat - extract non-sensitive PKCS#11 token object content in PEM format

# SYNOPSIS

**p11cat**
\[**-l** *pkcs11library*]
\[**-m** *nssconfigdir*]
\[**-s** *slotindex* | **-t** *tokenlabel*]
\[**-p** *password* | **:::exec:***command* | **:::nologin**]
\[**-S**]
\[**-x**]
\[**-h**]
\[**-V**]
*FILTER* \[*FILTER* ...]

# DESCRIPTION

**p11cat** extracts the non-sensitive content of one or more PKCS#11 token
objects and writes it to standard output in PEM (base64-encoded DER) format.
The output is suitable for piping into other tools such as **openssl**(1).

The behaviour depends on the object type:

- **Certificates**: the DER-encoded certificate is exported.
- **Public keys**: the SubjectPublicKeyInfo (SPKI) structure is exported.
  With **-x**, RSA public keys are exported in PKCS#1 format, and DH, DSA, and
  EC keys are exported as parameter files.
- **Secret keys and private keys**: the command refuses to execute, because
  these objects contain sensitive material that cannot be extracted in the
  clear.
- **Data objects**: the raw content is exported.

When neither **-s** nor **-t** is given, and no corresponding environment
variable is set, the command enters interactive mode and offers the list of
available slots for selection. See **pkcs11-tools**(7).

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

**-p** *password* | **:::exec:***command* | **:::nologin**
:   Token PIN. May be given literally, or as **:::exec:***command* to have the
    PIN read from the standard output of *command*, or as **:::nologin** to
    skip the login step entirely. Overrides **PKCS11PASSWORD**.

**-S**
:   Login with security officer (SO) privilege instead of user privilege.

**-x**
:   Extended output in OpenSSL native format:
    for RSA public keys, output in PKCS#1 format;
    for DH, DSA, and EC keys, output key parameters.

**-h**
:   Print usage information and exit.

**-V**
:   Print version information and exit.

# ARGUMENTS

*FILTER*
:   One or more object filters (at least one is required). Each filter has the
    form:

        [TYPE/[ATTRIBUTE/]]VALUE

    **TYPE** is one of `cert`, `pubk`, `prvk`, `seck`, `data`.
    When omitted, all object types are considered.

    **ATTRIBUTE** is `id`, `label`, `sn`, or a PKCS#11 attribute name such as
    **CKA_ENCRYPT**. When omitted, `label` is assumed.

    **VALUE** is an ASCII string or a hex string enclosed in curly braces.

# ENVIRONMENT

**PKCS11LIB**
:   Path to the PKCS#11 library. Overridden by **-l**.

**PKCS11NSSDIR**
:   NSS configuration directory. Overridden by **-m**.

**PKCS11SLOT**
:   Slot index. Overridden by **PKCS11TOKENLABEL**, **-t** or **-s**.

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

Export an RSA public key in SPKI (SubjectPublicKeyInfo) format:

    p11cat pubk/rsa-overarching-wrapping-key

Export the same RSA public key in PKCS#1 format:

    p11cat -x pubk/rsa-overarching-wrapping-key

Export a certificate and inspect it with openssl:

    p11cat cert/my-cert | openssl x509 -noout -text

Export EC key parameters:

    p11cat -x pubk/ec-key > ec-params.pem

# SEE ALSO

**pkcs11-tools**(7), **pkcs11rc**(5), **p11ls**(1), **p11more**(1),
**p11od**(1), **openssl**(1)

# AUTHOR

Mastercard, and the pkcs11-tools contributors.
