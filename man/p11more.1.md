% P11MORE(1) | pkcs11-tools

# NAME

p11more - display PKCS#11 token object content in human-readable format

# SYNOPSIS

**p11more**
\[**-l** *pkcs11library*]
\[**-m** *nssconfigdir*]
\[**-s** *slotindex* | **-t** *tokenlabel*]
\[**-p** *password* | **:::exec:***command* | **:::nologin**]
\[**-S**]
\[**-h**]
\[**-V**]
*FILTER* \[*FILTER* ...]

# DESCRIPTION

**p11more** extracts the non-sensitive content of one or more PKCS#11 token
objects and displays it in human-readable form, as if the PEM output of
**p11cat**(1) had been piped through the appropriate **openssl**(1) decoding
command.

The behaviour by object type is the same as for **p11cat**(1):

- **Certificates**: the certificate is decoded and printed (equivalent to
  `openssl x509 -text`).
- **Public keys**: the public key is decoded and printed.
- **Secret keys and private keys**: the command refuses to execute.
- **Data objects**: the raw content is displayed.

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

Display a self-signed certificate in human-readable form:

    p11more cert/a-self-signed

Display a public key's details:

    p11more pubk/rsa-2048

Display a certificate addressed by its CKA_ID hex value:

    p11more cert/id/{3938363139363833}

# SEE ALSO

**pkcs11-tools**(7), **pkcs11rc**(5), **p11cat**(1), **p11ls**(1),
**p11od**(1), **openssl**(1)

# AUTHOR

Mastercard, and the pkcs11-tools contributors.
