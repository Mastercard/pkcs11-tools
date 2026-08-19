% P11SETATTR(1) | pkcs11-tools

# NAME

p11setattr - change attributes of a PKCS#11 token object

# SYNOPSIS

**p11setattr**
\[**-l** *pkcs11library*]
\[**-m** *nssconfigdir*]
\[**-s** *slotindex* | **-t** *tokenlabel*]
\[**-p** *password* | **:::exec:***command* | **:::nologin**]
\[**-S**]
\[**-y**]
\[**-h**]
\[**-V**]
*TARGET* *ATTRIBUTE*=*VALUE* \[*ATTRIBUTE*=*VALUE* ...]

# DESCRIPTION

**p11setattr** modifies one or more attributes of a PKCS#11 token object
matched by *TARGET*. Each subsequent argument specifies an attribute name and
value pair.

Attribute names are case-insensitive; the `CKA_` prefix may be omitted for
convenience. For example, `CKA_LABEL`, `cka_label`, and `label` are all
accepted.

Boolean attributes accept the values `true`, `false`, `yes`, `no`, `CK_TRUE`,
or `CK_FALSE`. The value may be omitted for a boolean attribute, in which case
it defaults to `true`. A boolean attribute may also be negated by prefixing
its name with `no`, e.g. `noextractable`.

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

**-y**
:   Force positive answer to all confirmation prompts (non-interactive mode).

**-h**
:   Print usage information and exit.

**-V**
:   Print version information and exit.

# ARGUMENTS

*TARGET*
:   Object filter identifying the target object(s). The form is:

        [TYPE/[ATTRIBUTE/]]VALUE

    **TYPE** is one of `cert`, `pubk`, `prvk`, `seck`, `data`.
    When omitted, all object types are considered.

    **ATTRIBUTE** is `id`, `label`, `sn`, or a PKCS#11 attribute name.
    When omitted, `label` is assumed.

    **VALUE** is an ASCII string or a hex string enclosed in curly braces.

*ATTRIBUTE*=*VALUE*
:   One or more attribute assignments. Supported attributes are:

    **CKA_LABEL**, **CKA_ID**, **CKA_WRAP**, **CKA_UNWRAP**,
    **CKA_DECRYPT**, **CKA_ENCRYPT**, **CKA_ENCAPSULATE**,
    **CKA_DECAPSULATE**, **CKA_SIGN**, **CKA_VERIFY**,
    **CKA_SIGN_RECOVER**, **CKA_VERIFY_RECOVER**, **CKA_TRUSTED**,
    **CKA_MODIFIABLE**, **CKA_EXTRACTABLE**, **CKA_SENSITIVE**,
    **CKA_WRAP_WITH_TRUSTED**.

    Supported value formats: `true` / `false`, ASCII strings, hex strings in
    curly braces (e.g. `{deadbeef}`).

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

Mark a secret key as no longer extractable (after a key transport procedure):

    p11setattr seck/aes-wrapping-key CKA_EXTRACTABLE=false

Rename a certificate object:

    p11setattr cert/old-name CKA_LABEL=new-name

Enable encryption and decryption on an AES key:

    p11setattr seck/aes-key CKA_ENCRYPT=true CKA_DECRYPT=true

Mark a public key as trusted (requires SO login):

    p11setattr -S pubk/ca-root CKA_TRUSTED=true

# SEE ALSO

**pkcs11-tools**(7), **pkcs11rc**(5), **p11ls**(1), **p11od**(1),
**p11mv**(1), **p11rm**(1)

# AUTHOR

Mastercard, and the pkcs11-tools contributors.
