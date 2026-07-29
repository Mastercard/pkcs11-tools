% P11LS(1) | pkcs11-tools

# NAME

p11ls - list objects on a PKCS#11 token

# SYNOPSIS

**p11ls**
\[**-l** *pkcs11library*]
\[**-m** *nssconfigdir*]
\[**-s** *slotindex* | **-t** *tokenlabel*]
\[**-p** *password* | **:::exec:***command* | **:::nologin**]
\[**-S**]
\[**-h**]
\[**-V**]
\[*FILTER* ...]

# DESCRIPTION

**p11ls** connects to a PKCS#11 library and lists all token objects (or those
matching the given filters), grouped by type: certificates, public keys,
private keys, secret keys, and data objects. For each object its label (or,
when the label is absent, its **CKA_ID** value in curly brackets) is printed
together with a compact set of attribute abbreviations and the key algorithm
and parameter size.

Attribute abbreviations printed in **upper case** draw attention to conditions
that may have security or operational impact.

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
    skip the login step entirely (useful for accessing public objects without
    a PIN). Overrides **PKCS11PASSWORD**.

**-S**
:   Login with security officer (SO) privilege instead of user privilege.

**-h**
:   Print usage information and exit.

**-V**
:   Print version information and exit.

# ARGUMENTS

*FILTER*
:   Zero or more object filters. Each filter has the form:

        TYPE
        [TYPE/[ATTRIBUTE/]]VALUE[+ADDITIONAL_ATTRIBUTE/ADDITIONAL_VALUE]

    **TYPE** is one of `cert`, `pubk`, `prvk`, `seck`, `data`.
    When omitted, all object types are listed.

    **ATTRIBUTE** is `id`, `label`, `sn`, or a PKCS#11 attribute name such as
    **CKA_ENCRYPT**. When omitted, `label` is assumed.

    **VALUE** is an ASCII string or a hex string enclosed in curly braces,
    e.g. `{deadbeef}`.

    An additional attribute filter can be appended with `+`, for example:
    `cert/sn/12335344+CKA_ENCRYPT/{01}`.

    When no filter is given, all objects are listed.

# ATTRIBUTE ABBREVIATIONS

The following abbreviations appear after each object's label:

**AAU**
:   The key requires authentication each time it is used.

**NAS**
:   (Historical) The key has not always been sensitive.

**NSE**
:   The key is not sensitive; the clear-text value could leave the token
    boundary.

**WXT**
:   (Historical) The key has been at least once extractable.

**XTR**
:   The key is extractable (it can be wrapped or exported in the clear).

**alm**
:   The key is restricted to specific algorithm(s) (see `p11od` for details).

**ase**
:   (Historical) The key has always been sensitive.

**dcp**
:   Supports decapsulation (KEM private key).

**dct**
:   Has a decapsulate template (see `p11od` to reveal).

**dec**
:   Supports decryption.

**drv**
:   Supports key derivation.

**drt**
:   Has a derive template (see `p11od` to reveal).

**enc**
:   Supports encryption.

**imp**
:   The object was imported (e.g. unwrapped).

**loc**
:   The object was created locally on the token.

**ncp**
:   Supports encapsulation (KEM public key).

**nct**
:   Has an encapsulate template (see `p11od` to reveal).

**nxt**
:   (Historical) The key has never been extractable.

**r/o**
:   Not modifiable.

**r/w**
:   Modifiable.

**sen**
:   The key is sensitive; the clear-text value never leaves the token.

**ses**
:   Session object (transient).

**sig**
:   Supports signature or MAC generation.

**sir**
:   Supports signature with recovery (private key).

**tok**
:   Token object (persistent).

**tru**
:   The object is trusted (**CKA_TRUSTED** is set).

**uwr**
:   Supports key unwrapping.

**uwt**
:   Has an unwrap template (see `p11od` to reveal).

**vfy**
:   Supports signature or MAC verification.

**vre**
:   Supports signature verification with recovery (public key).

**wra**
:   Supports key wrapping.

**wrt**
:   Has a wrap template (see `p11od` to reveal).

**wtt**
:   The key may be wrapped with a trusted key only.

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

List all objects on the token in slot 0:

    p11ls -l /usr/lib/softhsm/libsofthsm2.so -s 0

List all secret keys:

    p11ls seck/

List certificates whose label matches `my-cert`:

    p11ls cert/my-cert

List objects filtered by serial number and an additional attribute:

    p11ls cert/sn/12335344+CKA_ENCRYPT/{01}

# SEE ALSO

**pkcs11-tools**(7), **pkcs11rc**(5), **p11slotinfo**(1), **p11cat**(1),
**p11more**(1), **p11od**(1), **p11rm**(1)

# AUTHOR

Mastercard, and the pkcs11-tools contributors.
