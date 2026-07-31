% P11OD(1) | pkcs11-tools

# NAME

p11od - dump PKCS#11 token object attributes in octal-dump style

# SYNOPSIS

**p11od**
\[**-l** *pkcs11library*]
\[**-m** *nssconfigdir*]
\[**-s** *slotindex* | **-t** *tokenlabel*]
\[**-p** *password* | **:::exec:***command* | **:::nologin**]
\[**-S**]
\[**-h**]
\[**-V**]
\[*FILTER* ...]

# DESCRIPTION

**p11od** (Object Dumper) connects to a PKCS#11 library and prints, for each
matching object, the raw value of every attribute retrieved from the token.
Each attribute is shown as a labelled hex dump, with a symbolic interpretation
where available (e.g. **CKO_SECRET_KEY**, **CKK_AES**, **CK_TRUE**).

Template attributes (such as **CKA_WRAP_TEMPLATE** or **CKA_UNWRAP_TEMPLATE**)
are recursively decoded and displayed indented under the parent attribute, to
distinguish them from the top-level attributes of the object.

**p11od** is the recommended tool when **p11ls**(1) shows an abbreviation such
as **alm**, **wrt**, **uwt**, **drt**, **nct**, or **dct** and you need to
inspect the full content of the corresponding template or allowed-mechanism
list.

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
:   Zero or more object filters. Each filter has the form:

        [TYPE/[ATTRIBUTE/]]VALUE

    **TYPE** is one of `cert`, `pubk`, `prvk`, `seck`, `data`.
    When omitted, all object types are considered.

    **ATTRIBUTE** is `id`, `label`, `sn`, or a PKCS#11 attribute name such as
    **CKA_ENCRYPT**. When omitted, `label` is assumed.

    **VALUE** is an ASCII string or a hex string enclosed in curly braces.

    When no filter is given, all objects are dumped.

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

Dump all attributes of a secret key named `aes-wrapping-key`:

    p11od seck/aes-wrapping-key

Dump all attributes of all objects on the token (verbose, use with care):

    p11od

Dump attributes of a certificate addressed by CKA_ID:

    p11od cert/id/{3938363139363833}

Inspect the wrap template of a wrapping key:

    p11od pubk/rsa-overarching-wrapping-key

# SEE ALSO

**pkcs11-tools**(7), **pkcs11rc**(5), **p11ls**(1), **p11cat**(1),
**p11setattr**(1)

# AUTHOR

Mastercard, and the pkcs11-tools contributors.
