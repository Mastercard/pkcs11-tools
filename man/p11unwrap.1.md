% P11UNWRAP(1) | pkcs11-tools

# NAME

p11unwrap - unwrap a key onto a PKCS#11 token from a wrapped key file

# SYNOPSIS

**p11unwrap**
\[**-l** *pkcs11library*]
\[**-m** *nssconfigdir*]
\[**-s** *slotindex* | **-t** *tokenlabel*]
\[**-p** *pin* | **:::exec:***command* | **:::nologin**]
**-f** *file*
\[**-i** *key_alias*]
\[**-w** *wrapping_key_alias*]
\[**-S**]
\[**-h**]
\[**-V**]
\[*ATTRIBUTE***=***value* ...]

# DESCRIPTION

**p11unwrap** reads a wrapped key file (in **pkcs11-wrap**(5) format) produced
by **p11wrap**(1) or **p11keygen**(1) and imports the key onto the PKCS#11
token by unwrapping it.  The wrapping key referenced in the file must already
exist on the token and must have **CKA_UNWRAP** set to **true**.

PKCS#11 attribute overrides can be supplied as positional **ATTRIBUTE=value**
arguments after all options.  These values take precedence over the
corresponding attributes embedded in the wrapped key file, allowing the caller
to control e.g. **CKA_EXTRACTABLE** or usage flags at import time.

When neither **-s** nor **-t** is given, and no corresponding environment
variable is set, the command enters interactive mode and offers the list of
available slots for selection.  See **pkcs11-tools**(7).

# OPTIONS

**-l** *pkcs11library*
:   Path to the PKCS#11 library (shared object or DLL) to use.  Mandatory,
    unless the **PKCS11LIB** environment variable is set.

**-m** *nssconfigdir*
:   NSS configuration directory, when the library is an NSS softoken.  The
    directory can be prefixed with `sql:` for SQLite-style databases.
    Overrides **PKCS11NSSDIR**.

**-s** *slotindex*
:   Slot index (an integer) of the token to address.  Overrides **PKCS11SLOT**.

**-t** *tokenlabel*
:   Label of the token to address.  When present, **-s** is ignored.  Overrides
    **PKCS11TOKENLABEL**.

**-p** *pin* | **:::exec:***command* | **:::nologin**
:   Token PIN, or one of the special forms:

    **:::exec:***command*
    :   Execute *command* and use its standard output as the PIN.

    **:::nologin**
    :   Skip login entirely (useful for tokens that do not require a PIN for
        the intended operation).

    Overrides **PKCS11PASSWORD**.

**-f** *file*
:   Path to the wrapped key file to import.  Mandatory.

**-i** *key_alias*
:   Override the label of the unwrapped key object on the token.  When not
    specified, the label from the wrapped key file is used.

**-w** *wrapping_key_alias*
:   Override the wrapping key label.  When present, this takes precedence over
    the wrapping key reference embedded in the wrapped key file.  The named key
    must have **CKA_UNWRAP** set to **true**.

**-S**
:   Login with Security Officer (SO) privilege instead of user privilege.

**-h**
:   Print usage information and exit.

**-V**
:   Print version information and exit.

**-n**
:   Allow the creation of a duplicate object (an object with the same
    **CKA_LABEL** or **CKA_ID** as an existing one).  Only available when the
    toolkit is built with duplicate-object support
    (**HAVE_DUPLICATES_ENABLED**).

# ARGUMENTS

Zero or more **ATTRIBUTE=value** pairs may be given after all options.  They
are applied to the unwrapped private or secret key object, overriding the
corresponding attributes from the wrapped key file.

Supported attributes:

**CKA_LABEL**
:   Object label (ASCII string).

**CKA_ID**
:   Object identifier.

**CKA_WRAP**
:   Allow the key to wrap other keys (**true** or **false**).

**CKA_UNWRAP**
:   Allow the key to unwrap other keys (**true** or **false**).

**CKA_ENCRYPT**
:   Allow encryption (**true** or **false**).

**CKA_DECRYPT**
:   Allow decryption (**true** or **false**).

**CKA_ENCAPSULATE**
:   Allow encapsulation (**true** or **false**).

**CKA_DECAPSULATE**
:   Allow decapsulation (**true** or **false**).

**CKA_SIGN**
:   Allow signing (**true** or **false**).

**CKA_VERIFY**
:   Allow verification (**true** or **false**).

**CKA_SIGN_RECOVER**
:   Allow sign-with-recovery (**true** or **false**).

**CKA_VERIFY_RECOVER**
:   Allow verify-with-recovery (**true** or **false**).

**CKA_DERIVE**
:   Allow key derivation (**true** or **false**).

**CKA_TRUSTED**
:   Mark the key as trusted (**true** or **false**).

**CKA_MODIFIABLE**
:   Allow the object to be modified after creation (**true** or **false**).

**CKA_EXTRACTABLE**
:   Allow the key to be extracted (wrapped) from the token (**true** or
    **false**).

**CKA_SENSITIVE**
:   Mark the key as sensitive (**true** or **false**).

**CKA_WRAP_WITH_TRUSTED**
:   Require that the key may only be wrapped with a trusted wrapping key
    (**true** or **false**).

**CKA_UNWRAP_TEMPLATE**
:   Unwrap template: a set of `{ attribute=value ... }` pairs that are
    applied to any key unwrapped by this key.

Supported values are **true**, **false**, an ASCII string, a date, or a
brace-enclosed template `{ ... }`.

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

Unwrap a key from a file, using the wrapping key label stored inside the
wrapped key file:

    p11unwrap -l /usr/lib/softhsm/libsofthsm2.so -s 0 \
        -f aes-wrapping-key.wrap

Unwrap and override the key label and explicitly mark the result as
non-extractable:

    p11unwrap -l /usr/lib/softhsm/libsofthsm2.so -t "dest token" \
        -f business-key-for-dest-token.wrap \
        CKA_LABEL=business-key CKA_EXTRACTABLE=false

Unwrap using an explicit unwrapping key (overriding the one in the file):

    p11unwrap -l /usr/lib/softhsm/libsofthsm2.so -s 1 \
        -f aes-wrapping-key.wrap \
        -w rsa-wrapping-key

Unwrap an AES key and grant it wrap and unwrap capabilities:

    p11unwrap -l /usr/lib/softhsm/libsofthsm2.so -s 0 \
        -f aes-wrapping-key.wrap \
        CKA_WRAP=true CKA_UNWRAP=true CKA_EXTRACTABLE=false

# SEE ALSO

**pkcs11-tools**(7), **pkcs11-wrap**(5), **p11wrap**(1), **p11rewrap**(1),
**p11keygen**(1), **p11slotinfo**(1)

# AUTHOR

Mastercard, and the pkcs11-tools contributors.
