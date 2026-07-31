% P11REWRAP(1) | pkcs11-tools

# NAME

p11rewrap - unwrap a key and re-wrap it under one or more new wrapping key(s), without permanently storing it

# SYNOPSIS

**p11rewrap**
\[**-l** *pkcs11library*]
\[**-m** *nssconfigdir*]
\[**-s** *slotindex* | **-t** *tokenlabel*]
\[**-p** *pin* | **:::exec:***command* | **:::nologin**]
**-f** *file*
\[**-i** *key_alias*]
\[**-w** *wrapping_key_alias*]
**-W** *wrapping_specifier* \[**-W** *wrapping_specifier* ...]
\[**-J** *wrapping_key_id*]
\[**-S**]
\[**-h**]
\[**-V**]
\[*ATTRIBUTE***=***value* ...]

# DESCRIPTION

**p11rewrap** combines **p11unwrap**(1) and **p11wrap**(1) in a single atomic
operation: it reads a **pkcs11-wrap**(5) wrapped key file, unwraps the key into
a *session* (temporary) object — which is never persisted on the token — and
immediately re-wraps it under one or more new wrapping keys, writing the
resulting wrapped key file(s) to disk.

This is the recommended way to transfer a key from one token to another,
because the key is never in a permanent extractable state on either token.  See
the EXAMPLES section for the full key-exchange workflow.

At least one **-W** specifier is mandatory.  **-W** can be repeated up to 32
times to produce multiple output files in a single invocation.

Optional PKCS#11 **ATTRIBUTE=value** positional arguments may be appended after
all options; they are applied to the temporary session key during the unwrap
phase and therefore influence the re-wrapping step (e.g. setting
**CKA_EXTRACTABLE=true** to allow the session key to be re-wrapped).

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
:   Path to the wrapped key file to read.  Mandatory.

**-i** *key_alias*
:   Override the label used for the temporary session key during unwrapping.
    When not specified, the label from the wrapped key file is used.

**-w** *wrapping_key_alias*
:   Override the unwrapping key label.  When present, this takes precedence over
    the wrapping key reference embedded in the wrapped key file.  The named key
    must have **CKA_UNWRAP** set to **true**.

**-W** *wrapping_specifier*
:   Rewrapping specifier; mandatory, and can be repeated.  The argument has
    the form:

        wrappingkey="<label>"[,algorithm=<algorithm>][,filename="<path>"]

    *  `wrappingkey="<label>"` — label of the (new) wrapping key (double
       quotes mandatory).  The key must have **CKA_WRAP** set to **true**.
    *  `algorithm=<algorithm>` — wrapping algorithm (default: **oaep**).
       See the ARGUMENTS section for the full list and parameter syntax.
    *  `filename="<path>"` — output file (double quotes mandatory); if
       omitted, the wrapped key is written to standard output.

    **-W** can be repeated up to 32 times.

**-J** *wrapping_key_id*
:   Output in JOSE JSON Web Key (JWK, RFC 7517) format instead of the
    default **pkcs11-wrap**(5) format.  *wrapping_key_id* is included in the
    JWK as the wrapping key identifier; pass an empty string (`""`) to omit
    it.  Envelope wrapping is not supported with **-J**.

**-S**
:   Login with Security Officer (SO) privilege instead of user privilege.

**-h**
:   Print usage information and exit.

**-V**
:   Print version information and exit.

**-n**
:   Allow the creation of a duplicate object during the temporary unwrap phase.
    Only available when the toolkit is built with duplicate-object support
    (**HAVE_DUPLICATES_ENABLED**).

# ARGUMENTS

The wrapping algorithm specified in each **-W** follows the same syntax as in
**p11wrap**(1):

**pkcs1**
:   PKCS#1 v1.5 (RFC 8017), mechanism **CKM_RSA_PKCS**.  Wrapping key: RSA.
    Wrapped key: symmetric or secret (HMAC).  Considered insecure; avoid when
    possible.

**oaep**\[**(**\[**label="***value***"**]\[**,mgf=***MGF*]\[**,hash=***HASH*]**)**]
:   PKCS#1 OAEP (RFC 8017), mechanism **CKM_RSA_PKCS_OAEP**.  Wrapping key:
    RSA.  Wrapped key: symmetric or secret (HMAC).  Default algorithm.

    Optional parameters (comma-separated):

    **label="***value***"**
    :   OAEP label (source data).  Default: empty.

    **mgf=***MGF*
    :   One of **CKG_MGF1_SHA1** (default), **CKG_MGF1_SHA224**,
        **CKG_MGF1_SHA256**, **CKG_MGF1_SHA384**, **CKG_MGF1_SHA512**.

    **hash=***HASH*
    :   One of **CKM_SHA_1** (default), **CKM_SHA224**, **CKM_SHA256**,
        **CKM_SHA384**, **CKM_SHA512**.

**cbcpad**\[**(**\[**iv=***0xHEX*]**)**]
:   CBC mode with PKCS#7 padding.  Wrapping key: AES or DES.  Wrapped key:
    any type.

    **iv=***0xHEX*
    :   Initialisation vector as a hex string prefixed with `0x`.

**rfc3394**
:   AES Key Wrap (RFC 3394), mechanism **CKM_AES_KEY_WRAP**.  Wrapping key:
    AES.  Wrapped key: any type aligned on 8 bytes.

**rfc5649**\[**(**\[**flavour=***flavour*]**)**]
:   AES Key Wrap with Padding (RFC 5649).  Wrapping key: AES.  Wrapped key:
    any type.  Default mechanism: **CKM_AES_KEY_WRAP_PAD**.

    **flavour=***flavour*
    :   One of **pad** (default), **kwp**, **nss**, **luna**, or a full
        **CKM_*** mechanism name.

**envelope**\[**(**\[**inner=***inner_alg*]\[**,outer=***outer_alg*]**)**]
:   Envelope wrapping (ephemeral AES session key wraps the target; outer RSA
    key wraps the AES key).

    **inner=***inner_alg*
    :   One of **cbcpad** (default), **rfc3394**, **rfc5649**.

    **outer=***outer_alg*
    :   One of **oaep** (default), **pkcs1**.

Positional **ATTRIBUTE=value** arguments (same set as **p11unwrap**(1)) can
follow all options to override attributes on the temporary session key:
**CKA_LABEL**, **CKA_ID**, **CKA_WRAP**, **CKA_UNWRAP**, **CKA_ENCRYPT**,
**CKA_DECRYPT**, **CKA_ENCAPSULATE**, **CKA_DECAPSULATE**, **CKA_SIGN**,
**CKA_VERIFY**, **CKA_SIGN_RECOVER**, **CKA_VERIFY_RECOVER**, **CKA_DERIVE**,
**CKA_TRUSTED**, **CKA_MODIFIABLE**, **CKA_EXTRACTABLE**, **CKA_SENSITIVE**,
**CKA_WRAP_WITH_TRUSTED**.  Accepted values: **true**, **false**, an ASCII
string, a date.

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
:   All rewrapping jobs succeeded.

A non-zero value indicates that one or more jobs failed.  When multiple **-W**
jobs are requested, **p11rewrap** returns the count of failed jobs.  See
**pkcs11-tools**(7) for exit code conventions.

# EXAMPLES

**Accelerated key exchange between two tokens (recommended workflow)**

This workflow transfers a key from a source token to a destination token without
ever storing an extractable copy on either token.

1. On the destination token, generate an RSA key pair:

        p11keygen -l /usr/lib/softhsm/libsofthsm2.so -t "dest token" \
            -k rsa -b 4096 -i rsa-dest-wrapping-key wrap unwrap

2. Export the public key:

        p11cat -l /usr/lib/softhsm/libsofthsm2.so -t "dest token" \
            pubk/rsa-dest-wrapping-key >rsa-dest-wrapping-key.pubk

3. On the source token, import the destination public key:

        p11importpubk -l /usr/lib/softhsm/libsofthsm2.so -t "source token" \
            -f rsa-dest-wrapping-key.pubk -i rsa-dest-wrapping-key

4. On the source token, rewrap the key under the destination public key:

        p11rewrap -l /usr/lib/softhsm/libsofthsm2.so -t "source token" \
            -f business-key-for-source-token.wrap \
            -W 'wrappingkey="rsa-dest-wrapping-key",algorithm=envelope,filename="business-key-for-dest-token.wrap"'

5. On the destination token, unwrap the key:

        p11unwrap -l /usr/lib/softhsm/libsofthsm2.so -t "dest token" \
            -f business-key-for-dest-token.wrap

**Rewrap a key to two different destination tokens simultaneously**

        p11rewrap -l /usr/lib/softhsm/libsofthsm2.so -t "source token" \
            -f original-key.wrap \
            -W 'wrappingkey="rsa-dest1-key",algorithm=envelope,filename="key-for-dest1.wrap"' \
            -W 'wrappingkey="rsa-dest2-key",algorithm=envelope,filename="key-for-dest2.wrap"'

**Rewrap using rfc3394 (AES-to-AES key exchange)**

        p11rewrap -l /usr/lib/softhsm/libsofthsm2.so -s 0 \
            -f aes-key.wrap \
            -W 'wrappingkey="aes-dest-wrapping-key",algorithm=rfc3394,filename="aes-key-rewrapped.wrap"'

**Rewrap with JWK output**

        p11rewrap -l /usr/lib/softhsm/libsofthsm2.so -s 0 \
            -f aes-key.wrap \
            -W 'wrappingkey="rsa-dest-key",algorithm=oaep,filename="aes-key.jwk"' \
            -J rsa-dest-key-id

# SEE ALSO

**pkcs11-tools**(7), **pkcs11-wrap**(5), **p11wrap**(1), **p11unwrap**(1),
**p11keygen**(1), **p11slotinfo**(1)

# AUTHOR

Mastercard, and the pkcs11-tools contributors.
