% P11WRAP(1) | pkcs11-tools

# NAME

p11wrap - wrap a key using one or more wrapping key(s) on a PKCS#11 token

# SYNOPSIS

**p11wrap**
\[**-l** *pkcs11library*]
\[**-m** *nssconfigdir*]
\[**-s** *slotindex* | **-t** *tokenlabel*]
\[**-p** *pin* | **:::exec:***command* | **:::nologin**]
**-i** *key_alias*
\[**-w** *wrapping_key_alias*
  \[**-a** *algorithm*]
  \[**-o** *file*]]
\[**-W** *wrapping_specifier* ...]
\[**-J** *wrapping_key_id*]
\[**-S**]
\[**-h**]
\[**-V**]

# DESCRIPTION

**p11wrap** connects to a PKCS#11 token and wraps (exports in encrypted form) a
key object under one or more wrapping keys.  The result is written as a
**pkcs11-wrap**(5) file that can later be imported with **p11unwrap**(1) or
re-wrapped to a different key with **p11rewrap**(1).

The key to wrap must have the **CKA_EXTRACTABLE** attribute set to **true**.
The wrapping key must have **CKA_WRAP** set to **true**.

Multiple wrapping operations on the same key can be performed in a single
invocation by repeating **-W**.  Each **-W** specifier produces its own output
file.

When neither **-s** nor **-t** is given, and no corresponding environment
variable is set, the command enters interactive mode and offers the list of
available slots for selection.  See **pkcs11-tools**(7).

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
:   Token PIN, or one of the special forms:

    **:::exec:***command*
    :   Execute *command* and use its standard output as the PIN.

    **:::nologin**
    :   Skip login entirely (useful for tokens that do not require a PIN for
        the intended operation).

    Overrides **PKCS11PASSWORD**.

**-i** *key_alias*
:   Label of the key to wrap.  The key must exist on the token and must have
    **CKA_EXTRACTABLE** set to **true**.  Mandatory.

**-w** *wrapping_key_alias*
:   Label of the wrapping key.  The key must have **CKA_WRAP** set to
    **true**.  Mandatory when using **-a** or **-o**; mutually exclusive with
    **-W**.

**-a** *algorithm*
:   Wrapping algorithm to use.  Default is **oaep**.  See the ARGUMENTS
    section for the full list and parameter syntax.  Mutually exclusive with
    **-W**.

**-o** *file*
:   Write the wrapped key to *file* instead of standard output.  Mutually
    exclusive with **-W**.

**-W** *wrapping_specifier*
:   Combined wrapping specifier; mutually exclusive with **-a**, **-o** and
    **-w**.  The argument has the form:

        wrappingkey="<label>"[,algorithm=<algorithm>][,filename="<path>"]

    *  `wrappingkey="<label>"` — label of the wrapping key (double quotes
       mandatory).
    *  `algorithm=<algorithm>` — wrapping algorithm (default: **oaep**).
    *  `filename="<path>"` — output file (double quotes mandatory); if
       omitted, the wrapped key is written to standard output.

    **-W** can be repeated up to 32 times to produce multiple wrapped-key
    files in a single run.

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

# ARGUMENTS

The wrapping algorithm is selected with **-a** (or via the `algorithm=` field
of **-W**).  The following algorithms are available:

**pkcs1**
:   PKCS#1 v1.5 (RFC 8017), mechanism **CKM_RSA_PKCS**.  Wrapping key: RSA.
    Wrapped key: symmetric or secret (HMAC).  Considered insecure; avoid when
    possible.

**oaep**\[**(**\[**label="***value***"**]\[**,mgf=***MGF*]\[**,hash=***HASH*]**)**]
:   PKCS#1 OAEP (RFC 8017), mechanism **CKM_RSA_PKCS_OAEP**.  Wrapping key:
    RSA.  Wrapped key: symmetric or secret (HMAC).  This is the default
    algorithm.

    Optional parameters (comma-separated, surround the whole algorithm
    specification with single quotes on the shell):

    **label="***value***"**
    :   OAEP label (source data).  Default: empty.

    **mgf=***MGF*
    :   Mask generation function.  One of **CKG_MGF1_SHA1** (default),
        **CKG_MGF1_SHA224**, **CKG_MGF1_SHA256**, **CKG_MGF1_SHA384**,
        **CKG_MGF1_SHA512**.

    **hash=***HASH*
    :   Hash algorithm.  One of **CKM_SHA_1** (default), **CKM_SHA224**,
        **CKM_SHA256**, **CKM_SHA384**, **CKM_SHA512**.

    Example: `-a 'oaep(mgf=CKG_MGF1_SHA256,hash=CKM_SHA256)'`

**cbcpad**\[**(**\[**iv=***0xHEX*]**)**]
:   CBC mode with PKCS#7 padding (**CKM_AES_CBC_PAD** or **CKM_DES_CBC_PAD**
    depending on the wrapping key).  Wrapping key: AES or DES.  Wrapped key:
    any type.

    Optional parameter:

    **iv=***0xHEX*
    :   Initialisation vector as a hex string prefixed with `0x`.

**rfc3394**
:   AES Key Wrap (RFC 3394, NIST SP 800-38F), mechanism
    **CKM_AES_KEY_WRAP** or an equivalent vendor-specific mechanism.
    Wrapping key: AES.  Wrapped key: any type aligned on 8 bytes.

**rfc5649**\[**(**\[**flavour=***flavour*]**)**]
:   AES Key Wrap with Padding (RFC 5649, NIST SP 800-38F).  Wrapping key:
    AES.  Wrapped key: any type.

    The default mechanism is **CKM_AES_KEY_WRAP_PAD** (PKCS#11 v2.40).
    Optional parameter:

    **flavour=***flavour*
    :   Force a specific mechanism.  *flavour* is one of:

        **pad** — **CKM_AES_KEY_WRAP_PAD** (default)\
        **kwp** — **CKM_AES_KEY_WRAP_KWP** (PKCS#11 v3.0)\
        **nss** — **CKM_NSS_AES_KEY_WRAP_PAD** (NSS variant, not fully RFC5649-compliant)\
        **luna** — **CKM_LUNA_AES_KWP** (Safenet/Gemalto Luna; requires a Luna-enabled build)

        A full **CKM_*** mechanism name is also accepted for direct vendor control.

**envelope**\[**(**\[**inner=***inner_alg*]\[**,outer=***outer_alg*]**)**]
:   Envelope wrapping: the target key is first wrapped with an ephemeral AES
    session key (*inner*), then the session key is wrapped with the specified
    wrapping key (*outer*).  Allows wrapping any key type under a top-level
    RSA key.

    **inner=***inner_alg*
    :   Inner wrapping algorithm.  One of **cbcpad**, **rfc3394**, **rfc5649**
        (with their own optional parameters).  Default: **cbcpad**.

    **outer=***outer_alg*
    :   Outer wrapping algorithm.  One of **pkcs1**, **oaep** (with their own
        optional parameters).  Default: **oaep**.

    Example: `-a 'envelope(inner=rfc3394,outer=oaep)'`\
    Default (when no parameters are given): `envelope(inner=cbcpad,outer=oaep)`.

    JWK output (**-J**) is not supported with envelope wrapping.

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

Wrap an AES key called `aes-wrapping-key` using an RSA key called
`rsa-wrapping-key` with the default OAEP algorithm, and write the result to a
file:

    p11wrap -l /usr/lib/softhsm/libsofthsm2.so -s 0 \
        -i aes-wrapping-key -w rsa-wrapping-key \
        -o aes-wrapping-key.wrap

Same, but with SHA-256 hash and MGF in OAEP (single-quoted to protect
parentheses from the shell):

    p11wrap -l /usr/lib/softhsm/libsofthsm2.so -s 0 \
        -i aes-wrapping-key -w rsa-wrapping-key \
        -a 'oaep(mgf=CKG_MGF1_SHA256,hash=CKM_SHA256)' \
        -o aes-wrapping-key.wrap

Wrap a private RSA key using envelope wrapping (RSA outer, CBC-PAD inner)
under an RSA public wrapping key:

    p11wrap -l /usr/lib/softhsm/libsofthsm2.so -t "my token" \
        -i my-private-key -w rsa-wrapping-key \
        -a 'envelope(inner=cbcpad,outer=oaep)' \
        -o my-private-key.wrap

Wrap the same key simultaneously under two different public keys in one
invocation using **-W**:

    p11wrap -l /usr/lib/softhsm/libsofthsm2.so -s 0 \
        -i business-key \
        -W 'wrappingkey="rsa-dest-key",algorithm=envelope,filename="bk-dest.wrap"' \
        -W 'wrappingkey="rsa-source-key",algorithm=envelope,filename="bk-source.wrap"'

Output the wrapped key in JWK format with an explicit key identifier:

    p11wrap -l /usr/lib/softhsm/libsofthsm2.so -s 0 \
        -i aes-key -w rsa-wrapping-key -J my-rsa-key-id \
        -o aes-key.jwk

# SEE ALSO

**pkcs11-tools**(7), **pkcs11-wrap**(5), **p11unwrap**(1), **p11rewrap**(1),
**p11keygen**(1), **p11slotinfo**(1)

# AUTHOR

Mastercard, and the pkcs11-tools contributors.
