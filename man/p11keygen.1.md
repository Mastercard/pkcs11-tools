% P11KEYGEN(1) | pkcs11-tools

# NAME

p11keygen - generate a key or key pair on a PKCS#11 token

# SYNOPSIS

**p11keygen**
\[**-l** *pkcs11library*]
\[**-m** *nssconfigdir*]
\[**-s** *slotindex* | **-t** *tokenlabel*]
\[**-p** *pin* | **:::exec:***command* | **:::nologin**]
\[**-S**]
**-i** *label*
**-k** *keytype*
\[**-b** *bits*]
\[**-e** *exponent*]
\[**-q** *curveparam*]
\[**-d** *paramfile*]
\[**-W** *wrappingspec*]
\[**-J** *wrappingkeyid*]
\[**-r**]
\[**-n**]
\[**-h**]
\[**-V**]
\[*ATTRIBUTE*=*VALUE* ...]

# DESCRIPTION

**p11keygen** generates a secret key or asymmetric key pair on a PKCS#11
token. The key type, label, and cryptographic attributes are selected at
generation time via command-line options and positional *ATTRIBUTE=VALUE*
arguments.

Optionally, **p11keygen** can generate the key as a session key and wrap it
immediately under one or more wrapping keys using the **-W** option, writing
the wrapped key to a file in the **pkcs11-wrap**(5) format. This is useful for
key-ceremony workflows where a clear-text key must never exist on the token.
By default a token copy is also kept; use **-r** to suppress it.

**-J** requests JWK (JSON Web Key, RFC 7517) output in place of the
pkcs11-tools wrap format. Envelope wrapping is not supported with **-J**.

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
    value `:::nologin` skips login entirely (useful for tokens that do not
    require authentication). Overrides **PKCS11PASSWORD**.

**-S**
:   Login with Security Officer (SO) privilege instead of user privilege.

**-i** *label*
:   Label (alias) to give to the generated key or key pair. Mandatory.

**-k** *keytype*
:   Key type to generate. Accepted values are:

    `aes`
    :   AES secret key (default size: 256 bits).

    `des`
    :   DES / 2DES / 3DES secret key (default size: 192 bits = DES3).

    `rsa`
    :   RSA key pair (default size: 2048 bits).

    `dsa`
    :   DSA key pair; size comes from a DH/DSA parameter file (**-d**).

    `dh`
    :   Diffie-Hellman key pair; size comes from a DH/DSA parameter file (**-d**).

    `ec`
    :   Elliptic Curve key pair (default curve: **prime256v1**).

    `ed`
    :   Edwards-curve key pair (default: **ED25519**).

    `generic` | `hmac`
    :   Generic-secret (HMAC) key (default size: 160 bits). The two names are
        synonyms.

    `hmacsha1`, `hmacsha224`, `hmacsha256`, `hmacsha384`, `hmacsha512`
    :   Entrust nCipher vendor-specific HMAC key types with a fixed hash
        algorithm. Only available when the toolkit is built with nCipher
        support (**--with-ncipher**).

    `mlkem`
    :   ML-KEM (FIPS 203) key pair; parameter set selected via **-b**. Only
        available when the toolkit is built with post-quantum support
        (**--enable-pqc**, which is the default).

    `mldsa`
    :   ML-DSA (FIPS 204) key pair; parameter set selected via **-b**. Only
        available when the toolkit is built with post-quantum support
        (**--enable-pqc**).

    `slhdsa`
    :   SLH-DSA (FIPS 205) key pair; parameter set selected via **-q**. Only
        available when the toolkit is built with post-quantum support
        (**--enable-pqc**).

**-b** *bits*
:   Key size in bits. Accepted values and defaults:

    AES: 128, 192, 256 (default 256).

    DES: 128 (=DES2) or 192 (=DES3, default).

    RSA: 1024, 2048, 3072, 4096 (default 2048).

    Generic/HMAC: any value >56 (default 160).

    ML-KEM: 512, 768 (default), 1024. Only with **--enable-pqc**.

    ML-DSA: 44, 65 (default), 87. Only with **--enable-pqc**.

    For DH and DSA the key size comes from the parameter file (**-d**) and
    this option is ignored.

**-e** *exponent*
:   RSA public exponent (default: 65537).

**-q** *curveparam*
:   Curve or parameter-set name, depending on key type:

    For **ec**: an OpenSSL elliptic curve name such as `prime256v1`,
    `secp384r1`, or `secp521r1` (default: `prime256v1`). Run
    `openssl ecparam -list_curves` for a full list; the token must support the
    chosen curve.

    For **ed**: `ED25519` or `ED448` (default: `ED25519`).

    For **slhdsa**: a variant of the form `{sha2,shake}-{128,192,256}{s,f}`,
    e.g. `sha2-128s` (default) or `shake-256f`. Only with **--enable-pqc**.

**-d** *paramfile*
:   Path to a DER or PEM-encoded DH or DSA parameter file. Mandatory for
    **-k dh** and **-k dsa**; ignored for all other key types.

**-W** *wrappingspec*
:   Wrap the generated key under a wrapping key on the token. Can be specified
    multiple times to wrap under several keys. The argument is a
    comma-separated specifier of the form:

        wrappingkey="<label>"[,algorithm=<alg>][,filename="<path>"]

    `wrappingkey="<label>"`
    :   Label of the wrapping key (double quotes are mandatory).

    `algorithm=<alg>`
    :   Wrapping algorithm (default: `oaep`). The supported algorithms are:

        `pkcs1`
        :   PKCS#1 v1.5 RSA wrapping (RFC 8017).

        `oaep(args...)`
        :   PKCS#1 OAEP RSA wrapping (RFC 8017). Optional arguments,
            comma-separated:

            `label="<value>"` — OAEP label/source argument.

            `mgf=` `CKG_MGF1_SHA1` | `CKG_MGF1_SHA224` | `CKG_MGF1_SHA256` | `CKG_MGF1_SHA384` | `CKG_MGF1_SHA512`
            — mask generation function (default: `CKG_MGF1_SHA1`).

            `hash=` `CKM_SHA_1` | `CKM_SHA224` | `CKM_SHA256` | `CKM_SHA384` | `CKM_SHA512`
            — hashing algorithm (default: `CKM_SHA_1`).

            Surround the algorithm string with single quotes when passing
            arguments to the shell, e.g.
            `'oaep(mgf=CKG_MGF1_SHA256,hash=CKM_SHA256)'`.

        `cbcpad(args...)`
        :   CBC-pad wrapping (`CKM_AES_CBC_PAD` or equivalent). Optional
            argument: `iv=0x<hexstring>` — initialization vector.

        `rfc3394`
        :   AES key wrap without padding (RFC 3394, NIST SP 800-38F),
            using `CKM_AES_KEY_WRAP` or a vendor equivalent.

        `rfc5649(args...)`
        :   AES key wrap with padding (RFC 5649, NIST SP 800-38F), using
            `CKM_AES_KEY_WRAP_PAD` or a vendor equivalent.

        `envelope(args...)`
        :   Two-layer envelope wrapping. Optional arguments:

            `inner=cbcpad|rfc3394|rfc5649` — inner algorithm (default:
            `cbcpad`).

            `outer=pkcs1|oaep` — outer algorithm (default: `oaep`).

            Algorithms may themselves carry parameters,
            e.g. `envelope(inner=rfc3394,outer=oaep)`.

    `filename="<path>"`
    :   Path to the output wrap file (double quotes are mandatory). See
        **pkcs11-wrap**(5) for the file format.

**-J** *wrappingkeyid*
:   Output wrapped key in JOSE JWK format (RFC 7517) instead of the
    pkcs11-tools wrap format. *wrappingkeyid* is a string identifying the
    wrapping key in the JWK; pass an empty string `""` to omit it. Envelope
    wrapping is not supported with **-J**. Requires **-W**.

**-r**
:   When wrapping (**-W**), remove the token copy of the session key after
    successful wrapping. By default a copy is kept on the token.

**-n**
:   Allow creation of duplicate objects (objects with the same label). Only
    available when the toolkit is built with **--enable-duplicate**.

**-h**
:   Print usage information and exit.

**-V**
:   Print version information and exit.

# ARGUMENTS

Zero or more *ATTRIBUTE=VALUE* pairs may be given as positional arguments after
all options. They set PKCS#11 attributes on the generated key or key pair.
For key pairs, attributes that apply to only one of the keys (public or
private) are dispatched automatically.

Supported attribute names (the `CKA_` prefix is optional and the names are
case-insensitive):

**CKA_LABEL**
:   String label (also set by **-i**).

**CKA_ID**
:   Hex or string identifier (e.g. `0xdeadbeef`).

**CKA_ENCRYPT**, **CKA_DECRYPT**
:   Boolean. Allow encryption / decryption.

**CKA_WRAP**, **CKA_UNWRAP**
:   Boolean. Allow key wrapping / unwrapping.

**CKA_SIGN**, **CKA_VERIFY**
:   Boolean. Allow signing / verification.

**CKA_SIGN_RECOVER**, **CKA_VERIFY_RECOVER**
:   Boolean.

**CKA_DERIVE**
:   Boolean. Allow key derivation.

**CKA_ENCAPSULATE**, **CKA_DECAPSULATE**
:   Boolean. Allow KEM encapsulation / decapsulation (ML-KEM).

**CKA_EXTRACTABLE**
:   Boolean. Allow the key to be extracted.

**CKA_SENSITIVE**
:   Boolean. Mark the key as sensitive (default: `true`).

**CKA_MODIFIABLE**
:   Boolean.

**CKA_TRUSTED**
:   Boolean. Can only be set when logged in as SO (**-S**).

**CKA_WRAP_WITH_TRUSTED**
:   Boolean.

**CKA_WRAP_TEMPLATE**, **CKA_UNWRAP_TEMPLATE**
:   Attribute template, e.g. `{ encrypt decrypt sensitive !extractable }`.

**CKA_ENCAPSULATE_TEMPLATE**, **CKA_DECAPSULATE_TEMPLATE**
:   Attribute template (ML-KEM).

Supported value syntax:

- Boolean: `true`, `false`, `yes`, `no`, `on`, `off`; bare attribute name
  means `true`; prefix with `no` or `!` means `false`.
- String: double-quoted ASCII string, e.g. `"mykey"`.
- Hex: even-digit hex value prefixed with `0x`, e.g. `0xdeadbeef`.
- Date: 8-digit string `YYYYMMDD`, e.g. `20260101`.
- Mechanism: PKCS#11 mechanism name beginning with `CKM_`.
- Mechanism array: space- or comma-separated mechanism names in `{ }`.
- Attribute array (templates): space- or comma-separated attribute/value
  pairs in `{ }`.

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

Generate a 256-bit AES key with encrypt and decrypt attributes:

    p11keygen -l /usr/lib/softhsm/libsofthsm2.so -s 0 \
        -p changeit -i my-aes-key -k aes -b 256 \
        encrypt decrypt

Generate a 2048-bit RSA key pair with sign and verify:

    p11keygen -l /usr/lib/softhsm/libsofthsm2.so -t "my token" \
        -p changeit -i my-rsa-key -k rsa -b 2048 \
        sign verify

Generate a 256-bit HMAC generic key:

    p11keygen -l /usr/lib/softhsm/libsofthsm2.so -t "my token" \
        -p changeit -i my-hmac-key -k generic -b 256 derive

Generate a session AES-256 key and wrap it under an RSA key using OAEP,
writing the wrapped key to a file (no token copy):

    p11keygen -l /usr/lib/softhsm/libsofthsm2.so -t "my token" \
        -p changeit -i my-session-aes -k aes -b 256 \
        -W 'wrappingkey="my-rsa-key",algorithm=oaep,filename="wrapped.key"' \
        -r encrypt decrypt

Generate an ML-DSA-65 key pair (requires post-quantum build):

    p11keygen -l /usr/lib/softhsm/libsofthsm2.so -t "my token" \
        -p changeit -i my-mldsa-key -k mldsa -b 65 sign verify

Generate an SLH-DSA key with the sha2-128s parameter set:

    p11keygen -l /usr/lib/softhsm/libsofthsm2.so -t "my token" \
        -p changeit -i my-slhdsa-key -k slhdsa -q sha2-128s sign verify

# SEE ALSO

**pkcs11-tools**(7), **pkcs11rc**(5), **pkcs11-wrap**(5),
**p11slotinfo**(1), **p11ls**(1), **p11wrap**(1), **p11unwrap**(1),
**p11req**(1), **p11kcv**(1)

# AUTHOR

Mastercard, and the pkcs11-tools contributors.
