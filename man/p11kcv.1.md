% P11KCV(1) | pkcs11-tools

# NAME

p11kcv - compute and print the key check value of a symmetric key on a PKCS#11 token

# SYNOPSIS

**p11kcv**
\[**-l** *pkcs11library*]
\[**-m** *nssconfigdir*]
\[**-s** *slotindex* | **-t** *tokenlabel*]
\[**-p** *pin* | **:::exec:***command* | **:::nologin**]
\[**-S**]
\[**-f** *flavour*]
\[**-b** *bufsize*]
\[**-n** *kcvlen*]
\[**-h**]
\[**-V**]
\[*FILTER* ...]

# DESCRIPTION

**p11kcv** connects to a PKCS#11 token, locates one or more symmetric keys
matching the given filters, and computes and prints their Key Check Value (KCV).

The following KCV algorithms are supported:

**kcv**
:   Retrieve the value of the **CKA_CHECK_VALUE** attribute on the key object
    (if present). Works for all key types.

**legacy** / **ecb**
:   ECB encryption of a block-size buffer of `0x00` bytes. For DES: 8 bytes;
    for AES: 16 bytes. Requires **CKA_ENCRYPT** to be set on the key.

**mac**
:   FIPS PUB 113 MAC computation on a block-size buffer of `0x00` bytes.
    Requires **CKA_SIGN** to be set on the key. Supported for DES and 2DES/3DES
    keys.

**cmac**
:   RFC 4493 CMAC computation on a 16-byte buffer of `0x00`. Supported for
    2DES/3DES and AES keys.

**aes-xcbc-mac**
:   RFC 3566 AES-XCBC-MAC on a 16-byte buffer of `0x00`. AES keys only.

**aes-xcbc-mac-96** / **aes-xcbc-mac96**
:   RFC 3566 AES-XCBC-MAC-96 on a 16-byte buffer of `0x00`. AES keys only.

For HMAC keys the algorithm selector is ignored; the KCV is computed by HMACing
a buffer of `0x00` bytes (length specified with **-b**, default 0).

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

**-f** *flavour*
:   KCV algorithm flavour. Accepted values depend on the key type:

    All keys: `kcv`

    DES keys: `ecb`, `legacy` (synonym for `ecb`), `mac`

    2DES / 3DES keys: `ecb`, `legacy`, `mac`, `cmac`

    AES keys: `ecb`, `legacy`, `mac`, `cmac`, `aes-xcbc-mac`,
    `aes-xcbc-mac-96`

    HMAC keys: ignored

    Default: `legacy`.

**-b** *bufsize*
:   Size (in bytes) of the buffer to HMAC, for HMAC keys. Default: 0 (empty
    buffer).

**-n** *kcvlen*
:   Number of bytes of KCV output to display. Default: 3.

**-h**
:   Print usage information and exit.

**-V**
:   Print version information and exit.

# ARGUMENTS

Zero or more *FILTER* expressions may be given after all options, to select
which keys to operate on. Each filter is of the form:

    [TYPE[/[ATTRIBUTE/]]VALUE]

*TYPE* must be `seck` (secret key).

*ATTRIBUTE* is one of `id`, `label`, `sn`, or a PKCS#11 attribute name (e.g.
`CKA_ENCRYPT`). When omitted, the default is `label`.

*VALUE* is either an ASCII string or a hexadecimal value enclosed in curly
braces, e.g. `{deadbeef}`.

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

Compute the KCV of an AES key named `my-aes-key` using the default (legacy)
algorithm:

    p11kcv -l /usr/lib/softhsm/libsofthsm2.so -s 0 -p changeit \
        seck/my-aes-key

Compute the CMAC-based KCV of a 3DES key, printing 4 bytes:

    p11kcv -l /usr/lib/softhsm/libsofthsm2.so -t "my token" -p changeit \
        -f cmac -n 4 seck/my-des3-key

Retrieve the CKA_CHECK_VALUE attribute of a key if present:

    p11kcv -l /usr/lib/softhsm/libsofthsm2.so -t "my token" -p changeit \
        -f kcv seck/my-aes-key

Compute the HMAC KCV over a 64-byte zeroed buffer:

    p11kcv -l /usr/lib/softhsm/libsofthsm2.so -t "my token" -p changeit \
        -b 64 seck/my-hmac-key

# SEE ALSO

**pkcs11-tools**(7), **pkcs11rc**(5), **p11keygen**(1), **p11ls**(1)

# AUTHOR

Mastercard, and the pkcs11-tools contributors.
