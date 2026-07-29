% PKCS11-WRAP(5) | pkcs11-tools

# NAME

pkcs11-wrap - wrapped-key file format used by p11wrap, p11unwrap, p11rewrap, and p11keygen

# DESCRIPTION

The **pkcs11-wrap** file format is a text-based, self-describing container
for a PKCS#11-wrapped key.  It is produced by **p11wrap**(1) and
**p11keygen**(1) (with the **-W** parameter) and consumed by **p11unwrap**(1)
and **p11rewrap**(1).

The file is a POSIX text file: lines are terminated by newline, blank lines are
ignored, and lines beginning with `#` are comments.  The lexer is
case-insensitive for header keywords and algorithm names.

A file consists of:

1. One or more **header lines** describing the file type, grammar version,
   wrapping key and algorithm, and the PKCS#11 attributes to be applied when
   the key is unwrapped.
2. One or two **PEM-style base64 blocks** carrying the encrypted key material.
3. Optionally, an embedded **public key** PEM block (envelope wrapping only).

An alternative **JWK** (JSON Web Key, RFC 7517) output format is produced
when **p11wrap**(1) or **p11keygen**(1) is invoked with **-J**.  The JWK
format does not support envelope wrapping.

# GRAMMAR VERSION

The current grammar version is **2.3** (defined as
`SUPPORTED_GRAMMAR_VERSION` in the toolkit source).  The parser accepts any
file whose `Grammar-Version:` value is less than or equal to the supported
version; a higher version causes an error and instructs the user to update
the toolkit.

# HEADER KEYWORDS

**Content-Type:** `application/pkcs11-tools`
:   Mandatory.  Identifies the file as a pkcs11-tools wrapped-key file.

**Grammar-Version:** *x.y*
:   Optional but recommended.  Current value is `2.3`.  The parser rejects
    files with a version newer than the one compiled in.

**Wrapping-Key:** "*label*"
:   Label (quoted string) of the wrapping key used to produce this file.
    On unwrap, this is informational; the actual wrapping key is selected by
    the attributes of the file or by the operator.

**Wrapping-Algorithm:** *algorithm*
:   Specifies the mechanism used to wrap the key.  See **WRAPPING ALGORITHMS**
    below.

# PKCS#11 ATTRIBUTE LINES

Attribute lines specify how the key is to be reconstructed (imported) by
**p11unwrap**(1).  Each line has the form:

    ATTRIBUTE: VALUE

Attribute names are case-insensitive.  The following attributes are recognized:

**CKA_LABEL:** "*string*"
:   Label (quoted string) to assign to the unwrapped key.

**CKA_ID:** *hexstring* | "*string*"
:   Object identifier as a hex value (`0x…`) or a quoted string.

**CKA_CLASS:** *objectclass*
:   Object class.  One of: `CKO_DATA`, `CKO_PUBLIC_KEY`, `CKO_PRIVATE_KEY`,
    `CKO_SECRET_KEY`, `CKO_CERTIFICATE`, `CKO_HW_FEATURE`,
    `CKO_DOMAIN_PARAMETERS`, `CKO_MECHANISM`, `CKO_OTP_KEY`.

**CKA_KEY_TYPE:** *keytype*
:   Key type.  Canonical names (e.g. `CKK_AES`) or short aliases
    (e.g. `aes`, `rsa`, `ec`, `generic`).  All key types supported by the
    command-line attribute parser are also valid here; see **pkcs11-tools**(7).

**CKA_TOKEN:** *boolean*
:   Whether the key is a token object.  Default: `true`.

**CKA_PRIVATE:** *boolean*
:   Whether the key requires login to access.

**CKA_SENSITIVE:** *boolean*
:   Whether the key is sensitive.

**CKA_EXTRACTABLE:** *boolean*
:   Whether the key may be extracted (wrapped) after import.

**CKA_MODIFIABLE:** *boolean*
:   Whether the key attributes may be changed after import.

**CKA_ENCRYPT:** *boolean*
:   The key may be used for encryption.

**CKA_DECRYPT:** *boolean*
:   The key may be used for decryption.

**CKA_WRAP:** *boolean*
:   The key may be used to wrap other keys.

**CKA_UNWRAP:** *boolean*
:   The key may be used to unwrap other keys.

**CKA_ENCAPSULATE:** *boolean*
:   The key may be used for key encapsulation (KEM, PKCS#11 v3.2).

**CKA_DECAPSULATE:** *boolean*
:   The key may be used for key decapsulation (KEM, PKCS#11 v3.2).

**CKA_SIGN:** *boolean*
:   The key may be used to sign.

**CKA_SIGN_RECOVER:** *boolean*
:   The key may be used to sign with recovery.

**CKA_VERIFY:** *boolean*
:   The key may be used to verify signatures.

**CKA_VERIFY_RECOVER:** *boolean*
:   The key may be used to verify with recovery.

**CKA_DERIVE:** *boolean*
:   The key may be used for key derivation.

**CKA_TRUSTED:** *boolean*
:   The key is trusted (can only be set by a Security Officer).

**CKA_WRAP_WITH_TRUSTED:** *boolean*
:   The key may only be wrapped by a trusted key.

**CKA_START_DATE:** *YYYYMMDD*
:   Key validity start date.

**CKA_END_DATE:** *YYYYMMDD*
:   Key validity end date.

**CKA_CHECK_VALUE:** *hexstring*
:   Key check value.

**CKA_EC_PARAMS:** *hexstring*
:   DER-encoded EC domain parameters.

**CKA_SUBJECT:** *hexstring*
:   DER-encoded subject name.

**CKA_WRAP_TEMPLATE:** `{` *attribute-list* `}`
:   Template applied when this key is used to wrap another key.

**CKA_UNWRAP_TEMPLATE:** `{` *attribute-list* `}`
:   Template applied to any key unwrapped by this key.

**CKA_DERIVE_TEMPLATE:** `{` *attribute-list* `}`
:   Template applied to keys derived from this key.

**CKA_ENCAPSULATE_TEMPLATE:** `{` *attribute-list* `}`
:   Template applied when this key is used to encapsulate.

**CKA_DECAPSULATE_TEMPLATE:** `{` *attribute-list* `}`
:   Template applied to keys decapsulated using this key.

**CKA_ALLOWED_MECHANISMS:** `{` *mechanism-list* `}`
:   List of mechanisms this key is permitted to use.

Boolean values accept: `true`, `false`, `yes`, `no`, `CK_TRUE`, `CK_FALSE`.
A bare attribute name is `true`; prefixing with `no` or `!` is `false`.
Template attributes are delimited with `{` and `}` and contain further
attribute assignments.  On **AWS CloudHSM**, template attributes must be
commented out before unwrapping.

# WRAPPING ALGORITHMS

The `Wrapping-Algorithm:` header (and the **-a** option to **p11wrap**(1))
accepts the following values:

**pkcs1**
:   PKCS#1 v1.5 RSA wrapping (`CKM_RSA_PKCS`).  RSA wrapping key only.
    Considered insecure; avoid in new deployments.

**oaep** | **oaep(**[*params*]**)**
:   PKCS#1 OAEP RSA wrapping (`CKM_RSA_PKCS_OAEP`).  RSA wrapping key only.
    This is the default algorithm.  Optional parameters (comma-separated):

    `hash=`*CKM_SHA_1* | *CKM_SHA224* | *CKM_SHA256* | *CKM_SHA384* | *CKM_SHA512*
    :   Hash algorithm (default: `CKM_SHA_1`).

    `mgf=`*CKG_MGF1_SHA1* | *CKG_MGF1_SHA224* | *CKG_MGF1_SHA256* | *CKG_MGF1_SHA384* | *CKG_MGF1_SHA512*
    :   Mask generation function (default: `CKG_MGF1_SHA1`).

    `label="`*string*`"`
    :   OAEP source label (default: empty).

**cbcpad** | **cbcpad(**[*params*]**)**
:   CBC-mode wrapping with PKCS#7 padding (`CKM_AES_CBC_PAD` or
    `CKM_DES_CBC_PAD`).  AES or DES wrapping key.  Widely supported.
    Optional parameter:

    `iv=`*0xHEXSTRING*
    :   Initialisation vector (default: all-zero bytes, library-specific).

**rfc3394**
:   AES Key Wrap as defined in RFC 3394 and NIST SP 800-38F
    (`CKM_AES_KEY_WRAP`), or an equivalent vendor-specific mechanism.
    AES wrapping key only.  The wrapped key must be aligned on an 8-byte
    boundary.  The standard mechanism is preferred automatically when
    several compatible mechanisms are advertised by the token.

**rfc5649** | **rfc5649(**`flavour=`*name*`)**
:   AES Key Wrap with Padding as defined in RFC 5649 and NIST SP 800-38F.
    AES wrapping key only.  The default mechanism is `CKM_AES_KEY_WRAP_PAD`
    (PKCS#11 v2.40).  The optional `flavour=` parameter selects a specific
    mechanism:

    `pad`
    :   `CKM_AES_KEY_WRAP_PAD` — PKCS#11 v2.40 (default).

    `kwp`
    :   `CKM_AES_KEY_WRAP_KWP` — PKCS#11 v3.0.

    `nss`
    :   `CKM_NSS_AES_KEY_WRAP_PAD` — NSS variant (not fully RFC 5649
        compliant; recorded explicitly in the file to prevent accidental
        cross-mechanism unwrap).

    `luna`
    :   `CKM_LUNA_AES_KWP` — Safenet/Gemalto Luna (requires a Luna-enabled
        build).

    Any full `CKM_*` mechanism name is also accepted (with a warning).
    The `pad`, `kwp`, and `luna` flavours are mutually interoperable and all
    produce standard RFC 5649 / NIST SP 800-38F KWP output; the wrapped-key
    file records `rfc5649/1.0` for these flavours.

**envelope** | **envelope(**[*params*]**)**
:   Two-layer wrapping that combines an asymmetric outer wrap with a
    symmetric inner wrap, enabling any key type to be wrapped under a single
    RSA key.  Parameters (comma-separated):

    `inner=`*cbcpad*|*rfc3394*|*rfc5649*
    :   Symmetric algorithm used to wrap the target key (default: `cbcpad`).
        Each inner algorithm may specify its own sub-parameters.

    `outer=`*pkcs1*|*oaep*
    :   Asymmetric algorithm used to wrap the ephemeral inner key (default:
        `oaep`).

    Envelope wrapping is not supported in JWK output mode.

# PEM BLOCKS

The encrypted key material is carried in one or two PEM-style blocks:

**`-----BEGIN WRAPPED KEY-----`** … **`-----END WRAPPED KEY-----`**
:   Used for non-envelope wrapping algorithms (`pkcs1`, `oaep`, `cbcpad`,
    `rfc3394`, `rfc5649`).  Contains the base64-encoded encrypted blob.

**`-----BEGIN INNER WRAPPED KEY-----`** … **`-----END INNER WRAPPED KEY-----`**
:   Envelope wrapping only.  The target key wrapped under the ephemeral
    inner (symmetric) key.

**`-----BEGIN OUTER WRAPPED KEY-----`** … **`-----END OUTER WRAPPED KEY-----`**
:   Envelope wrapping only.  The ephemeral inner key wrapped under the
    outer (asymmetric) wrapping key.

**`-----BEGIN PUBLIC KEY-----`** … **`-----END PUBLIC KEY-----`**
:   Envelope wrapping only.  The public key corresponding to the outer
    wrapping key, embedded for verification purposes.

# JWK OUTPUT FORMAT

When **-J** is passed to **p11wrap**(1), the output is a JSON object conforming
to RFC 7517 (JSON Web Key).  The JWK object contains:

- Standard JWK fields: `kty`, `alg`, `key_ops`, `kid`.
- The wrapped key material in the `k` field (base64url-encoded).
- PKCS#11 attributes mapped to vendor-prefixed JSON keys.
- An optional `wrapping_key_id` field if a wrapping key label is provided.

Envelope wrapping is incompatible with JWK output.

# EXAMPLES

## Simple AES key wrapped with RSA-OAEP (default)

    ########################################################################
    #
    # key <aes-export-key> wrapped by key <rsa-wrapping-key>
    # wrapped on host <vault.example.com>
    # operation date and time (UTC): Mon Jul 29 21:00:00 2026
    # wrapping algorithm: oaep
    #
    # use p11unwrap from pkcs11-tools to unwrap key on dest. PKCS#11 token
    #
    ########################################################################
    Content-Type: application/pkcs11-tools
    Grammar-Version: 2.3
    Wrapping-Key: "rsa-wrapping-key"
    Wrapping-Algorithm: oaep(hash=CKM_SHA256,mgf=CKG_MGF1_SHA256)
    CKA_CLASS: CKO_SECRET_KEY
    CKA_KEY_TYPE: CKK_AES
    CKA_LABEL: "aes-export-key"
    CKA_TOKEN: true
    CKA_SENSITIVE: true
    CKA_ENCRYPT: true
    CKA_DECRYPT: true
    CKA_WRAP: false
    CKA_UNWRAP: false
    CKA_EXTRACTABLE: false

    -----BEGIN WRAPPED KEY-----
    VGhpcyBpcyBub3QgYSByZWFsIGNyeXB0b2dyYW0gYnV0IGEgcGxhY2Vob2xkZXI=
    -----END WRAPPED KEY-----

## AES key in an envelope (RSA outer, CBC-pad inner)

    Content-Type: application/pkcs11-tools
    Grammar-Version: 2.3
    Wrapping-Key: "rsa-overarching-key"
    Wrapping-Algorithm: envelope(inner=cbcpad,outer=oaep)
    CKA_CLASS: CKO_SECRET_KEY
    CKA_KEY_TYPE: CKK_AES
    CKA_LABEL: "business-key"
    CKA_TOKEN: true
    CKA_SENSITIVE: true
    CKA_ENCRYPT: true
    CKA_DECRYPT: true
    CKA_EXTRACTABLE: false
    CKA_ALLOWED_MECHANISMS: { CKM_AES_CBC, CKM_AES_GCM }
    CKA_UNWRAP_TEMPLATE: { sensitive=true extractable=false }

    -----BEGIN INNER WRAPPED KEY-----
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    -----END INNER WRAPPED KEY-----

    -----BEGIN OUTER WRAPPED KEY-----
    BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
    -----END OUTER WRAPPED KEY-----

    -----BEGIN PUBLIC KEY-----
    MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA...
    -----END PUBLIC KEY-----

# SEE ALSO

**p11wrap**(1), **p11unwrap**(1), **p11rewrap**(1), **p11keygen**(1),
**pkcs11-tools**(7)

# AUTHOR

Mastercard, and the pkcs11-tools contributors.
