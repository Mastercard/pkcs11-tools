% PKCS11-TOOLS(7) | pkcs11-tools

# NAME

pkcs11-tools - overview, common options, and conventions of the pkcs11-tools toolkit

# DESCRIPTION

**pkcs11-tools** is a collection of command-line utilities for managing
cryptographic objects on PKCS#11 tokens: hardware security modules (HSMs),
smart cards, and software-based keystores such as SoftHSM2, NSS, and Kryoptic.
All commands share a consistent interface described in this page.

## Commands

**p11cat**(1)
:   Print a certificate or public key in PEM (base64 DER) format.

**p11importcert**(1)
:   Import a PEM/DER certificate into the token; binds it to a matching
    private key by adjusting **CKA_ID**.

**p11importdata**(1)
:   Import an arbitrary file as a data object on the token.

**p11importpubk**(1)
:   Import a PEM/DER public key into the token; adjusts **CKA_ID** according
    to IBM JCA rules.

**p11init**(1)
:   Initialize a token and/or its user PIN, or reset an existing token.

**p11kcv**(1)
:   Compute a key check value (KCV) of a symmetric key.

**p11keygen**(1)
:   Generate a key or key pair on the token; optionally wrap the freshly
    generated key under one or more wrapping keys without ever storing the
    cleartext key material outside the token.

**p11ls**(1)
:   List token contents, grouped by object class.

**p11mkcert**(1)
:   Generate a self-signed certificate suitable for Java JCA keystores.

**p11more**(1)
:   Display the decoded, human-readable content of a certificate or public key.

**p11mv**(1)
:   Rename (move) a token object or a class of objects.

**p11od**(1)
:   Object dumper — print every attribute of a token object in hexadecimal.

**p11req**(1)
:   Generate a PKCS#10 certificate signing request.

**p11rewrap**(1)
:   Unwrap a key from a wrapped-key file and immediately re-wrap it under one
    or more wrapping keys, without permanently storing the key on the token.

**p11rm**(1)
:   Delete a token object or a class of objects.

**p11setattr**(1)
:   Set or change attributes of a token object.

**p11slotinfo**(1)
:   Print slot and token information; list supported mechanisms with their
    operations and key-size ranges.

**p11unwrap**(1)
:   Unwrap (import) a key from a wrapped-key file produced by **p11wrap**(1)
    or **p11keygen**(1).

**p11wrap**(1)
:   Wrap (export) an extractable key from the token, writing the encrypted
    blob in the **pkcs11-wrap**(5) file format.

**masqreq**(1)
:   Adjust the subject DN and extensions of an existing PKCS#10 CSR without
    re-signing it.

## Common options

The following options are accepted by almost every command:

**-l** *pkcs11library*
:   Path to the PKCS#11 shared library to load.  Mandatory unless
    **PKCS11LIB** is set or the command is invoked through a wrapper script
    (see **with_pkcs11_common**(1)).

**-m** *nssconfigdir*
:   NSS database directory (e.g. `.` or `sql:.`), required when the library
    is Mozilla NSS **libsoftokn3**.  May be prefixed with `sql:` for
    SQLite-style databases.  Overrides **PKCS11NSSDIR**.

**-s** *slotindex*
:   Slot *index* (0-based integer as returned by the library, not the slot
    number reported by the token).  Overrides **PKCS11SLOT**.

**-t** *tokenlabel*
:   Token label.  When both **-s** and **-t** are given, **-t** takes
    precedence.  Overrides **PKCS11TOKENLABEL**.

**-p** *pin* | **:::exec:***command* | **:::nologin**
:   Token PIN, a subprocess command that returns a PIN, or `:::nologin` to
    access only public objects without calling **C_Login()**.
    Overrides **PKCS11PASSWORD**.

**-S**
:   Login with Security Officer (SO) privilege.

**-n**
:   Allow creation of objects with duplicate labels (only when the toolkit
    is compiled with `--enable-duplicate`).

**-h**
:   Print a usage summary and exit.

**-V**
:   Print version information and exit.

## Slot and token selection

Specify the target slot either by its index (**-s**) or by the token label
(**-t**).  Environment variables **PKCS11SLOT** and **PKCS11TOKENLABEL** are
the non-interactive equivalents.  When neither is given the command enters
interactive mode (see below).

Caution: the slot index is the ordinal position in the list returned by
the library — it is *not* the slot ID printed in that list.

## Interactive mode

When no slot index or token label is provided (and neither **PKCS11SLOT** nor
**PKCS11TOKENLABEL** is set), the command prints the list of available slots and
prompts the user to choose one.  PIN entry is then also performed interactively
with echo disabled.

## PIN handling

**Direct value**
:   Pass the PIN directly: `-p mypin`.

**Subprocess command**
:   Prefix the command with `:::exec:` (use single quotes to suppress variable
    expansion, or double quotes to allow it):

        p11ls -s 1 -p :::exec:'getpin -label my-pin'

    The subprocess must print the PIN on its standard output.

**No login**
:   Use `:::nologin` to access only public objects without calling
    **C_Login()**.  Applicable to commands that can operate on public
    objects only (e.g. **p11cat**(1), **p11ls**(1)).

## NSS specifics

NSS requires a non-standard argument to **C_Initialize** that specifies the
location of its key and certificate databases.  Pass this path with **-m**
(command line) or via **PKCS11NSSDIR** (environment).  Both forms accept an
optional `sql:` prefix for SQLite-style databases (`key4.db`, `cert9.db`,
`pkcs11.txt`).  The wrapper **with_nss** also forwards **NSS_LIB_PARAMS** to
the underlying command; the `configDir=` field of **NSS_LIB_PARAMS** is used
only as a fallback when **PKCS11NSSDIR** is unset.

Slot 0 is the NSS internal slot; user objects normally reside on slot 1, which
is the default for **with_nss**.

## Library auto-detection

Each wrapper script knows its vendor library filename and a list of
vendor-specific search directories.  When the library is not found there, the
following common directories are searched in order:

- `/usr/lib` and `/usr/lib/pkcs11`
- `/usr/lib64` and `/usr/lib64/pkcs11` (Linux only)
- `/usr/lib/<arch>-linux-gnu` and its `pkcs11` subdirectory (Linux only)
- `/usr/local/lib` and `/usr/local/lib/pkcs11`
- `$HOME/.local/lib`
- `$HOMEBREW_PREFIX/lib` and `$HOMEBREW_PREFIX/lib/pkcs11` (when
  **HOMEBREW_PREFIX** is set)

Auto-detection is always overridden by setting **PKCS11LIB** to an explicit
path.

On macOS the wrappers look for `.dylib` libraries; SoftHSM2 is an exception
and keeps the `.so` extension on all platforms (it is a libtool module).

## Addressing objects

A token object is addressed as *class*/*label*, where *class* is one of:

`pubk`
:   Public key (`CKO_PUBLIC_KEY`)

`prvk`
:   Private key (`CKO_PRIVATE_KEY`)

`seck`
:   Secret key (`CKO_SECRET_KEY`)

`cert`
:   Certificate (`CKO_CERTIFICATE`)

`data`
:   Data object (`CKO_DATA`)

For example: `pubk/my-rsa-key`, `seck/aes-wrapping-key`.

When an object has no **CKA_LABEL**, its **CKA_ID** is used and the address
takes the form *class*`/id/{`*hexstring*`}`, e.g.:

    prvk/id/{39363231313338383739}

An additional attribute filter can be appended with `+`:

    p11ls cert/sn/12335344+CKA_ENCRYPT={01}

## CKA_ID conventions

The toolkit sets **CKA_ID** on newly created key objects according to the
following rules (mirroring IBM JCA / Sun PKCS#11 provider conventions):

`RSA`
:   SHA-1 of the public modulus (**CKA_MODULUS**)

`DSA` or `DH`
:   SHA-1 of the public key value (**CKA_VALUE**)

`EC / ECDSA`
:   SHA-1 of the DER-encoded EC point in uncompressed form (**CKA_EC_POINT**)

## PKCS#11 attribute syntax

Several commands (**p11keygen**, **p11importpubk**, **p11setattr**, **p11unwrap**)
accept a list of PKCS#11 attributes on the command line.

Attribute names are case-insensitive.  The `CKA_` prefix may be omitted
(`LABEL` and `CKA_LABEL` are equivalent).  Multiple attributes are separated
by whitespace and/or commas.

**Boolean values** — any of: `true`, `false`, `yes`, `no`, `on`, `off`,
`CK_TRUE`, `CK_FALSE`.  A bare attribute name is `true`; prefixing with `no`
or `!` is `false`.

**String values** — enclosed in double quotes: `"my label"`.

**Hexadecimal values** — even-length hex string prefixed with `0x`:
`0xabcdef12`.

**Date values** — eight-digit string in `YYYYMMDD` format: `20250101`.

**Mechanism values** — the PKCS#11 mechanism name beginning with `CKM_`:
`CKM_RSA_PKCS_OAEP`.

**Mechanism arrays** — a space/comma-separated list of mechanism names in
curly braces: `{ CKM_AES_CBC, CKM_AES_GCM }`.

**Attribute arrays** (for template attributes such as **CKA_UNWRAP_TEMPLATE**,
**CKA_WRAP_TEMPLATE**, **CKA_DERIVE_TEMPLATE**, **CKA_ENCAPSULATE_TEMPLATE**,
**CKA_DECAPSULATE_TEMPLATE**) — a space/comma-separated list of attribute
assignments in curly braces: `{ sensitive !extractable }`.

Example:

    encrypt decrypt=true sign=on verify=off wrap, no unwrap, \
    unwrap_template = { not extractable, sign }

## Environment variables

**PKCS11LIB**
:   Path to the PKCS#11 shared library.  Overridden by **-l**.

**PKCS11NSSDIR**
:   NSS database directory.  Overridden by **-m**.

**PKCS11SLOT**
:   Slot index.  Overridden by **PKCS11TOKENLABEL**, **-t**, or **-s**.

**PKCS11TOKENLABEL**
:   Token label.  Overridden by **-t**.

**PKCS11PASSWORD**
:   Token PIN.  Overridden by **-p**.

## Exit status

**0**
:   Success.

**4**
:   Memory allocation failure.

**5**
:   PKCS#11 library could not be loaded.

**6**
:   Invalid command-line option.

**7**
:   Error reading input.

**8**
:   Invalid usage (missing or conflicting arguments).

**9**
:   Invalid handle.

**10**
:   Object already exists on the token.

**11**
:   PKCS#11 API error (the token returned a non-**CKR_OK** status).

**12**
:   Key generation failed.

**13**
:   Object not found on the token.

Any other non-zero value indicates an unclassified error.

## Vendor-specific limitations

### AWS CloudHSM

AWS CloudHSM support is disabled by default (`--with-awscloudhsm` configure
option).  When enabled:

- Certificates are not supported; all certificate-handling commands will fail.
- Changing attribute values is not supported; commands that adjust **CKA_ID**
  may report an error, although key material is usually still created.
- **p11mv**(1) and **p11setattr**(1) do not work on this platform.
- Duplicate **CKA_ID** attributes are not allowed, which can cause occasional
  errors during key generation.
- **p11od**(1) does not work due to the way CloudHSM handles attribute
  enumeration.
- Wrap and unwrap templates are not supported; they must be commented out in
  wrapped-key files before unwrapping.

### Yubico (YubiHSM 2)

Yubico support is enabled by default when `include/cryptoki/yubico.h` is
present (`--without-yubico` configure option to disable).  The vendor key
types **CKK_YUBICO_AES128_CCM_WRAP**, **CKK_YUBICO_AES192_CCM_WRAP** and
**CKK_YUBICO_AES256_CCM_WRAP** are recognized.  Limitations:

- CCM-wrap keys cannot be generated with **p11keygen**(1).  Use the native
  `yubihsm-shell` tool to create them; the toolkit can inspect them
  (**p11ls**, **p11od**, **p11cat**) and reference their key type in templates.
- **p11wrap**(1), **p11unwrap**(1) and **p11rewrap**(1) do not support the
  Yubico **CKM_YUBICO_AES_CCM_WRAP** mechanism, which exports an opaque
  whole-object container incompatible with the toolkit's attribute-template
  wrapping model.

# FILES

*$HOME*`/.pkcs11rc`
:   Default location for the configuration file read by the wrapper scripts.
    See **pkcs11rc**(5) for syntax and search order.

# SEE ALSO

**pkcs11rc**(5), **pkcs11-wrap**(5), **with_pkcs11_common**(1),
**p11cat**(1), **p11importcert**(1), **p11importdata**(1),
**p11importpubk**(1), **p11init**(1), **p11kcv**(1), **p11keygen**(1),
**p11ls**(1), **p11mkcert**(1), **p11more**(1), **p11mv**(1), **p11od**(1),
**p11req**(1), **p11rewrap**(1), **p11rm**(1), **p11setattr**(1),
**p11slotinfo**(1), **p11unwrap**(1), **p11wrap**(1), **masqreq**(1)

# AUTHOR

Mastercard, and the pkcs11-tools contributors.
