% P11MKCERT(1) | pkcs11-tools

# NAME

p11mkcert - generate a self-signed X.509 certificate using a key on a PKCS#11 token

# SYNOPSIS

**p11mkcert**
\[**-l** *pkcs11library*]
\[**-m** *nssconfigdir*]
\[**-s** *slotindex* | **-t** *tokenlabel*]
\[**-p** *pin* | **:::exec:***command* | **:::nologin**]
**-i** *label*
**-d** *subjectdn*
\[**-r**]
\[**-u** *days*]
\[**-j**]
\[**-o** *outfile*]
\[**-a** *sigalgo*]
\[**-H** *hashalgo*]
\[**-e** *sanfield* ...]
\[**-X**]
\[**-v**]
\[**-n**]
\[**-h**]
\[**-V**]
\[*ATTRIBUTE*=*VALUE* ...]

# DESCRIPTION

**p11mkcert** generates and outputs a self-signed X.509 certificate using a
private key stored on a PKCS#11 token. The certificate is written to standard
output or to a file in PEM format, and can optionally be imported back onto the
token (**-j**).

The primary use case is Java JCA code-signing platforms and other scenarios
that require a certificate paired with a hardware-protected private key. The
private key must have **CKA_SIGN** set to `true`, unless the fake-signing mode
(**-F** from **p11req**(1) is not available here; for self-signed certs the
signing is always real) is not applicable here — signing is always performed.

The Subject DN must be specified in strict OpenSSL format, beginning with a
leading `/` character. By default the DN components are written in
human-readable order (CN first) and **p11mkcert** reverses them to the binary
DER order required by X.509. To supply the DN already in binary order, use
**-r**.

Post-quantum key types (ML-DSA, SLH-DSA) are supported when the toolkit is
built with post-quantum support (**--enable-pqc**, the default) and linked
against OpenSSL >= 3.5.0.

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
    value `:::nologin` skips login entirely. Overrides **PKCS11PASSWORD**.

**-i** *label*
:   Label (alias) of the private key to use for signing. Mandatory.

**-d** *subjectdn*
:   Subject Distinguished Name in strict OpenSSL format, e.g.
    `/CN=mysite.net/O=My Org/C=BE`. Mandatory. By default the components are
    listed in human order (leftmost attribute becomes innermost RDN); use
    **-r** to supply them already in binary (DER) order.

**-r**
:   Interpret the Subject DN (**-d**) in reverse (binary DER) order.

**-u** *days*
:   Certificate validity period in days. Default: 365.

**-j**
:   Import the generated certificate back onto the PKCS#11 token after
    creation. The **CKA_ID** is adjusted to match IBM PKCS#11 JCE rules.

**-o** *outfile*
:   Write the certificate to *outfile* instead of standard output.

**-a** *sigalgo*
:   Signature algorithm, for RSA keys:

    `pkcs1` | `pkcs`
    :   PKCS#1 v1.5 RSA signature (default; insecure and deprecated for new
        deployments).

    `pss`
    :   RSA-PSS signature.

**-H** *hashalgo*
:   Hash algorithm to use. Accepted values: `sha1` (or `sha`), `sha224`,
    `sha256` (or `sha2`), `sha384`, `sha512`. Default: `sha256`.

**-e** *sanfield*
:   Subject Alternative Name extension field. May be repeated. Accepted
    prefixes:

    `DNS:`*hostname* — DNS name.

    `email:`*address* — RFC 822 e-mail address.

    `IP:`*address* — IPv4 address.

**-X**
:   Add Subject Key Identifier and Authority Key Identifier X.509v3
    extensions. The value is the SHA-1 hash of the key modulus (or equivalent
    for non-RSA keys).

**-v**
:   Verbose output: print the decoded content of the generated certificate to
    standard output.

**-n**
:   Allow creation of duplicate objects (a certificate with the same label
    already on the token). Only available when the toolkit is built with
    **--enable-duplicates**.

**-h**
:   Print usage information and exit.

**-V**
:   Print version information and exit.

# ARGUMENTS

Zero or more *ATTRIBUTE=VALUE* pairs may be given as positional arguments after
all options to override attributes set on the imported certificate object (when
**-j** is used). See **p11keygen**(1) for the attribute syntax.

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

Generate a self-signed certificate for key `test-rsa-2048` with SHA-256:

    p11mkcert -l /usr/lib/softhsm/libsofthsm2.so -t "my token" \
        -p changeit \
        -i test-rsa-2048 \
        -d '/CN=test/OU=my dept/C=BE' \
        -H sha256 \
        -e DNS:anotherhost.int \
        -e email:writeme@example.com

Generate a certificate valid for 3 years and import it back onto the token:

    p11mkcert -l /usr/lib/softhsm/libsofthsm2.so -t "my token" \
        -p changeit \
        -i my-rsa-key \
        -d '/CN=server.example.com/O=Example/C=US' \
        -u 1095 -j -o server.crt

Generate a self-signed certificate using RSA-PSS and write it to a file:

    p11mkcert -l /usr/lib/softhsm/libsofthsm2.so -t "my token" \
        -p changeit \
        -i my-rsa-key \
        -d '/CN=pss.example.com/C=US' \
        -a pss -H sha384 -o pss-cert.pem

# SEE ALSO

**pkcs11-tools**(7), **pkcs11rc**(5), **p11req**(1), **p11importcert**(1),
**p11keygen**(1), **masqreq**(1), **p11slotinfo**(1)

# AUTHOR

Mastercard, and the pkcs11-tools contributors.
