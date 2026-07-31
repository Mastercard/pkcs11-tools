% P11KEYCOMP(1) | pkcs11-tools

# NAME

p11keycomp - import a symmetric key from split key components onto a PKCS#11 token

# SYNOPSIS

**p11keycomp**
\[**-l** *pkcs11library*]
\[**-m** *nssconfigdir*]
\[**-s** *slotindex* | **-t** *tokenlabel*]
\[**-p** *password* | **:::exec:***command* | **:::nologin**]
**-i** *keylabel*
**-c** *numcomponents*
**-w** *wrappingkeylabel*
\[**-S**]
\[**-n**]
\[**-h**]
\[**-V**]

# DESCRIPTION

**p11keycomp** imports a symmetric (AES) key onto a PKCS#11 token by
XOR-combining a number of key components entered interactively at the terminal.
This process mirrors the classic dual-control key-ceremony procedure in which
no single custodian knows the full key value.

The command proceeds as follows for each component (from 1 to *numcomponents*):

1. The screen is cleared.
2. A caution message is displayed, reminding the operator of the security
   implications of entering key material on a terminal.
3. The operator is prompted to enter the component in hexadecimal (`HEX>`).
4. The component is XOR-ed into the running key value inside the process.
5. After each input, the component buffer is overwritten three times before
   it is freed.

After all components have been entered, the assembled key is wrapped under the
RSA key pair identified by *wrappingkeylabel* and injected into the token as a
non-extractable token object labelled *keylabel*.

**WARNING**: because key components are typed in the clear on a terminal
console, the security of the ceremony depends on appropriate surrounding
procedural controls. When in doubt, press **Ctrl+C** at the prompt to cancel.

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

**-i** *keylabel*
:   Label (alias) to assign to the imported key on the token. Mandatory.

**-c** *numcomponents*
:   Number of key components to collect. Each component is entered
    interactively as a hexadecimal string. Mandatory.

**-w** *wrappingkeylabel*
:   Label of the RSA key pair on the token that will be used to wrap the
    assembled key before injecting it. Mandatory.

**-S**
:   Login with security officer (SO) privilege instead of user privilege.

**-n**
:   Allow creation of a duplicate object (an object with the same label and
    class as an existing token object). Only available when the toolkit is
    built with `--enable-duplicate`.

**-h**
:   Print usage information and exit.

**-V**
:   Print version information and exit.

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

Import an AES-128 key from three components, wrapped under an RSA key pair
named `rsa-wrapping-key`, storing the result as `imported-aes-key`:

    p11keycomp -l /usr/lib/softhsm/libsofthsm2.so -s 0 \
        -i imported-aes-key -c 3 -w rsa-wrapping-key

Same operation addressed by token label, with PIN supplied via helper:

    p11keycomp -t "ceremony token" -p ":::exec:get-pin" \
        -i imported-aes-key -c 2 -w rsa-wrapping-key

# SEE ALSO

**pkcs11-tools**(7), **pkcs11rc**(5), **pkcs11-wrap**(5), **p11ls**(1),
**p11keygen**(1), **p11od**(1)

# AUTHOR

Mastercard, and the pkcs11-tools contributors.
