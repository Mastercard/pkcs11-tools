% P11SLOTINFO(1) | pkcs11-tools

# NAME

p11slotinfo - print slot information and available mechanisms of a PKCS#11 slot or token

# SYNOPSIS

**p11slotinfo**
\[**-l** *pkcs11library*]
\[**-m** *nssconfigdir*]
\[**-s** *slotindex* | **-t** *tokenlabel*]
\[**-S**]
\[**-e**]
\[**-L**]
\[**-h**]
\[**-V**]

# DESCRIPTION

**p11slotinfo** connects to a PKCS#11 library and prints, for the selected slot,
the slot description, the token information (label, manufacturer, model, serial
number, flags) and the complete list of mechanisms supported by the token,
together with the operations each mechanism can be used for (encrypt, decrypt,
sign, verify, wrap, unwrap, derive, digest, key generation) and the supported
key sizes.

It is the recommended first command to run against a new token: it tells which
algorithms are actually usable, and therefore which options of **p11keygen**(1),
**p11wrap**(1) or **p11req**(1) will succeed.

When neither **-s** nor **-t** is given, and no corresponding environment
variable is set, the command enters interactive mode and offers the list of
available slots for selection. See **pkcs11-tools**(7).

# OPTIONS

**-l** *pkcs11library*
:   Path to the PKCS#11 library (shared object or DLL) to use. Mandatory,
    unless the **PKCS11LIB** environment variable is set, or unless the command
    is invoked through one of the wrapper scripts, see
    **with_pkcs11_common**(1).

**-m** *nssconfigdir*
:   NSS configuration directory, when the library is an NSS softoken. The
    directory can be prefixed with `sql:` for SQLite-style databases.
    Overrides **PKCS11NSSDIR**.

**-s** *slotindex*
:   Slot index (an integer) of the token to address. Overrides **PKCS11SLOT**.

**-t** *tokenlabel*
:   Label of the token to address. When present, **-s** is ignored. Overrides
    **PKCS11TOKENLABEL**.

**-S**
:   Login with security officer (SO) privilege instead of user privilege.

**-e**
:   Also list the named elliptic curves supported by the token. This requires
    querying the token for every curve known to the toolkit, and can be slow on
    some devices.

**-L**
:   List all slots that contain a token, in a terse, parsable form. This mode
    is primarily used by the bash and zsh completion scripts.

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

A complete description of the environment variables shared by all commands of
the toolkit is given in **pkcs11-tools**(7).

# EXIT STATUS

**0**
:   Success.

Any non-zero value indicates an error; see **pkcs11-tools**(7) for the meaning
of the exit codes.

# EXAMPLES

Print information for the token in slot 1 of a SoftHSM library:

    p11slotinfo -l /usr/lib/softhsm/libsofthsm2.so -s 1

Same, using the wrapper script and an environment variable:

    with_softhsm p11slotinfo -s 1

List the mechanisms and the named elliptic curves of a token addressed by
label:

    p11slotinfo -t "my token" -e

List all slots carrying a token:

    p11slotinfo -L

# SEE ALSO

**pkcs11-tools**(7), **pkcs11rc**(5), **p11ls**(1), **p11keygen**(1),
**with_pkcs11_common**(1)

# AUTHOR

Mastercard, and the pkcs11-tools contributors.
