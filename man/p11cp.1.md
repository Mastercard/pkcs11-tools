% P11CP(1) | pkcs11-tools

# NAME

p11cp - copy a PKCS#11 token object under a new label

# SYNOPSIS

**p11cp**
\[**-l** *pkcs11library*]
\[**-m** *nssconfigdir*]
\[**-s** *slotindex* | **-t** *tokenlabel*]
\[**-p** *password* | **:::exec:***command* | **:::nologin**]
\[**-S**]
\[**-y**]
\[**-v**]
\[**-n**]
\[**-h**]
\[**-V**]
*SOURCE* *DESTINATION*

# DESCRIPTION

**p11cp** copies a PKCS#11 token object, creating a new object with the label
given by *DESTINATION* and the same attributes as the source object. The source
object is not modified.

If *SOURCE* is not prefixed with an object-class qualifier (`cert/`, `prvk/`,
`pubk/`, `seck/`, or `data/`), all objects on the token that share the given
label are copied, one per class.

The command is interactive by default: when a matching source object is found,
the user is asked to confirm before the copy is made. Use **-y** to suppress
confirmation prompts.

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

**-S**
:   Login with security officer (SO) privilege instead of user privilege.

**-y**
:   Force positive answer to all confirmation prompts (non-interactive mode).

**-v**
:   Verbose output.

**-n**
:   Allow creation of duplicate objects (objects with the same label and class
    as an existing object). Only available when the toolkit is built with
    `--enable-duplicate`.

**-h**
:   Print usage information and exit.

**-V**
:   Print version information and exit.

# ARGUMENTS

*SOURCE*
:   The label of the object to copy. May be prefixed with `cert/`, `prvk/`,
    `pubk/`, `seck/`, or `data/` to restrict the copy to a single object
    class. When no prefix is given, all objects sharing the label are copied.

*DESTINATION*
:   The new label to assign to the copied object(s).

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

Copy all objects labelled `wrapperkey` to a new label `wrapperkey-backup`,
confirming each copy interactively:

    p11cp wrapperkey wrapperkey-backup

Copy only the secret key named `aes-key` to `aes-key-copy`, without prompting:

    p11cp -y seck/aes-key aes-key-copy

Copy using a token label instead of a slot index:

    p11cp -t "my token" -y cert/server-cert server-cert-old

# SEE ALSO

**pkcs11-tools**(7), **pkcs11rc**(5), **p11ls**(1), **p11mv**(1),
**p11rm**(1), **p11setattr**(1)

# AUTHOR

Mastercard, and the pkcs11-tools contributors.
