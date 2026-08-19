% P11RM(1) | pkcs11-tools

# NAME

p11rm - delete objects from a PKCS#11 token

# SYNOPSIS

**p11rm**
\[**-l** *pkcs11library*]
\[**-m** *nssconfigdir*]
\[**-s** *slotindex* | **-t** *tokenlabel*]
\[**-p** *password* | **:::exec:***command* | **:::nologin**]
\[**-S**]
\[**-y**]
\[**-v**]
\[**-h**]
\[**-V**]
*LABEL* \[*LABEL* ...]

# DESCRIPTION

**p11rm** deletes one or more objects from a PKCS#11 token. Each *LABEL*
argument identifies the object(s) to remove.

If *LABEL* is not prefixed with an object-class qualifier (`cert/`, `prvk/`,
`pubk/`, `seck/`, or `data/`), all objects on the token that share the given
label are deleted, one per class.

The command is interactive by default: when a matching object is found, the
user is asked to confirm before deletion. Use **-y** to suppress confirmation
prompts and delete without asking.

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

**-h**
:   Print usage information and exit.

**-V**
:   Print version information and exit.

# ARGUMENTS

*LABEL*
:   One or more object labels to delete. Each label may be prefixed with
    `cert/`, `prvk/`, `pubk/`, `seck/`, or `data/` to restrict deletion to a
    single object class. When no prefix is given, all objects sharing the label
    are deleted. The label may also address an object by its **CKA_ID** using
    the `id/` prefix, e.g. `prvk/id/{deadbeef}`.

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

Delete all objects labelled `other-wrapperkey`, confirming each deletion:

    p11rm other-wrapperkey
    Delete prvk/other-wrapperkey ? (y/n, default n)n
    Delete pubk/other-wrapperkey ? (y/n, default n)n

Delete only the secret key named `aes-key` without prompting:

    p11rm -y seck/aes-key

Delete multiple objects by label in one invocation:

    p11rm -y cert/old-cert pubk/old-cert prvk/old-cert

# SEE ALSO

**pkcs11-tools**(7), **pkcs11rc**(5), **p11ls**(1), **p11mv**(1),
**p11cp**(1), **p11setattr**(1)

# AUTHOR

Mastercard, and the pkcs11-tools contributors.
