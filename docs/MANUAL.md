# Introduction
## Motivations for this project
Cryptographic tokens (smart cards, HSMs, software crypto libraries) implementing the [PKCS\#11 standard](https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=pkcs11) have taken an increasingly important place in daily key management, for various reasons:
-   Virtually all HSM and smart card vendors support this interface
-   Software libraries, such a [SoftHSM](https://www.opendnssec.org/softhsm/) supports it; [NSS](https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS) also exposes a PKCS\#11 interface, although it requires specific API call to initialize
-   Java platforms ([IBM](https://www.ibm.com/support/knowledgecenter/SSYKE2_8.0.0/com.ibm.java.security.component.80.doc/security-component/pkcs11implDocs/ibmpkcs11.html) and [Oracle](https://docs.oracle.com/en/java/javase/11/security/pkcs11-reference-guide1.html)) both support, through JCE providers, access to PKCS\#11-protected keys and certificates
-   It is also widely supported in many other languages and platforms (C++, Python, Rust, Ruby, ...)

However, these implementations suffers from several issues:
-   Although the specification is quite comprehensive, some aspects are not mandated. For example, there is no direction upon how to define a label, or an ID attribute accross related objects such as public and private keys, and certificates;
-   JVMs from Sun and IBM are using these differences to implement keys and certificates that are not easily interoperable

Moreover, setting up a JVM for using PKCS\#11 keys and certs is cumbersome. Also, the setup is different, depending on the intent: for key management, some attributes must be tweaked to generate keys properly, that you don't necessarily want to keep on a production system.

Finally, HSM vendors provides tools to deal with PKCS\#11 tokens, but they are proprietary and not interoperable.

For these reasons, this toolkit was created in order to bring the following functionalities:
-   basic key management primitives
-   support for certificate management (generation of CSR, import of certificates)
-   support different OS ( Linux, BSD, Solaris, AIX, Windows)
-   Generate key pairs and certificates in a fashion that makes them interoperable between IBM and Sun JVM
-   Whenever possible, "unix"-like style commands
-   support for advanced key management techniques (key exchange among tokens via key wrapping)


## CKA\_ID common value
The `CKA_ID` attribute being central in the way how some JVMs are managing their keystore, its value is set according to the rules below:
-   If the key is of type RSA, `CKA_ID` is the SHA-1 of the public modulus (stored in `CKA_MODULUS` attribute)
-   If the key is of type DSA or DH, `CKA_ID` is the SHA-1 of the public key (stored in `CKA_VALUE` attribute)
-   if the key is of type EC/ECDSA, `CKA_ID` is the SHA-1 of the curve point, uncompressed, in its octet-string representation (stored in `CKA_EC_POINT` attribute)

 |Key type   |`CKA_ID` is the sha-1 of                                                       |
 |-----------|-------------------------------------------------------------------------------|
 |RSA        |The public key modulus stored in `CKA_MODULUS`                                 |
 |DSA or DH  |The public key stored in `CKA_VALUE`                                           |
 |EC/ECDSA   |The curve point in its `OCTET-STRING` representation stored in `CKA_EC_POINT`  |

## List of commands
The following commands are supported:

|command name    |description                                                                       |
|----------------|----------------------------------------------------------------------------------|
|`p11cat`        |prints out in PEM format the content of a certificate or public key               |
|`p11more`       |prints out, in human-readable format, the content of a certificate or public key  |
|`p11keygen`     |generates a key, and optionally wrap it under one or several wrapping key(s)      |
|`p11kcv`        |computes a key check value                                                        |
|`p11od`         |object dumper, dumps all attributes of an object                                  |
|`p11setattr`    |sets attribute of an object                                                       |
|`p11importcert` |imports a certificate and binds it accordingly with key pair if any               |
|`p11importpubk` |imports a public key                                                              |
|`p11importdata` |imports a data file                                                               |
|`p11ls`         |lists token contents                                                              |
|`p11req`        |generate CSR                                                                      |
|`p11slotinfo`   |prints slot information, including mechanisms                                     |
|`p11mv`         |"moves" (i.e. renames) object                                                     |
|`p11rm`         |deletes  an object                                                                |
|`p11wrap`       |wraps a key using one or several wrapping key(s)                                  |
|`p11unwrap`     |unwraps a key using another key                                                   |
|`p11rewrap`     |unwraps a key, and wrap it again under one or several wrapping key(s)             |
|`masqreq`       |tunes a CSR to adjust DN and other fields (without re-signing)                    |

## common arguments
The following arguments are common to almost every command:
* `-l <pkcs#11 library path>` allows to specify a path to the PKCS\#11 library to use
* `-m <NSS config dir>` ( e.g. `'.'` or `'sql:.'` ) is used to locate the NSS db directory, for NSS keystores, see [below](#working-with-nss-library) for more details.
* `-s <slot number>` specifies the slot index number, starting from `0`. Caution: this is NOT the slot number itself!
* `-t <token label>` speficies the token label. If both a slot index and a token label are specified, the token label takes precedence.
* `-p <token PIN | :::exec:<command> | :::nologin >` specified the password used to access the token, see [below](#fetching-password-from-a-subprocess) for more details. Optionally, a command to execute can be specified when prefixed with `:::exec:`; to use token public objects only, (i.e. without invoking `C_Login()`) use `:::nologin` value. See [below](#accessing-public-objects) for
* `-S` will login to the token with Security Officer privilege
* `-h` will print usage information
* `-V` will print version information

## Interfacing with NSS tokens
NSS has a comprehensive set of mechanisms implemented in software, and given certain conditions, its keystores can be turned into FIPS 140-2 level 2 containers. However, there is one API call that is not compliant with the PKCS\#11 standard, it's the call to `C_Initialize`. NSS requires to use a supplementary member in the structure passed as an argument, to contain (amongst other things) the location of the NSS database.
In order to use NSS library, there are two ways to specify where to find the key and cert databases
-   either set the `PKCS11NSSDIR` environment variable
-   or use the `-m` argument.

The argument value contains the path to the directory where the NSS database is located (where you will find `key3.db`, `cert8.db` and `secmod.db`); It can be prefixed with `sql:` if you are using SQLite-style NSS database (`key4.db`, `cert9.db` and `pkcs11.txt`)

## Interactive mode
If not token label or slot index number is specified, then the utility will present a list of slots with token information and ask to choose one. Then password entry will happen interactively.

## Accessing public objects
It is possible, for certain commands, to proceed without login in against the token, e.g. to access only public objects. To do so, use `-p` parameter with `:::nologin`

## Fetching password from a subprocess
It is possible to specify a command to execute to retrieve the password. Use `-p` parameter with `:::exec:` followed by the command to launch, between simple or double quotes (use simple quotes to avoid variable expansion on the quoted expression, and double quotes to allow it). This enables to interface with a vault, to prevent storing the password in a script or in an environment variable.

```
$ p11ls -s 1 -p :::exec:\"getpassword -label password-label\"
```
## Environment variables
Each command can be invoked without the need of any environment variable. However, it can be cumbersome, as all token information must be passed as arguments. To ease the pain, a few environment variables can be specified:

| environemt variable | argument equivalent | usage                      |
|---------------------|---------------------|----------------------------|
| `PKCS11LIB`         | `-l`                | path to PKCS\#11 library   |
| `PKCS11NSSDIR`      | `-m`                | NSS configuration location |
| `PKCS11SLOT`        | `-s`                | slot index                 |
| `PKCS11TOKENLABEL`  | `-t`                | token label                |
| `PKCS11PASSWORD`    | `-p`                | password                   |

Environment variables obbey to the same syntax as the corresponding arguments. Note that any argument present in the command line will override the corresponding environment variable.

## Addressing objects
When an object has a label value, it is represented as `[object_class]/[label]`, where:
-   `[object_class]` can be one of `pubk`, `prvk`, `seck`, `cert`, `data`
-   `[label]` is the value of the `CKA_LABEL` attribute

e.g.: `pubk/my-public-key-label`

When an object does not have a label value, then the `CKA_ID` attribute is used, and it is listed as `[object_class]/id/{[hex-string-of-CKA_ID-value]}`

e.g.: `prvk/id/{39363231313338383739}`

## Commands accepting PKCS\#11 attributes
Some commands accept attributes. These attributes can be entered in different ways:
- using the formal name; e.g. `CKA_LABEL`
- this name is not case-sensitive, `cka_label` is also valid
- the prefix `CKA_` can be removed, for convenience. `label` is therefore a valid token.
- for attributes accepting a boolean value, the following tokens are accepted: `CK_TRUE`, `CK_FALSE`, `true`, `false`, `yes`, `no`

# Commands details
## p11slotinfo
This command provides basic information about slots and tokens connected to a library.
SLot and token features and flags are described, and all lechanisms are listed, together with their allowed mechanism family.

The following table lists the meaning of abbreviations:

 |abbreviation|capability meaning          |
 |------------|----------------------------|
 |`enc`       |Encryption                  |
 |`dec`       |Decryption                  |
 |`hsh`       |Hashing                     |
 |`sig`       |Signature                   |
 |`sir`       |Signature with recovery     |
 |`vfy`       |Verification                |
 |`vre`       |Verification with recovery  |
 |`gen`       |Key generation              |
 |`gkp`       |Key pair generation         |
 |`wra`       |Wrapping                    |
 |`unw`       |Unwrapping                  |
 |`der`       |Derivation                  |

Moreover, the last column indicates if the operation takes place inside the module (`HW`) or at the library level (`SW`).

Finally, for mechanisms supporting elliptic curve cryptography, there are additional capabilities printed:
 |abbreviation|capability meaning                              |
 |------------|------------------------------------------------|
 |`F^p`       |Supports curves defined over prime-based fields |
 |`F^2m`      |Supports curves defined over power of 2 fields  |
 |`par`       |Supports custom parameters curves               |
 |`nam`       |Supports well-known named curves                |
 |`unc`       |Supports compressed points representation       |
 |`cmp`       |Supports compressed points representation       |

Here is an example of `p11slotinfo` executed with SoftHSMv2:
```
$ p11slotinfo -l /usr/local/opt/softhsm/lib/softhsm/libsofthsm2.so -s 0
Slot[0]
-------------
Slot Number : 1575777370
Description : SoftHSM slot ID 0x5dec745a
Manufacturer: SoftHSM project
Slot Flags  : [ CKF_TOKEN_PRESENT ]

Token
-------------
Label       : sofhsm-token-1
Manufacturer: SoftHSM project

Token Flags : [ CKF_RNG CKF_LOGIN_REQUIRED CKF_USER_PIN_INITIALIZED CKF_RESTORE_KEY_NOT_NEEDED CKF_TOKEN_INITIALIZED ]

Mechanisms:
-----------
CKM_MD5                                   --- --- hsh --- --- --- --- --- --- --- --- --- SW (00000210)
CKM_SHA_1                                 --- --- hsh --- --- --- --- --- --- --- --- --- SW (00000220)
CKM_SHA224                                --- --- hsh --- --- --- --- --- --- --- --- --- SW (00000255)
CKM_SHA256                                --- --- hsh --- --- --- --- --- --- --- --- --- SW (00000250)
CKM_SHA384                                --- --- hsh --- --- --- --- --- --- --- --- --- SW (00000260)
CKM_SHA512                                --- --- hsh --- --- --- --- --- --- --- --- --- SW (00000270)
CKM_MD5_HMAC                              --- --- --- sig --- vfy --- --- --- --- --- --- SW (00000211)
CKM_SHA_1_HMAC                            --- --- --- sig --- vfy --- --- --- --- --- --- SW (00000221)
CKM_SHA224_HMAC                           --- --- --- sig --- vfy --- --- --- --- --- --- SW (00000256)
CKM_SHA256_HMAC                           --- --- --- sig --- vfy --- --- --- --- --- --- SW (00000251)
CKM_SHA384_HMAC                           --- --- --- sig --- vfy --- --- --- --- --- --- SW (00000261)
CKM_SHA512_HMAC                           --- --- --- sig --- vfy --- --- --- --- --- --- SW (00000271)
CKM_RSA_PKCS_KEY_PAIR_GEN                 --- --- --- --- --- --- --- --- gkp --- --- --- SW (00000000)
CKM_RSA_PKCS                              enc dec --- sig --- vfy --- --- --- wra unw --- SW (00000001)
CKM_RSA_X_509                             enc dec --- sig --- vfy --- --- --- --- --- --- SW (00000003)
CKM_MD5_RSA_PKCS                          --- --- --- sig --- vfy --- --- --- --- --- --- SW (00000005)
CKM_SHA1_RSA_PKCS                         --- --- --- sig --- vfy --- --- --- --- --- --- SW (00000006)
CKM_RSA_PKCS_OAEP                         enc dec --- --- --- --- --- --- --- wra unw --- SW (00000009)
CKM_SHA224_RSA_PKCS                       --- --- --- sig --- vfy --- --- --- --- --- --- SW (00000046)
CKM_SHA256_RSA_PKCS                       --- --- --- sig --- vfy --- --- --- --- --- --- SW (00000040)
CKM_SHA384_RSA_PKCS                       --- --- --- sig --- vfy --- --- --- --- --- --- SW (00000041)
CKM_SHA512_RSA_PKCS                       --- --- --- sig --- vfy --- --- --- --- --- --- SW (00000042)
CKM_RSA_PKCS_PSS                          --- --- --- sig --- vfy --- --- --- --- --- --- SW (0000000d)
CKM_SHA1_RSA_PKCS_PSS                     --- --- --- sig --- vfy --- --- --- --- --- --- SW (0000000e)
CKM_SHA224_RSA_PKCS_PSS                   --- --- --- sig --- vfy --- --- --- --- --- --- SW (00000047)
CKM_SHA256_RSA_PKCS_PSS                   --- --- --- sig --- vfy --- --- --- --- --- --- SW (00000043)
CKM_SHA384_RSA_PKCS_PSS                   --- --- --- sig --- vfy --- --- --- --- --- --- SW (00000044)
CKM_SHA512_RSA_PKCS_PSS                   --- --- --- sig --- vfy --- --- --- --- --- --- SW (00000045)
CKM_GENERIC_SECRET_KEY_GEN                --- --- --- --- --- --- --- gen --- --- --- --- SW (00000350)
CKM_DES_KEY_GEN                           --- --- --- --- --- --- --- gen --- --- --- --- SW (00000120)
CKM_DES2_KEY_GEN                          --- --- --- --- --- --- --- gen --- --- --- --- SW (00000130)
CKM_DES3_KEY_GEN                          --- --- --- --- --- --- --- gen --- --- --- --- SW (00000131)
CKM_DES_ECB                               enc dec --- --- --- --- --- --- --- --- --- --- SW (00000121)
CKM_DES_CBC                               enc dec --- --- --- --- --- --- --- --- --- --- SW (00000122)
CKM_DES_CBC_PAD                           enc dec --- --- --- --- --- --- --- --- --- --- SW (00000125)
CKM_DES_ECB_ENCRYPT_DATA                  --- --- --- --- --- --- --- --- --- --- --- der SW (00001100)
CKM_DES_CBC_ENCRYPT_DATA                  --- --- --- --- --- --- --- --- --- --- --- der SW (00001101)
CKM_DES3_ECB                              enc dec --- --- --- --- --- --- --- --- --- --- SW (00000132)
CKM_DES3_CBC                              enc dec --- --- --- --- --- --- --- --- --- --- SW (00000133)
CKM_DES3_CBC_PAD                          enc dec --- --- --- --- --- --- --- --- --- --- SW (00000136)
CKM_DES3_ECB_ENCRYPT_DATA                 --- --- --- --- --- --- --- --- --- --- --- der SW (00001102)
CKM_DES3_CBC_ENCRYPT_DATA                 --- --- --- --- --- --- --- --- --- --- --- der SW (00001103)
CKM_DES3_CMAC                             --- --- --- sig --- vfy --- --- --- --- --- --- SW (00000138)
CKM_AES_KEY_GEN                           --- --- --- --- --- --- --- gen --- --- --- --- SW (00001080)
CKM_AES_ECB                               enc dec --- --- --- --- --- --- --- --- --- --- SW (00001081)
CKM_AES_CBC                               enc dec --- --- --- --- --- --- --- --- --- --- SW (00001082)
CKM_AES_CBC_PAD                           enc dec --- --- --- --- --- --- --- --- --- --- SW (00001085)
CKM_AES_CTR                               enc dec --- --- --- --- --- --- --- --- --- --- SW (00001086)
CKM_AES_GCM                               enc dec --- --- --- --- --- --- --- --- --- --- SW (00001087)
CKM_AES_KEY_WRAP                          --- --- --- --- --- --- --- --- --- wra unw --- SW (00002109)
CKM_AES_KEY_WRAP_PAD                      --- --- --- --- --- --- --- --- --- wra unw --- SW (0000210a)
CKM_AES_ECB_ENCRYPT_DATA                  --- --- --- --- --- --- --- --- --- --- --- der SW (00001104)
CKM_AES_CBC_ENCRYPT_DATA                  --- --- --- --- --- --- --- --- --- --- --- der SW (00001105)
CKM_AES_CMAC                              --- --- --- sig --- vfy --- --- --- --- --- --- SW (0000108a)
CKM_DSA_PARAMETER_GEN                     --- --- --- --- --- --- --- gen --- --- --- --- SW (00002000)
CKM_DSA_KEY_PAIR_GEN                      --- --- --- --- --- --- --- --- gkp --- --- --- SW (00000010)
CKM_DSA                                   --- --- --- sig --- vfy --- --- --- --- --- --- SW (00000011)
CKM_DSA_SHA1                              --- --- --- sig --- vfy --- --- --- --- --- --- SW (00000012)
CKM_DSA_SHA224                            --- --- --- sig --- vfy --- --- --- --- --- --- SW (00000013)
CKM_DSA_SHA256                            --- --- --- sig --- vfy --- --- --- --- --- --- SW (00000014)
CKM_DSA_SHA384                            --- --- --- sig --- vfy --- --- --- --- --- --- SW (00000015)
CKM_DSA_SHA512                            --- --- --- sig --- vfy --- --- --- --- --- --- SW (00000016)
CKM_DH_PKCS_KEY_PAIR_GEN                  --- --- --- --- --- --- --- --- gkp --- --- --- SW (00000020)
CKM_DH_PKCS_PARAMETER_GEN                 --- --- --- --- --- --- --- gen --- --- --- --- SW (00002001)
CKM_DH_PKCS_DERIVE                        --- --- --- --- --- --- --- --- --- --- --- der SW (00000021)
CKM_ECDSA_KEY_PAIR_GEN                    --- --- --- --- --- --- --- --- gkp --- --- --- SW (00001040) ec: F^p --- --- nam unc ---
CKM_ECDSA                                 --- --- --- sig --- vfy --- --- --- --- --- --- SW (00001041) ec: F^p --- --- nam unc ---
CKM_ECDH1_DERIVE                          --- --- --- --- --- --- --- --- --- --- --- der SW (00001050)
```

## p11ls
This command allows to list the content of a token. Objects are grouped by type (certificates, secret keys, public keys, private keys). If a label is found, it is printed, otherwise the `CKA_ID` attribute is printed between brackets.

It is also possible to filter through an object identifier, or a part of it.
e.g. the following command will list all secret keys:
```bash
$ p11ls seck/
```

For each object, a quick list of attributes is displayed. The following table lists the meaning of these abbreviations:

 |abbreviation  |capability meaning                                          |
 |--------------|------------------------------------------------------------|
 |    `tok`     |object is on token (always true)                            |
 |    `pub`     |object is public                                            |
 |    `prv`     |object is private                                           |
 |    `r/o`     |object is read only                                         |
 |    `r/w`     |object is writable (modifiable)                             |
 |    `tru`     |object is trusted (`CKA_TRUST` attribute is true)           |
 |    `wtt`     |object can be wrapped with another trusted key              |
 |    `loc`     |object has been created locally                             |
 |    `imp`     |object has been imported                                    |
 |    `enc`     |object can be used for encryption                           |
 |    `dec`     |object can be used for decryption                           |
 |    `sig`     |object can be used for signature                            |
 |    `sir`     |object can be used for signature with recovery              |
 |    `vfy`     |object can be used for signature verification               |
 |    `vre`     |object can be used for signature verification with recovery |
 |    `wra`     |object can be used for key wrapping                         |
 |    `unw`     |object can be used for key unwrapping                       |
 |    `der`     |object can be used for key derivation                       |
 |    `sen`     |object is sensitive                                         |
 |    `xtr`     |object is extractable                                       |
 |    `NXT`     |object has never been extractable                           |
 |    `ASE`     |object has always been sensitive                            |
 | `key(param)` |key algorithm and length or parameter                       |

Here is an example of execution:
```
$ p11ls
seck/aes-wrapping-key                 tok,prv,r/w,loc,wra,unw,sen,ase,XTR,WXT,aes(256)
prvk/rsa-2048                         tok,prv,r/w,imp,dec,sig,sen,NAS,XTR,WXT,rsa(2048)
pubk/rsa-overarching-wrapping-key     tok,pub,r/w,imp,enc,vfy,vre,wra,rsa(4096)
```
In the example above, three objects are found on the token:
 - a 256 bits AES secret key called `aes-wrapping-key` which is extractable - it can be wrapped - (`XTR`), and that can wrap (`wra`) and unwrap (`unw`) other keys. That key has been created locally (`loc`), and is a private object, i.e. requiring to login against the token, (`prv`).
 - an RSA 2048 bits private key called `rsa-2048`, which is also extractable (`XTR`), that can sign (`sig`) and decrypt (`dec`). the key has been imported to the token (`imp`); consequently, the historical attribute "was extractable" (`WXT`) is set.  Although the key is sensitive i.e. operated within the boundaries of the cryptographic token (`sen`), and since it has been imported, the token is setting the other historical attribute "not always sensitive" (`NAS`).
 - an RSA 4096 bits public key called `rsa-overarching-wrapping-key`, which is a public object, i.e. not requiring to login (`pub`). It is also imported (`imp`) and has the capability to wrap other keys (`wra`).
 ## p11cat
Given an object identifier, exctract the content in DER, base64 encoded format ( aka PEM format). The output of the command can be used to pipe in another command. Additionally, when used in conjuction with `-x` parameter on public keys, the output is tuned either to yield native format for RSA keys, and parameter files for DH, DSA, and EC keys.
-   if the object is a certificate, then the certificate value is exported
-   if the object is a public key, the public key value is exported
-   if the object is a secret or a private key, the commands refuses to execute
-   if the object is a data file, the raw content is exported

Here is an example of execution, yielding the public key in SPKI format:
```
$ p11cat rsa-overarching-wrapping-key
-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEApZ9zT82SQY9DSYfR+F/Q
cQInqDCP9V4PjyUvnM2NPMKdCY7k+QyFekkQK16vzmmd3A+ELrtORq8sarJ1DmgU
0moPIknqPRpBGUJQ1OtO/6+5Rdx+RQ8d9L2Y7LfXjea7KxsADItyvmRD9f/pZT9F
qbN5rJ16GNUrt68fqf+LYf9ZbCl5/VkFsNoprTSY7imX9GoTL6sYD9q4h3LXVYvd
x5H1TJqiNp6T0sWWUlHOkkGLWInC6XPYl+aXDUDRb0i6QFkUeg2XBbArSME3R041
XdTdoWsrTKXCKZ6Z/NWq3pF+zEnwFDs7vg/gsR6pzsnyyh9K+rDl7UletrIkNk30
7o4gjUWQbn3hnvcvkvJ0hRhuONsjbG4HFpLxyVOjjigV5KdS5cmBmo6fEPvdi8JC
vFe84UcrKbaD4RPVsUX6l+B7hov5f73ERPKZt995AFL0BCpZRG6O+k1Q4c9gAFiD
ALPVfqCdGe0piZ+jfK8iuuEBQQ5CVHTpG4XiQj19WiDRk/ipRtWlb79cbnzlPIhF
btRcjL2A7A+SAKmy/MMNnvE9PCqDiyfbQSuDT5HagGisXb9YR4FmibuzfgJEx9jG
pKLMScuEgFr5ZVP5fX2QAB7JU1tC3F6QVjppRh5/+4vzQZ2WK9FJI27On+B2y3io
FHXy65qiBpWndifnFmgOLBsCAwEAAQ==
-----END PUBLIC KEY-----
```

Another example demonstrates how to output the same key, in PKCS#1 format:
```
$ p11cat -x rsa-overarching-wrapping-key
-----BEGIN RSA PUBLIC KEY-----
MIICCgKCAgEApZ9zT82SQY9DSYfR+F/QcQInqDCP9V4PjyUvnM2NPMKdCY7k+QyF
ekkQK16vzmmd3A+ELrtORq8sarJ1DmgU0moPIknqPRpBGUJQ1OtO/6+5Rdx+RQ8d
9L2Y7LfXjea7KxsADItyvmRD9f/pZT9FqbN5rJ16GNUrt68fqf+LYf9ZbCl5/VkF
sNoprTSY7imX9GoTL6sYD9q4h3LXVYvdx5H1TJqiNp6T0sWWUlHOkkGLWInC6XPY
l+aXDUDRb0i6QFkUeg2XBbArSME3R041XdTdoWsrTKXCKZ6Z/NWq3pF+zEnwFDs7
vg/gsR6pzsnyyh9K+rDl7UletrIkNk307o4gjUWQbn3hnvcvkvJ0hRhuONsjbG4H
FpLxyVOjjigV5KdS5cmBmo6fEPvdi8JCvFe84UcrKbaD4RPVsUX6l+B7hov5f73E
RPKZt995AFL0BCpZRG6O+k1Q4c9gAFiDALPVfqCdGe0piZ+jfK8iuuEBQQ5CVHTp
G4XiQj19WiDRk/ipRtWlb79cbnzlPIhFbtRcjL2A7A+SAKmy/MMNnvE9PCqDiyfb
QSuDT5HagGisXb9YR4FmibuzfgJEx9jGpKLMScuEgFr5ZVP5fX2QAB7JU1tC3F6Q
VjppRh5/+4vzQZ2WK9FJI27On+B2y3ioFHXy65qiBpWndifnFmgOLBsCAwEAAQ==
-----END RSA PUBLIC KEY-----
```

## p11more
Exctract the content of an object and display it in human-readable format. The same result could be achieved by using `p11cat` and piping the output into the relevant `openssl` command.
Here is an example of such command output:
```
$ p11more cert/a-self-signed
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 2947579903 (0xafb07fff)
    Signature Algorithm: sha256WithRSAEncryption
        Issuer: CN=a self-signed cert
        Validity
            Not Before: Dec 21 08:26:20 2018 GMT
            Not After : Dec 21 08:26:20 2019 GMT
        Subject: CN=a self-signed cert
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    00:ca:54:86:ff:af:f1:b7:1d:01:78:3e:88:d4:6e:
                    4a:cf:1f:0b:e4:9d:06:2b:b4:08:bd:3e:fb:e2:53:
                    6b:05:8b:d9:03:00:48:47:fb:f2:06:62:b6:eb:d3:
                    5b:4b:de:61:fc:e9:6e:d6:ba:2d:8f:5d:c2:b8:8e:
                    d5:db:f4:b3:12:73:77:3e:dc:96:17:1a:15:f8:40:
                    e9:95:cb:d7:d8:28:74:b3:55:12:3e:5f:03:6c:a8:
                    59:aa:3f:0d:ba:30:65:16:44:2b:38:61:17:2b:d2:
                    d0:cb:94:35:4a:e3:c8:29:93:b1:67:6b:dd:75:9b:
                    09:41:52:50:af:c7:7b:4f:d7:97:f0:6f:37:5e:bc:
                    8a:b6:4b:39:7a:6c:f5:5c:61:56:0f:31:3f:fa:e2:
                    ca:f7:99:aa:3a:b7:c9:83:0a:a2:16:0c:28:bd:b5:
                    f4:75:9f:2c:37:d9:a4:6d:23:84:3d:34:9c:c1:28:
                    6a:40:6f:f4:e6:03:f6:f8:16:eb:72:66:45:5a:70:
                    1f:f3:c2:58:b2:67:08:a5:5e:95:c2:ee:c0:3b:37:
                    3d:cd:70:f7:cc:9b:75:5f:af:98:ba:e2:8c:c1:e2:
                    bd:a3:c8:8c:ba:37:de:f8:64:e4:9a:51:b9:88:e8:
                    60:4e:c9:6d:60:de:50:57:53:cb:91:0f:8f:bf:d2:
                    0f:a1
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature, Key Encipherment
    Signature Algorithm: sha256WithRSAEncryption
         9e:6d:41:66:1f:b0:2a:af:da:2d:28:1a:71:a4:05:e5:f1:00:
         06:ae:24:2e:65:60:d4:ec:8f:c6:f6:62:93:f5:f9:d9:f1:b4:
         be:99:21:87:96:b5:25:41:2c:6b:a6:8b:76:29:f0:ed:94:07:
         8d:ce:d2:c7:a2:28:a9:e9:b2:4b:5a:0d:ec:2b:99:80:6a:e8:
         68:59:3d:4c:fe:2e:ba:1d:e0:b7:5c:79:ff:75:e1:ed:db:38:
         be:ff:f7:ac:69:c8:75:79:57:f1:95:46:3c:65:ba:19:87:c7:
         11:58:89:b9:28:62:08:d9:40:f9:52:37:2f:9f:a8:eb:04:ae:
         28:1a:0f:76:02:44:db:a2:f6:82:40:60:5b:5b:1b:d9:fc:8e:
         74:db:9e:30:aa:01:2e:a2:e0:35:2c:c9:f8:4f:98:67:e2:6a:
         46:4e:41:a7:7b:6b:ac:d0:fc:93:7f:02:ff:b2:6a:29:56:d9:
         f4:6b:ae:d8:81:2a:aa:81:9e:ee:81:ed:6f:96:86:5e:91:2c:
         df:6a:5b:34:30:79:ad:31:ad:d6:80:2d:77:88:7d:2d:6b:33:
         1d:e5:a0:09:dd:8f:1d:7a:8d:9d:7c:81:b0:59:23:3f:0b:47:
         d9:9b:3d:b6:b7:bc:8f:f8:37:75:35:4c:46:e2:f0:78:81:96:
         ef:d0:84:17
```

## p11mv
given an object identifier, rename an object or a class of object. If no object class is given ( i.e. `pubk/`, `prvk/`, `cert/`, `seck/` or `data/`) then all objects of the class are renamed.

The tool is interactive by default: if a match is found, the user is requested to confirm the action. To force a non-interactive execution, use `-y` argument.

``` bash
$ p11mv wrapperkey other-wrapperkey
move prvk/wrapperkey to prvk/other-wrapperkey ? (y/N)y
move pubk/wrapperkey to pubk/other-wrapperkey ? (y/N)y
$
```
## p11rm
Given an object identifier, delete an object or a class of object. If no object class is given ( i.e. `pubk/`, `prvk/`, `cert/`, `seck/` or `data/`) then all objects of the class are removed.

The tool is interactive by default: if a match is found, the user is requested to confirm the action. To force a non-interactive execution, use `-y` argument.
```
$ p11rm other-wrapperkey
Delete prvk/other-wrapperkey ? (y/n, default n)n
Delete pubk/other-wrapperkey ? (y/n, default n)n
$
```

## p11od
Object Dumper. Given an object identifier, prints attributes and values of an object.
Example output:
```
$ p11od seck/aes-wrapping-key
seck/aes-wrapping-key:
 CKA_CLASS:
  0000  04 00 00 00 00 00 00 00                          CKO_SECRET_KEY
 CKA_TOKEN:
  0000  01                                               CK_TRUE
 CKA_PRIVATE:
  0000  01                                               CK_TRUE
 CKA_LABEL:
  0000  61 65 73 2d 77 72 61 70 70 69 6e 67 2d 6b 65 79  aes-wrapping-key
 CKA_TRUSTED:
  0000  00                                               CK_FALSE
 CKA_CHECK_VALUE:
  0000  82 f8 4f                                         ..O
 CKA_KEY_TYPE:
  0000  1f 00 00 00 00 00 00 00                          CKK_AES
 CKA_ID:
  0000  61 65 73 32 35 36 2d 31 35 38 34 39 36 38 31     aes256-15849681
 CKA_SENSITIVE:
  0000  01                                               CK_TRUE
 CKA_ENCRYPT:
  0000  00                                               CK_FALSE
 CKA_DECRYPT:
  0000  00                                               CK_FALSE
 CKA_WRAP:
  0000  01                                               CK_TRUE
 CKA_UNWRAP:
  0000  01                                               CK_TRUE
 CKA_SIGN:
  0000  00                                               CK_FALSE
 CKA_VERIFY:
  0000  00                                               CK_FALSE
 CKA_DERIVE:
  0000  00                                               CK_FALSE
 CKA_VALUE_LEN:
  0000  20 00 00 00 00 00 00 00                          32 (0x00000020)
 CKA_EXTRACTABLE:
  0000  01                                               CK_TRUE
 CKA_LOCAL:
  0000  01                                               CK_TRUE
 CKA_NEVER_EXTRACTABLE:
  0000  00                                               CK_FALSE
 CKA_ALWAYS_SENSITIVE:
  0000  01                                               CK_TRUE
 CKA_KEY_GEN_MECHANISM:
  0000  80 10 00 00 00 00 00 00                          CKM_AES_KEY_GEN
 CKA_MODIFIABLE:
  0000  01                                               CK_TRUE
 CKA_WRAP_WITH_TRUSTED:
  0000  00                                               CK_FALSE
```

## p11keygen
Generate a key or a key pair on a PKCS\#11 token, or generate and wrap under one or several key(s). There are multiple options, but the more important are:
-   `-i`: the label of the key
-   `-k`: the key algorithm: `rsa`, `ec`, `des`, `aes`, `generic`, `hmac` (`hmac` and `generic` are synonyms), `hmacsha1`, `hmacsha256`, `hmacsha384`, `hmacsha512` (these are nCipher-specific, and only available when the toolkit is compiled with nCipher extentions)
-   `-b`: the key length in bits / `-q`: curve parameter name for elliptic curve. Please check out `openssl ecparam -list_curves` for a list of supported curves (obviously, the PKCS\#11 token must support it).

Moreover, it is possible to specify attributes to set at key inception. This is very important as usually attributes cannot be enabled on a key once it has been disabled, so make sure to specify any required attribute here.

For key pairs, the tool will dispatch attributes pertaining to the relevant key (public or private).
For RSA key pairs, `CKA_ID` is adjusted to match IBM PKCS\#11 JCE algorithm (the value is the SHA-1 of the key modulus).

```
$ p11keygen -k rsa -b 2048 -i test-rsa-2048 CKA_ENCRYPT=true CKA_DECRYPT=true CKA_SIGN=true CKA_VERIFY=true
Generating, please wait... Key Generation succeeded
```

For HMAC key (excepting on nCipher HSMs), you need to specify `CKA_DERIVE=true`. The `-b` parameter specifies how many bits are used to generate the key. It is rounded up to the next byte boundary.

```
$ p11keygen -k generic -b 256 -i test-hmac-32-bytes CKA_DERIVE=true
Generating, please wait... Key Generation succeeded
```

For generating HMAC key on nCipher, you need to use one of the following key types: `hmacsha1`, `hmacsha256`, `hmacsha384`, `hmacsha512`; In addition, specify `CKA_SIGN=true` and `CKA_VERIFY=true`. The `-b` parameter specifies how many bits are used to generate the key. It is rounded up to the next byte boundary.

### creating wrapped keys
using `p11keygen`, it is possible to generate a session key and wrap it immediately under one or several wrapping keys. To achieve this, you simply need to add the `-W` optional parameter, followed by the wrapping parameters string, as explained in `p11wrap`. Note that the key will not be stored on the token.

## p11kcv
Computes the key check value of a symmetric key and prints it. This will work only on symmetric keys (`des` and `aes` keys).

## p11req
Generate a PKCS\#10 CSR. Important options are:

 - `-i`: the label of the key
 - `-d`: subject DN - Caution: must be specified in strict OpenSSL format, which is with a leading `/` character. In addition, the order in which the subject name is given is the binary layout, i.e. NOT inversed for human reading. If the CSR DN must comply with network order ( e.g. for inclusion of the certificate into an LDAP database), you MUST write it reversed, e.g. `/dc=com/dc=company/ou=whatever/cn=test cert`
- `-e` ( may be specified several times): SAN field. It is prefixed with `DNS:` for a DNS entry, `email:` for an email entry, and `IP:` for an IPv4 address.
- `-H` : hashing algorithm (`sha1`, `sha256`, \.... )
- `-X`: add a subject key identifier extension to the CSR.
- `-F`: do not perform signature. This can be useful in some case where the private key does not have `CKA_SIGN` property asserted, but where a CSR is yet required. The resulting signature is always invalid.
- `-v`: be verbose.
- `-o [filename]`: output to file

```
$ p11req -i test-rsa-2048 -d \'/CN=test/OU=my dept/C=BE\' -H sha256 -e DNS:anotherhost.int -e email:writeme\@mastercard.com
-----BEGIN CERTIFICATE REQUEST-----
MIICuDCCAaACAQAwLjENMAsGA1UEAxMEdGVzdDEQMA4GA1UECxMHbXkgZGVwdDEL
MAkGA1UEBhMCQkUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC1rk8d
pEgHBhdE4KDkkXm+I3RzbdGjYBLPxHdlam7uHw9dBJ3PVb6l0AU/W5i4dWAHQJAa
2W44F+fmQDblYrsefiGZ0r7xCQXxfndNp0K8rTQ0n0s5aSy5FALrAZwCg8OPbnGY
uesnuveOvzke7fwl8eTE6Dzh/l9imoFvUb9qZ9VbsBoqwfykCP3FQt08tx0smDnF
ev6rlH66WNIZoI+gKKCKUyD6jRn8l4F/vWT3GRwgnygryJgX/VroGH4HM62qBoUi
qDAl9cGPEL2gCmWriwOqGT5VhUG7xm2hsYxcJ8onKqdFNdysSlG3jKlmU+yOcTOs
osX7r88dbedkstEzAgMBAAGgRTBDBgkqhkiG9w0BCQ4xNjA0MDIGA1UdEQQrMCmC
D2Fub3RoZXJob3N0LmludIEWd3JpdGVtZUBtYXN0ZXJjYXJkLmNvbTANBgkqhkiG
9w0BAQsFAAOCAQEAVu3cB22+tUz/STVomGuKPvZ1r2/HgGwU/1IDBdmNKYDI35N2
ZKXMwIpUpQbbl0rIREHyl1e1WKenlBr8iyIsj0FGoMfdCbsHKhSzrLpaklzZe/4T
03Za/P7tR+niAdv6/PK/HIeSoaG4VH7TLvn8LSpHxGNUGqUgTW9KQJqaDd84++gB
B6TVns2ss550xD63V+/Uo6PDMaeMWtMkyzXq+9t4bt/cEdgjFkQWngqwJCZWFRg5
A1vF7h/OtbTavv5OQfnEQ5hOfVvJKiH+r2e1tUV3zqAuFZhRylFdfTZvVawNk4/I
dOaYPtY2vDku2as4Y5oj9g4Aht26yqNsYQFNKw==
-----END CERTIFICATE REQUEST-----
```

## p11importcert
This utility will load a PEM or DER formatted certificate and import it back. The`CKA_ID` attribute will be adjusted according to IBM rules.

If needed, the trust bit can be set ( using the `-T` option, in combination with the `-S` option).

```
$ p11importcert -f test.crt -i test-rsa-2048
PEM format detected
p11importcert: importing certificate succeeded.
```

## p11importpubk
Similarily to `p11importcert`, this utility will load a PEM or DER formatted public key and import it into the PKCS\#11 token. The `CKA_ID`
will be adjusted according to IBM rules.

```
$ p11importpubk -f test-public-rsa-key.rsa -i test-public-rsa-key
PEM format detected
p11importpubk: import of public key succeeded.
```

## p11importdata
Similarily to p11importcert, this utility will load an arbitrary file and import it into the PKCS\#11 token.

```
$ p11importdata -f hello.txt -i dummy_data
p11importdata: import of data succeeded.
```

## masqreq
Under certain circumstances, it is desirable to adapt an existing CSR, before submission to CA. A typical use case is CSR generated by an appliance where the structure of the DN is not flexible and must contain some fields that are otherwise rejected by the CA at
submission. This tool allows to adapt some of the features of a PKCS\#10 request. It does not sign the CSR however, and as such, the signature is invalid.

```
$ masqreq -c test.req -d'/CN=another CN'
-----BEGIN CERTIFICATE REQUEST-----
MIICWjCCAUICAQAwFTETMBEGA1UEAxMKYW5vdGhlciBDTjCCASIwDQYJKoZIhvcN
AQEBBQADggEPADCCAQoCggEBALWuTx2kSAcGF0TgoOSReb4jdHNt0aNgEs/Ed2Vq
bu4fD10Enc9VvqXQBT9bmLh1YAdAkBrZbjgX5+ZANuViux5+IZnSvvEJBfF+d02n
QrytNDSfSzlpLLkUAusBnAKDw49ucZi56ye6946/OR7t/CXx5MToPOH+X2KagW9R
v2pn1VuwGirB/KQI/cVC3Ty3HSyYOcV6/quUfrpY0hmgj6AooIpTIPqNGfyXgX+9
ZPcZHCCfKCvImBf9WugYfgczraoGhSKoMCX1wY8QvaAKZauLA6oZPlWFQbvGbaGx
jFwnyicqp0U13KxKUbeMqWZT7I5xM6yixfuvzx1t52Sy0TMCAwEAAaAAMA0GCSqG
SIb3DQEBBQUAA4IBAQAoxL4oxL4oxL4oxL4oxL4oxL4oxL4oxL4oxL4oxL4oxL4o
xL4oxL4oxL4oxL4oxL4oxL4oxL4oxL4oxL4oxL4oxL4oxL4oxL4oxL4oxL4oxL4o
xL4oxL4oxL4oxL4oxL4oxL4oxL4oxL4oxL4oxL4oxL4oxL4oxL4oxL4oxL4oxL4o
xL4oxL4oxL4oxL4oxL4oxL4oxL4oxL4oxL4oxL4oxL4oxL4oxL4oxL4oxL4oxL4o
xL4oxL4oxL4oxL4oxL4oxL4oxL4oxL4oxL4oxL4oxL4oxL4oxL4oxL4oxL4oxL4o
xL4oxL4oxL4oxL4oxL4oxL4oxL4oxL4oxL4oxL4o
-----END CERTIFICATE REQUEST-----
```

## p11wrap and p11unwrap
the commands `p11wrap` and `p11unwrap` can be used to respectively wrap and unwrap keys. Several algorithms are available, as described in the table below.

| `-a` argument | wrapping algorithm            | PKCS\#11 mechanism    | wrapping key | wrapped key                      | remark                        |
|---------------|-------------------------------|-----------------------|--------------|----------------------------------|-------------------------------|
| `pkcs1`       | PKCS#1 v1.5,  RFC8017         | `CKM_RSA_PKCS`        | RSA          | symmetric, secret(HMAC)          | considered insecure Today     |
| `oaep`        | OAEP, RFC8017                 | `CKM_RSA_PKCS_OAEP`   | RSA          | symmetric, secret(HMAC)          | default                       |
| `cbcpad`      | CBC mode, with PKCS#7 padding | `CKM_AES_CBC_PAD`     | AES          | any key type                     | widely supported              |
|               |                               | `CKM_DES_CBC_PAD`     | DES          | any key type                     |                               |
| `rfc3394`     | RFC3394, NIST SP.800.38F      | `CKM_AES_KEY_WRAP`    | AES          | any key type, aligned on 8 bytes | useful for symmetric keys     |
| `rfc5649`     | RFC5649, NIST SP.800.38F      | `CKM_AES_KEY_WRAP_PAD`| AES          | any key type                     |                               |
| `envelope`    | combines `pkcs1` or `oaep`    |                       | RSA/AES      | any key type                     | allows to wrap any key using  |
|               | with `cbcpad`, `rfc3394` or   |                       |              |                                  | a top level RSA key           |
|               | `rfc5649`                     |                       |              |                                  |                               |

To wrap a key, you will need:
 - a wrapping key, that must have `CKA_WRAP` attribute set
 - a key to wrap, that must have `CKA_EXTRACTABLE` attribute set

### p11wrap syntax
you must at least provide:
 - `-w`, the label of the wrapping key
 - `-i`, the label of the key to wrap

By default, the wrapping algorithm is set to `oaep`. You can change this with the `-a` argument:
 - `-a pkcs1` will choose PKCS#1 1.5 wrapping algorithm. It is considered insecure and should be avoided.
 - `-a oaep` or `-a oaep(args...)` will choose PKCS#1 OAEP (RFC3447).
   `args...` can be one or several of the following parameters, separated by commas:
   * `label="label-value"` - OAEP label or source argument, default is empty
   * `mgf=CKG_MGF1_SHA1|CKG_MGF1_SHA256|CKG_MGF_SHA384|CKG_MGF_SHA512` - MGF parameter, default is `CKG_MGF1_SHA1`
   * `hash=CKM_SHA_1|CKM_SHA224|CKM_SHA256|CKM_SHA384|CKM_SHA512` - hashing alg. argument, default is `CKM_SHA_1`

 - `-a cbcpad` or `-a cbcpad(args...)` : private and secret key wrapping (using CKM_xxx_CBC_PAD wrapping mehanisms)
    `args...` can be one or several of the following parameters (separated by commas)
    * `iv=[HEX STRING prefixed with 0x]` - Initialisation vector, please refer to PKCS#11 `CKM_AES_CBC_PAD` description for more details.
 - `-a rfc3394`: private and secret key wrapping, as documented in RFC3394 and NIST.SP.800-38F, using `CKM_AES_KEY_WRAP` mechanism or equivalent vendor-specific
 - `-a rfc5649`: private and secret key wrapping, as documented in RFC5649 and NIST.SP.800-38F, using `CKM_AES_KEY_WRAP_PAD` mechanism or equivalent vendor-specific
 - `-a envelope`: private an secret key wrapping, using the envelope wrapping technique (see envelope wrapping below)

Alternatively, it is possible to specify one or more key/wrapping algorithm/output filename using `-W` optional and repeatable parameter.
The syntax is `-W 'wrappingkey="<wrappingkeylabel>"[,algorithm=<algorithm>[,filename="<path>"]]'`, with:
 - `"<wrappingkeylabel>"` is the name of a valid wrapping key on the token (i.e. that has `CKA_WRAP`). Caution: it must be surrounded with double quotes.
 - `<algorithm>` is a valid wrapping algorithm, as specified above
 - `"<path>"` is a valid path to a filename; when specified, the wrapped key is written to that file, instead of standard output. Caution: it must be surrounded with double quotes.

#### envelope wrapping
It is possible to combine private key and symmetric key wrapping together, to allow wrapping any key material, given a single private key. To do this, use `-a envelope` or `-a envelope(args...)`; `args...` can be one or several of the following parameters (separated by commas)
    * `inner=<algorithm>`: specifies the algorithm that wraps the target key. It must be one of `cbcpad`, `rfc3394` or `rfc5649`. In turn, algorithms can be specified with their own set of parameters. If not specified, default is `cbcpad`.
	* `outer=<algorithm>`: specifies the algoritom that wraps the inner key, using the specified wrapping key. It must be one of `pkcs1` or `oaep`. If not speficied, default is `oaep`.

### p11unwrap syntax
you must at least provide:
 - `-f`, the path to a wrapping key file produced by `p11wrap`

In addition, PKCS#11 attributes can be specified, that will override attributes from the wrapping key file.

## p11rewrap
This command is actually a combination of `p11unwrap` and `p11wrap`, but is not storing the unwrapped key permanently. This way keys can be rewrapped to one or several public key(s).
The syntax of this command is similar to `p11unwrap`; in addition, rewrapping jobs can be specified using the `-W` repeatable parameter (see `p11wrap` syntax for more details).

---
## exchanging a keys between tokens - the long way

In order to exchange all kinds of keys between tokens, you must first exchange a symmetric key (typically AES), which implies this symmetric key to be itself exchanged, typically using an assymetric key.

The following diagram depicts the different steps to execute to establish a key exchange channel between two tokens:

```
+--+ DEST TOKEN +----------------+     +--+ SOURCE TOKEN +------------+
|                                |     |                              |
|  1. generate RSA key pair      |     |                              |
|     that can wrap              |     |                              |
|     (p11keygen)                |     |                              |
|                                |     |                              |
|  2. export public key  +--------------->  3. import public key      |
|     (p11cat)                   |     |       (p11importpubk)        |
|                                |     |                              |
|                                |     |    4. generate AES           |
|                                |     |       extractable key        |
|                                |     |       (p11keygen)            |
|                                |     |                              |
|  6. unwrap AES key     <---------------+  5. wrap AES key           |
|     using private key          |     |       using public key       |
|     (p11unwrap)                |     |       (p11wrap)              |
|                                |     |                              |
|                                |     |    7. remove extractable     |
|                                |     |       on AES key             |
|                                |     |       (p11setattr)           |
|                                |     |                              |
|                                |     |    8. generate key to share  |
|                                |     |       (extractable)          |
|                                |     |                              |
|  10. unwrap generated key <------------+  9. wrap generated key     |
|      using AES key             |     |       under AES key          |
|      (p11unwrap)               |     |                              |
|                                |     |   11. remove extractable     |
|                                |     |       on generated key       |
|                                |     |                              |
|                                |     |                              |
|                                |     |                              |
+--------------------------------+     +------------------------------+
```

Steps from the figure are explained here below:

1. On the destination token, an RSA key pair can be generated e.g. using the following command:
`p11keygen -k rsa -b 4096 -i rsa-wrapping-key CKA_WRAP=true CKA_UNWRAP=true`
2. On the destination token, the freshly created public key can be extracted as follows:
`p11cat pubk/rsa-wrapping-key >rsa-wrapping-key.pubk`
3. On the source token, the public key can be imported using:
`p11importpubk -f rsa-wrapping-key.pubk -i rsa-wrapping-key`
4. On the source token, generate an AES key that will be used to wrap keys from source token:
`p11keygen -k aes -b 256 -i aes-wrapping-key CKA_WRAP=true CKA_UNWRAP=true CKA_EXTRACTABLE=true`
5. On the source token, wrap that AES key:
`p11wrap -a oaep -i aes-wrapping-key -w rsa-wrapping-key -o aes-wrapping-key.wrap`
6. On the destination token, unwrap that AES key:
`p11unwrap -f aes-wrapping-key.wrap`
7. On the source token, flip the extractable attribute back to false:
`p11setattr seck/aes-wrapping-key CKA_EXTRACTABLE=false`

Once the AES key has been established on both tokens, it can be used to wrap and exchange any other extractable key (irrespective of key type) from both tokens, using `-a cbcpad`, `-a rfc3394` and `-a rfc5649` argument to specify algorithm (see remarks in table [above](#p11wrap-and-p11unwrap) for each algorithm):
8. On the source token, generate a key (using `p11keygen`)
9. On the source token, wrap that key under the AES key
10. On the destination token, unwrap that key
11. On the source token, remove the extractable bit.

While this procedure works, it is cumbersome and insecure to some degrees, as keys created on the token are extractable for a while.

## exchanging keys between tokens - the accelerated way
All the steps above can be executed in a simpler and more secure fashion, that leverages the PKCS\#11 capability to create session keys, accessible only to the calling process.

1. On the destination token, generate an RSA key pair e.g. using the following command:
`p11keygen -k rsa -b 4096 -i rsa-dest-wrapping-key CKA_WRAP=true CKA_UNWRAP=true`
2. Similarly, On the source token, generate an RSA key pair e.g. using the following command:
`p11keygen -k rsa -b 4096 -i rsa-source-wrapping-key CKA_WRAP=true CKA_UNWRAP=true`
3. On the destination token, the freshly created public key can be extracted as follows:
`p11cat pubk/rsa-dest-wrapping-key >rsa-dest-wrapping-key.pubk`
4. On the source token, the public key can be imported using:
`p11importpubk -f rsa-wrapping-dest-key.pubk -i rsa-dest-wrapping-key`
5. On the source token, generate and wrap to both wrapping keys (using `p11keygen` with `-W` parameter)
`p11keygen -k aes -b 128 -i business-key -W 'algorithm=envelope,wrappingkey="rsa-dest-wrapping-key",filename="business-key-for-dest-token.wrap" -W 'algorithm=envelope,wrappingkey="rsa-source-wrapping-key",filename="business-key-for-source-token.wrap"' encrypt=yes decrypt=yes`
6. On the destination token, unwrap the key
`p11unwrap -f business-key-for-dest-token.wrap`
7. On the source token, unwrap the key
`p11unwrap -f business-key-for-source-token.wrap`

```
+--+ DEST TOKEN +--------------+      +---+ SOURCE TOKEN +---------------+
|                              |      |                                  |
|  1. generate RSA key pair    |      |     2. generate RSA key pair     |
|     that can wrap            |      |        that can wrap             |
|     (p11keygen)              |      |        (p11keygen)               |
|                              |      |                                  |
|  3. export public key  +--------------->  4. import public key         |
|     (p11cat)                 |      |        (p11importpubk)           |
|                              |      |                                  |
|  6. unwrap key               |      |     5. generate key to share     |
|     (p11unwrap)        <----------------+    and wrap it under         |
|                              |      |        RSA key pair, using       |
|                              |      |        envelope algorithm        |
|                              |      |                                  |
|                              |      |     7. unwrap key                |
|                              |      |        (p11unwrap)               |
|                              |      |                                  |
+------------------------------+      +----------------------------------+
```
