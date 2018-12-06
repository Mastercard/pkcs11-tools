# Introduction
## Motivations for this project
PKCS\#11 cryptographic tokens have increasingly taken place in our daily
key management, for various reasons:
-   Virtually all HSM and smart card vendors support this interface
-   NSS also expose a PKCS\#11 interface, although it requires specific API call to initialize
-   Java platforms (IBM & Sun) both support, through JCE providers, access to PKCS\#11-protected keys and certificates

However, the interface suffers from several issues:
-   Although the specification is quite comprehensive, some aspects are not mandated. For example, there is no direction upon how to define a label, or an ID attribute
-   JVMs from Sun and IBM are using these differences to implement keys and certificates that are not easily interoperable

Moreover, setting up a JVM for using PKCS\#11 keys and certs is cumbersome. Also, the setup is different, depending on the intent: for key management, some attributes must be tweaked to generate keys properly, that you don't necessarily want to keep on a production system.

Finally, HSM vendors provides tools to deal with PKCS\#11 tokens, but they are proprietary and not interoperable.

For these reasons, this toolkit was created in order to bring the following functionalities:

-   basic key management primitives
-   support different OS ( Linux, Solaris, AIX, Windows)
-   Generate key pairs and certificates in a fashion that makes them interoperable between IBM and Sun JVM
-   Whenever possible, "unix"-like commands style


## CKA\_ID algorithm
CKA\_ID value is set according to the rules below:
-   If the key is of type RSA, CKA\_ID is the SHA-1 of the public modulus (stored in CKA\_MODULUS attribute)
-   If the key is of type DSA or DH, CKA\_ID is the SHA-1 of the public key (stored in CKA\_VALUE attribute)
-   if the key is of type EC/ECDSA, CKA\_ID is the SHA-1 of the curve point, uncompressed, in its octet-string representation (stored in
    CKA\_EC\_POINT attribute)

 |Key type   |CKA\_ID is the sha-1 of                            |
 |-----------|---------------------------------------------------|
 |RSA        |The public key modulus stored in CKA\_MODULUS      |
 |DSA or DH  |The public key stored in CKA\_VALUE                |
 |EC/ECDSA   |The curve point in its OCTET-STRING representation stored in CKA\_EC\_POINT  |

## List of commands:
The following commands are supported:

|command name          |description                                                                       |
|----------------------|----------------------------------------------------------------------------------|
|```p11cat```          |prints out in PEM format the content of a certificate or public key               |
|```p11more```         |prints out, in human-readable format, the content of a certificate or public key  |
|```p11keygen```       |generates key                                                                     |
|```p11kcv```          |Computes a key check value                                                        |
|```p11od```           |object dumper, dumps all attributes of an object                                  |
|```p11setattr```      |set attribute of an object                                                        |
|```p11importcert```   |import certificate and binds it accordingly with key pair if any                  |
|```p11importpubk```   |import of a standalone public key                                                 |
|```p11importdata```   |import a data file                                                                |
|```p11ls```           |list content of a token                                                           |
|```p11req```          |generate CSR                                                                      |
|```p11slotinfo```     |print slot information, including mechanisms                                      |
|```p11mv```           |"move" (i.e. rename) object                                                       |
|```p11rm```           |delete object                                                                     |
|```masqreq```         |tune a CSR to adjust DN and other fields (without re-signing)                     |
|```p11wrap```         |Wrap a key using another key                                                      |
|```p11unwrap```       |Unwrap a key using another key                                                    |

## Environment setup
Each command can be invoked without the need of any environment variable. However, it can be cumbersome, as all token information must be passed as arguments. To ease the pain, a few environment variables can be specified:

-  ```PKCS11LIB``` : path to PKCS\#11 library
-  ```PKCS11NSSDIR``` : NSS configuration directory directive. This is for use with an NSS token, since it requires a supplementary initialization parameter. That parameter is in the form of ```[PATH]``` (key3/cert8 format) or ```sql:[PATH]``` (key4/cert9 format), and is containing the path to the NSS database.
-  ```PKCS11SLOT``` : token slot (integer), in which case the working token is at given slot index
-  ```PKCS11TOKENLABEL``` : token label, in which case the working token will be searched by name
-  ```PKCS11PASSWORD``` : password ( can be also ```:::nologin``` or ```:::exec:[PATH TO EXECUTABLE]``` )

Any Optional argument in conflict with these environment variables overrides them.

## Working with NSS library
In order to use NSS library, there are two ways to specify where to find the key and cert databases
-   either set the ```PKCS11NSSDIR``` environment variable
-   or use the ```-m``` argument.

##Interactive mode
If not token or slot is specified, then the utility will present a list of slots with token information and ask to choose one. Then password entry will happen interactively.

##Do not login
It is possible, for certain commands, to proceed without login in against the token, e.g. to access only public objects. Use ```-p``` parameter with ```:::nologin```

## Use external password utility
Similarily, It is possible to specify a command to execute to retrieve the password. Use ```-p``` parameter with ```:::exec:``` followed by the command to launch, between simple or double quotes (use simple quotes to avoid variable expansion on the quoted expression, and double quotes to allow it).

```bash
$ p11ls -s 1 -p :::exec:\"getpassword -label password-label\"
```

## Addressing objects
When an object has a label value, it is represented as ```[object_class]/[label]```, where:
-   ```[object_class]``` can be one of ```pubk```, ```prvk```, ```seck```, ```cert```, ```data```
-   ```[label]``` is the value of the ```CKA_LABEL``` attribute

e.g.: ```pubk/my-public-key-label```

When an object does not have a label value, then the ```CKA_ID``` attribute is used, and it is listed as ```[object_class]/id/{[hex-string-of-CKA_ID-value]}```

e.g.: ```prvk/id/{39363231313338383739}```

Help
----
For all commands, the ```-h``` option prints out a short usage summary. 

Current limitations
-------------------
-   copy command missing
-   p11keycomp needs more rework to support more key types, other platforms than NSS, etc\...

# Commands overview
## p11slotinfo
This command provides basic information about slots and tokens connected to a library. Mechanisms are listed, together with their allowed use.

The following table lists the meaning of abbreviations:

 |abbreviation  |capability meaning          |
 |--------------|----------------------------|
 |```enc```           |Encryption                  |
 |```dec```           |Decryption                  |
 |```hsh```           |Hashing                     |
 |```sig```           |Signature                   |
 |```sir```           |Signature with recovery     |
 |```vfy```           |Verification                |
 |```vre```           |Verification with recovery  |
 |```gen```           |key generation              |
 |```gkp```           |key pair generation         |
 |```wra```           |Wrapping                    |
 |```unw```           |Unwrapping                  |
 |```der```           |Derivation                  |

Moreover, the last column indicates if the operation takes place inside the module (```HW```) or at the library level (```SW```).

## p11ls
This command allows to list the content of a token. Objects are grouped by type (certificates, secret keys, public keys, private keys). If a label is found, it is printed, otherwise the ```CKA_ID``` attribute is printed between brackets.

It is also possible to filter through an object identifier, or a part of it.
e.g. the following command will list all secret keys:
```bash
$ p11ls seck/
```

For each object, a quick list of attributes is displayed. The following table lists the meaning of these abbreviations:

 |abbreviation  |capability meaning                                          |
 |--------------|------------------------------------------------------------|
 |```tok```     |object is on token (always true) |
 |```pub```     |object is public |
 |```prv```     |object is private |
 |```r/o```     |object is read only |
 |```r/w```     |object is writable (modifiable) |
 |```tru```     |object is trusted (CKA\_TRUST attribute is true) |
 |```wtt```     |object can be wrapped with another trusted key |
 |```loc```     |object has been created locally |
 |```imp```     |object has been imported |
 |```enc```     |object can be used for encryption |
 |```dec```     |object can be used for decryption |
 |```sig```     |object can be used for signature |
 |```sir```     |object can be used for signature with recovery |
 |```vfy```     |object can be used for signature verification |
 |```vre```     |object can be used for signature verification with recovery |
 |```wra```     |object can be used for key wrapping |
 |```unw```     |object can be used for key unwrapping |
 |```der```     |object can be used for key derivation |
 |```sen```     |object is sensitive |
 |```xtr```     |object is extractable |
 |```NXT```     |object has never been extractable |
 |```ASE```     |object has always been sensitive |
 |```key(param)``` |key algorithm and length or parameter |

## p11cat
Given an object identifier, exctract the content in DER, base64 encoded format ( aka PEM format). The output of the command can be used to pipe in another command. Additionally, when used in conjuction with ```-x``` parameter on public keys, the output is tuned either to yield native format for RSA keys, and parameter files for DH, DSA, and EC keys.
-   if the object is a certificate, then the certificate value is exported
-   if the object is a public or a private key, the public key is exported.
-   if the object is a secret or a private key, the commands refuses to execute
-   if the object is a data file, the raw content is outpout.

## p11more
Exctract the content of an object and display it in human-readable format. The same result could be achieved by using p11cat and piping the output into the relevant openssl command.

## p11mv
given an object identifier, rename an object or a class of object. If no object class is given ( i.e. ```pubk/```, ```prvk/```, ```cert/```, ```seck/``` or ```data/```) then all objects of the class are renamed.

The tool is interactive by default (this can be disabled by a flag): if a match is found, the user is requested to confirm the action.

``` bash
$ p11mv wrapperkey other-wrapperkey
move prvk/wrapperkey to prvk/other-wrapperkey ? (y/N)y
move pubk/wrapperkey to pubk/other-wrapperkey ? (y/N)y
$
```
## p11rm
Given an object identifier, delete an object or a class of object. If no object class is given ( i.e. ```pubk/```, ```prvk/```, ```cert/```, ```seck/``` or ```data/```) then all objects of the class are removed.

The tool is interactive by default (this can be disabled by a flag): if a match is found, the user is requested to confirm the action.
```bash
$ p11rm other-wrapperkey
Delete prvk/other-wrapperkey ? (y/n, default n)n
Delete pubk/other-wrapperkey ? (y/n, default n)n
$
```

## p11od
Object Dumper. Given an object identifier, prints attributes and values of an object.

## p11keygen
Generate a key or a key pair. There are multiple options, but the more important are:
-   ```-i```: the label of the key
-   ```-k```: the key algorithm: rsa, ec, des, aes, generic, hmac (hmac and generic are synonyms), hmacsha1, hmacsha256, hmacsha384, hmacsha512 (these are nCipher-specific, and only available when the toolkit is compiled with nCipher extentions)
-   ```-b```: the key length in bits / ```-q```: curve parameter name for elliptic curve

Moreover, it is possible to specify attributes to set at key inception. This is very important as usually attributes cannot be enabled on a key once it has been disabled, so make sure to specify the attribute at key creation.

-   For key pairs, the tool will dispatch attributes pertaining to the relevant key (public or private).
-   For RSA key pairs, ```CKA_ID``` is adjusted to match IBM PKCS#11 JCE algorithm (the value is the SHA-1 of the key modulus).

```bash
$ p11keygen -k rsa -b 2048 -i test-rsa-2048 CKA_ENCRYPT=true CKA_DECRYPT=true CKA_SIGN=true CKA_VERIFY=true

Generating, please wait... Key Generation succeeded

$
```

 - For HMAC key (excepting on nCipher HSMs), you need to specify ```CKA_DERIVE=true```. 
 - ```-b``` parameter specifies how many bits are used to generate the key. It is rounded up to the next byte boundary.

```bash
$ p11keygen -k generic -b 256 -i test-hmac-32-bytes CKA_DERIVE=true

Generating, please wait... Key Generation succeeded

$
```

 - For generating HMAC key on nCipher, you need to use one of the following key types: ```hmacsha1```, ```hmacsha256```, ```hmacsha384```, ```hmacsha512```; In addition, specify ```CKA_SIGN=true``` and ```CKA_VERIFY=true```. 
 - ```-b``` parameter specifies how many bits are used to generate the key. It is rounded up to the next byte boundary.

## p11kcv
Computes the key check value of a symmetric key.

## p11req
Generate a PKCS\#10 CSR. Important options are:

 - ```-i```: the label of the key 
 - ```-d```: subject DN - Caution: must be specified in strict OpenSSL format, which is with a leading ```/``` character. In addition, the order in which the subject name is given is NOT inversed. If the CSR DN must comply with network order ( e.g. for inclusion of the certificate into an LDAP database), you MUST reverse the order. E.g. ```/dc=com/dc=company/ou=whatever/cn=test cert```
- ```-e``` ( may be specified several times): SAN field. It is prefixed with
    ```DNS:``` for a DNS entry, ```email:``` for an email entry, and ```IP:```for
    an IPv4 entry ( four dot notation).
- ```-H``` : hashing algorithm (```sha1```, ```sha256```, \.... )
- ```-X```: add a subject key identifier to the CSR.
- ```-F```: do not perform signature. This can be useful in some case where the private key does not have ```CKA_SIGN``` property asserted, but where a CSR is yet required.
- ```-v```: be verbose.
- ```-o [filename]```: output file
- 
```bash
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
This utility will load a PEM or DER formatted certificate and import it back. ```The CKA_ID``` will be adjusted according to IBM rules.

If needed, the trust bit can be set ( using the ```-T``` option, in combination with the ```-S``` option).

```bash
$ p11importcert -f test.crt -i test-rsa-2048
PEM format detected
*** PKCS\#11 Info : CreateObject() returned CKR_OK ( 0x00000000 )
p11importcert: importing certificate succeeded.
$
```

## p11importpubk
Similarily to ```p11importcert```, this utility will load a PEM or DER formatted public key and import it into the PKCS\#11 token. The ``CKA_ID```
will be adjusted according to IBM rules.

```bash
$ p11importpubk -f test-public-rsa-key.rsa -i test-public-rsa-key
PEM format detected
*** PKCS#11 Info : CreateObject() returned CKR_OK ( 0x00000000 )
p11importpubk: import of public key succeeded.

$
```

## p11importdata
Similarily to p11importcert, this utility will load an arbitrary file and import it into the PKCS\#11 token.

```bash
$ p11importdata -f hello.txt -i dummy_data
*** PKCS#11 Info : CreateObject() returned CKR_OK ( 0x00000000 )
p11importdata: import of data succeeded.
$
```

## masqreq
Under certain circumstances, it is desirable to adapt an existing CSR, before submission to CA. A typical use case is CSR generated by an appliance where the structure of the DN is not flexible and must contain some fields that are otherwise rejected by the CA at
submission. This tool allows to adapt some of the features of a PKCS\#10 request. It does not sign the CSR however, and as such, the signature is invalid.

```bash
$ masqreq -c test.req -d\'/CN=another CN'
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

p11wrap
-------
Used to wrap jeys.
yet to document

p11unwrap
---------
Used to unwrap keys.
yet to document

