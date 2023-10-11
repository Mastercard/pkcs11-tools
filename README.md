# PKCS\#11 tools

pkcs11-tools is a toolkit containing a bunch of small utilities to perform key management tasks on cryptographic tokens
implementing a PKCS\#11 interface. It features a number of commands similar to the unix CLI utilities, such as `ls`
, `mv`, `rm`, `od`, and `more`. It also has specific commands to generate keys, generate CSRs, import certificates and
other files, in a fashion compatible with most implementations, including both IBM and Oracle JVMs. It is also able to
interface with NSS libraries from [mozilla.org](https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS).

Some features:

- support for DES, 3DES, AES, HMAC, RSA, DSA, DH, Elliptic curves (NIST curves, Edwards curves)
- generation of PKCS\#10 (CSR) and self-signed certificates
- import of certificates, public keys, data files
- support for wrapping and unwrapping keys, for both symmetric and asymmetric keys
- support for templates during key creation, public key import, key wrapping and key unwrapping
- support for session key generation and direct wrapping under one or several keys, in a single command
- support for key rewrapping (i.e. key unwrapping and key wrapping)

## News
### July 2023
Version 2.6 brings support for the AWS CloudHSM platform, library version 5.9.
Limitations are:
 - Certificates are not supported by the platform, therefore any command handling certificates will fail
 - Changing attributes values is not supported by the platform; several commands rely on that capability to adjust `CKA_ID` accross objects. These commands may occasionally report an error when executed; key material is usually created.
 - For the same reason, `p11mv` and `p11setattr`  will not operate on this platform.
 - The platform does not allow for duplicate `CKA_ID` attributes, which occasionally brings issues when generating key material. This will be adjusted in a later release.
 - `p11od` command will not work, due to the way CloudHSM handles attributes.
 - When using wrapped key files, `CKA_SIGN_RECOVER` and `CKA_VERIFY_RECOVER` are not supported, and should be commented out.
 - Wrap and unwrap templates are not supported by this platform. These should also be commented out in wrapped key files.
AWS CloudHSM support is disabled by default; please refer to [installation instructions](docs/INSTALL.md) for more details.

### June 2023
Version 2.6, introduces support for JWK - JOSE Web Key output (RFC 7517) on the `p11keygen`, `p11wrap`, and `p11rewrap`
commands. The JWK format is not supported for importing keys.

### October 2021

Version 2.5, that brings support for `CKA_ALLOWED_MECHANISMS`, on many key management commands: `p11keygen`, `p11wrap`
, `p11unwrap`, `p11rewrap`, `p11od`, `p11ls`. Note that the wrapped key grammar has changed; the grammar version number
has been incremented to `2.2`.

### July 2021

Version 2.4, to support templates in many commands: `p11keygen`, `p11importpubk`, `p11wrap`, `p11unwrap`, `p11od`
, `p11ls`. Keys created with a template can be wrapped, the template attributes will be carried. Note that the wrapped
key grammar has changed, and the grammar version number has been incremented to `2.1`.

### April 2021

Version 2.3, that adds extra options to p11kcv, so that tokens not supporting NULL-length HMAC computation can be also
supported.

### March 2021

Version 2.2 is slightly changing the layout of `p11slotinfo`. Edwards Curve support enhanced. The toolkit is also
adapted to be packaged as a [FreeBSD port](https://www.freshports.org/security/pkcs11-tools/).

### January 2021

Version 2.1 brings support for Edwards Curve.

### December 2020

The toolkit has reached v2.0. It features several major changes:

- it supports (and requires) OpenSSL v1.1.1+
- signing commands (`p11mkcert`, `p11req` and `masqreq`) implement OpenSSL algorithm methods. This will enable
  supporting more algorithms in the future.
- major overhaul of the wrapping/unwrapping system: it is now possible to perform double wrapping (aka envelope
  wrapping) with a single command, in a secure fashion
- `p11keygen` can now generate a session key and wrap it under one or several wrapping keys
- a new command, `p11rewrap`, allows to unwrap a key and immediately rewrap in under one or several wrapping keys, in a
  secure fashion.

## Introduction

Ensure the prerequisites listed in the [Install Document](https://github.com/Mastercard/pkcs11-tools/blob/master/docs/INSTALL.md) are installed before proceeding

To build the source code, simply execute (with appropriate privileges)

```bash
$ ./bootstrap.sh
$ ./configure
$ make install
```

To list the methods available on a PKCS#11 token, use `p11slotinfo`, that will return the list of available mechanisms,
together with allowed APIs.

```bash
$ using PKCS11LIB at /opt/softhsm2-devel/lib/softhsm/libsofthsm2.so
PKCS#11 Library
---------------
Name        : /opt/softhsm2-devel/lib/softhsm/libsofthsm2.so
Lib version : 2.6
API version : 2.40
Description : Implementation of PKCS11
Manufacturer: SoftHSM

PKCS#11 module slot list:
Slot index: 0
----------------
Description : SoftHSM slot ID 0x4fbfdc13
Token Label : token1
Manufacturer: SoftHSM project


Enter slot index: 0

Slot[0]
-------------
Slot Number : 1337973779
Description : SoftHSM slot ID 0x4fbfdc13
Manufacturer: SoftHSM project
Slot Flags  : [ CKF_TOKEN_PRESENT ]

Token
-------------
Label       : first token
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
...
```

To list the objects sitting on the token at slot with index 0, use `p11ls`. objects are listed together with their
attributes;

```bash
$ p11ls -l /usr/local/opt/softhsm/lib/softhsm/libsofthsm2.so -s 0

Enter passphrase for token: ******

seck/des-double                       tok,prv,r/w,loc,enc,dec,sen,ase,nxt,des(128)
pubk/rsa                              tok,pub,r/w,loc,vfy,rsa(2048)
seck/des-simple                       tok,prv,r/w,loc,enc,dec,sen,ase,nxt,des(64)
seck/aes-wrapping                     tok,prv,r/w,imp,wra,unw,sen,NAS,WXT,aes
pubk/dh                               tok,pub,r/w,loc,enc,vre,wra,dh(2048)
pubk/rsa-wrapping                     tok,pub,r/w,loc,wra,rsa(2048)
prvk/rsa-disclosed                    tok,prv,r/w,loc,sig,NSE,NAS,XTR,WXT,rsa(2048)
prvk/rsa-wrapping                     tok,prv,r/w,loc,unw,sen,ase,nxt,rsa(2048)
seck/aes-128                          tok,prv,r/w,loc,enc,dec,sen,ase,nxt,aes(128)
seck/aes-256                          tok,prv,r/w,loc,wra,unw,sen,ase,nxt,aes(256)
prvk/rsa                              tok,prv,r/w,loc,sig,sen,ase,nxt,rsa(2048)
pubk/rsa-disclosed                    tok,pub,r/w,loc,vfy,rsa(2048)
prvk/dh                               tok,prv,r/w,loc,dec,sir,unw,sen,ase,nxt,dh(2048)
seck/des-triple                       tok,prv,r/w,loc,enc,dec,sen,ase,nxt,des(192)
prvk/dsa                              tok,prv,r/w,loc,dec,sig,sir,unw,sen,ase,nxt,dsa(2048)
pubk/dsa                              tok,pub,r/w,loc,enc,vfy,vre,wra,dsa(2048)
data/dsaparam                         tok,prv,
seck/hmac-256                         tok,prv,r/w,loc,sig,vfy,sen,ase,nxt,generic
data/dhparam                          tok,prv,
```

To avoid specifying command line arguments, environment variables can be specified for the following items:

|optional arg|description                        |environment variable|
|------------|-----------------------------------|--------------------|
| `-l`       |path to library                    |`PKCS11LIB`         |
| `-m`       |path to NSS keystore (for NSS only)|`PKCS11NSSDIR`      |
| `-s`       |slot index number                  |`PKCS11SLOT`        |
| `-t`       |token name                         |`PKCS11TOKEN`       |
| `-p`       |token password                     |`PKCS11PASSWORD`    |

To extract the value of a non-sensitive object, use `p11cat`:

```bash
$ p11cat pubk/rsa
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2zd+HKrd1u7TBMfvlpO2
1eT8uoY+aLw6/yT9treLk67czyA6XQ8NMtspacgxLXbC0XbaObGJDOswFN2o+zjA
hgKkBY6mEZKO3dzmqtQupQvxybyrj0pg0e+YoZe34rIjVvCdJ9T48etvCyrDZata
XYMw9pT2JvlJQG2ddPVjR83tGNayGYWmz5L0JwDLlb0NwJTJItIaabseIKHqQOzN
tSgeLsOmy08aqSq87WKEAilXrxcv8mWl/gbu18Chu4z7KJ76dWHnJfXzIMJCNNxf
HjhvKZx6bFMEi/gI9gCkUekO+6clrEjSxWzgnC8IDZCLGAvNBZ0pKBW9yEuayPiX
rQIDAQAB
-----END PUBLIC KEY-----
```

To see an object's value, use `p11more`:

```bash
$ p11more cert/rootca
Certificate:
	Data:
		Version: 3 (0x2)
		Serial Number: 2933735351 (0xaedd3fb7)
	Signature Algorithm: sha256WithRSAEncryption
		Issuer: C=BE, O=Dummy CA Inc., CN=Dummy Root CA G1
		Validity
			Not Before: Sep 28 08:10:48 2018 GMT
			Not After : Sep 28 08:10:48 2028 GMT
		Subject: C=BE, O=Dummy CA Inc., CN=Dummy Root CA G1
		Subject Public Key Info:
			Public Key Algorithm: rsaEncryption
				Public-Key: (2048 bit)
				Modulus:
					00:a9:a6:a5:99:d0:3e:0e:00:c1:f7:df:9f:9c:92:
					40:ac:67:d3:77:e0:d5:6d:eb:a0:5c:29:12:ad:57:
					a3:23:9a:27:03:cb:dc:62:43:c3:04:a8:e8:a3:ab:
...
```

Moreover, `p11od`can be used to extract all attribute values from an object:

```bash
$ p11od pubk/dh
pubk/dh:
 CKA_CLASS:
  0000  02 00 00 00 00 00 00 00                          CKO_PUBLIC_KEY
 CKA_TOKEN:
  0000  01                                               CK_TRUE
 CKA_PRIVATE:
  0000  00                                               CK_FALSE
 CKA_LABEL:
  0000  64 68                                            dh
 CKA_VALUE:
  0000  7e cc a1 d2 c2 e7 90 b9 fa 68 fc ae 49 46 2e 0f  ~........h..IF..
  0010  62 1e 2c 69 2e 94 f2 eb 46 63 d7 fd 57 1f 5d 02  b.,i....Fc..W.].
  0020  30 f4 3b 48 44 0c eb d7 7e 83 d5 26 7c 7a a3 f5  0.;HD...~..&|z..
...
```

Generating a key is easy: just use `p11keygen` with the proper arguments.

```bash
$ p11keygen -k ec -q prime256v1 -i my-ec-key sign=true verify=true
Generating, please wait...
key generation succeeded
```

Likewise, `p11req` is used to generate a CSR.

```bash
$ p11req -i my-ec-key -d '/CN=my.site.org/O=My organization/C=BE' -e 'DNS:another-url-for-my.site.org' -v
Certificate Request:
	Data:
		Version: 0 (0x0)
		Subject: C=BE, O=My organization, CN=my.site.org
		Subject Public Key Info:
			Public Key Algorithm: id-ecPublicKey
				Public-Key: (256 bit)
				pub:
					04:3f:56:11:f8:38:c7:f0:c1:87:a4:75:1a:ca:2e:
					46:38:9e:6a:79:3a:3e:a5:90:54:48:be:81:18:c6:
					f3:1c:92:8b:72:35:cd:e3:32:8c:40:a4:d4:e7:33:
					50:13:34:4a:87:e0:8c:17:77:39:ed:ef:de:d3:1a:
					26:b3:11:87:13
				ASN1 OID: prime256v1
				NIST CURVE: P-256
		Attributes:
		Requested Extensions:
			X509v3 Subject Alternative Name:
				DNS:another-url-for-my.site.org
	Signature Algorithm: ecdsa-with-SHA256
		 30:45:02:21:00:e8:b7:c0:49:bc:77:8d:94:29:18:66:8f:9d:
		 6a:62:cd:f0:84:46:89:73:93:11:d8:67:98:95:12:1c:53:f7:
		 5f:02:20:4a:b6:98:fd:66:be:7c:7f:d1:02:07:d0:5b:dc:8b:
		 fd:3f:89:f0:ed:03:ec:2e:a4:1c:72:a2:21:22:9f:a5:7d
-----BEGIN CERTIFICATE REQUEST-----
MIIBMTCB2AIBADA9MQswCQYDVQQGEwJCRTEYMBYGA1UECgwPTXkgb3JnYW5pemF0
aW9uMRQwEgYDVQQDDAtteS5zaXRlLm9yZzBZMBMGByqGSM49AgEGCCqGSM49AwEH
A0IABD9WEfg4x/DBh6R1GsouRjieank6PqWQVEi+gRjG8xySi3I1zeMyjECk1Ocz
UBM0SofgjBd3Oe3v3tMaJrMRhxOgOTA3BgkqhkiG9w0BCQ4xKjAoMCYGA1UdEQQf
MB2CG2Fub3RoZXItdXJsLWZvci1teS5zaXRlLm9yZzAKBggqhkjOPQQDAgNIADBF
AiEA6LfASbx3jZQpGGaPnWpizfCERolzkxHYZ5iVEhxT918CIEq2mP1mvnx/0QIH
0Fvci/0/ifDtA+wupBxyoiEin6V9
-----END CERTIFICATE REQUEST-----
```

Later, `p11importcert` can be used to import the certificate back to the keystore. Public keys can be imported
using `p11importpubk`, and data files with `p11importdata`.

If you need to wrap or unwrap a key, you can use the command `p11wrap`:

```bash
$ p11wrap -w aes-wrapping -i rootca -a cbcpad >wrapped-key.wrap
key wrapping succeeded
```

The key can be unwrapped later, reusing the `wrapped-key.wrap` file created earlier:

```bash
$ p11unwrap -f wrapped-key.wrap
key unwrapping succeeded
```

## Installation

The project can compile on many platforms, including Linux, AIX, Solaris. Using cross-compilers, it is also possible to
compile for the Windows platform. Compilation under macOS requires [brew](https://brew.sh/). Please refer
to [docs/INSTALL.md](docs/INSTALL.md) for installation instructions.

## Manual

Please refer to [docs/MANUAL.md](docs/MANUAL.md) for instructions / how-to guide.

## Contributing

If you wish to contribute to this project, please refer to the rules in [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md).

Contributors:
 - Georg Lippold (Mastercard, https://www.mastercard.com) - JWK output, GitHub build & CodeQL integration

## Author

Eric Devolder (Mastercard, https://www.mastercard.com)

## Licensing terms

Except when specified differently in source files, the following license apply:

---------------
Copyright (c) 2018 Mastercard

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "
AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific
language governing permissions and limitations under the License.

-----
