# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

# [UNPUBLISHED]
### Added
- support public key extraction for libraries with non-compliant `CKA_EC_POINT` implementations (with no OCTET STRING encapsulation)
- support for Docker builds
- `p11req` and `p11mkcert` now support RSA-PSS signature (add `-a pss` arguments to select it)
- `p11kcv` beefed up, to support multiple MACing algorithms, as well as displaying the value of `CKA_CHECK_VALUE`
- support for wrapping keys in JOSE Web Key format (JWK, RFC 7178)
- new option `--enable-duplicate`, to override duplicate label protection when creating or importing a key (must be enabled at compile time)
- search templates: it is now possible to add other attributes in a search, to filter out on more than one attribute

### Fixed
- small fix on with_xxx wrappers, replacing space with underscore in reply code

# [2.6.0]
### Added
- support for AWS Cloud HSM. See [README.md] for limitations.

### Fixed
- with recent versions of GCC, compilation issue with lexx and yacc produced source code.
- when `automake`<1.14 is used, use an older, compatible commit for `gnulib`

### Updated
- `gnulib` in now built from a stable branch, `stable-202307`

# [2.5.1]
- adding `-S` option flag for `p11keygen`, for enabling key generation when logged in as Security Officer (PR #33)
- fixed a few memory management issues, preventing to import EC public keys when using `p11keygen`, `p11unwrap` and `p11importpubk`.

# [2.5.0]
### Added
 - `CKA_ALLOWED_MECHANISMS` support for all key management utilities (`p11keygen`, `p11wrap`, `p11unwrap`, `p11rewrap`, `p11ls`, `p11od`)

### Fixed
 - `p11wrap`: fixed memory leaks

# [2.4.2]
### Fixed
 - `p11ls`: removed duplicate `CKA_CHECK_VALUE` attribute from `C_GetAttributeValue()` call on secret keys (may cause issues on some PKCS\#11 tokens)

# [2.4.1]
### Fixed
 - template content is no more wrapped/dipsplayed if length is not a multiple of CK_ATTRIBUTE structure,
   to ignore templates incorrectly reported by some tokens

# [2.4.0]
### Added
 - support for template attributes on most commands

# [2.3.1]
### Fixed
 - some of the mgf argument values for `p11wrap`, `p11rewrap` and `p11keygen` were incorrect. The documentation has also been adjusted (Issue #30).
 - `p11more`, `p11req`, `p11mkcert` and `p11cat` could not deal with Edwards curve if the curve parameter was specified as a named curve.

# [2.3.0]
### Added
- added the ability to specify a buffer length, when performing HMAC key check values (default is 0).

# [2.2.0]
### Added
- `p11kcv` will compute a Key Check Value on `CK_GENERIC_SECRET` keys as well. These are mapped to HMAC-SHA256.
- `p11slotinfo` now prints library version
- support for FreeBSD ports and packaging
- for Edwards curve based keys, allow providing curve name instead of OID when generating a key

# [2.1.3] - 2021-03-25
### Fixed
- ensure that openssl 1.1.1e or above is used, issue #27
- ensure that threading library is referenced, to allow building with static OpenSSL library

# [2.1.2] - 2021-02-01
### Fixed
- fixed unallowed memory free, causing command `p11rewrap` to crash

# [2.1.1] - 2021-01-26
### Fixed
- wrapping DES keys with PKCS#1 v1.5 algorithm bug - wrapped key length deduced from key type onwards

# [2.1.0] - 2021-01-06
### Added
- support for Edwards curve based keys ( ED448 and ED25519 ), for all commands (closing issue #11).

# [2.0.2] - 2020-12-22
### Fixed
- include file `lib/pkcs11_ossl.h` to the source distribution (Issue #24)
- typo in documentation (Issue #24)
- compilation on older RedHat derivatives that use `openssl11-dev` instead of `openssl-dev`

# [2.0.1] - 2020-12-18
### Fixed
- fixed cross-compilation issues for mingw32

# [2.0.0] - 2020-12-15
### Added
- implemented envelope wrapping (combining a symmetric key and a private key to wrap anything)
- `p11keygen`: implemented wrapping under one or more keys
- `p11wrap` : implemented wrapping underone or more keys
- added `p11rewrap` command, allowing to rewrap wrapped keys under other keys
- added `p11mkcert` command, to create self-signed certificates usable with JVMs

### Changed
- support for OpenSSL 1.1 ( OpenSSL 1.1.1+ required) - Contribution from Ian Norton (@inorton)
- major refactoring of `p11req` and `masqreq` to leverage OpenSSL algoritm method subsystem

### Fixed
- fixed `p11kcv` to work on SoftHSM
- fixed packaging for Solaris

# [1.2.0] - 2020-04-10
### Enhanced
- implemented CKA_AES_KEY_WRAP (rfc3394) and CKA_AES_KEY_WRAP_PAD (rfc5649)
- added support for Gemalto Safenet Luna HSM
- added flavour=nss parameter to rfc5649 algorithm, to identify non compliant RFC5649 implementation of NSS

### Fixed
- fixed compilation warning on linux/debian 10 with gcc
- fixed issue that prevented cross-compilation to work, for mingw32

## [1.1.0] - 2020-01-15
### Enhanced
- the build process can leverage pkg-config, when available
- the Git repository does not store generated source files anymore. It requires to execute `bootstrap.sh` before `configure`
- `gnulib`is now a submodule of the project
- PKCS11 version upgraded to v2.40, with the backport of EdDSA defines from v3.0
- enhanced installation documentation

## [1.0.3] - 2019-08-14
### Fixed
- Fix for token labels having maximum length (i.e. 32 characters) (Issue #7)

## [1.0.2] - 2018-12-20
### Fixed
- Fix for cross-compilation and header file detection in `configure.ac` (Issue #1)
- Documentation for installing

## [1.0.1] - 2018-12-07
### Changed
- Project name changed from pkcs11-toolkit to pkcs11-tools

### Fixed
- Enhanced nCipher header file detection (now automatic)
- Fixed missing files when generating Solaris pkg
- Removed unnecessary files from github
- Links and date in the Changelog are now accurate

## [1.0.0] - 2018-12-06
### Added
- Initial public release

[2.6.0]: https://github.com/Mastercard/pkcs11-tools/tree/v2.6.0
[2.5.1]: https://github.com/Mastercard/pkcs11-tools/tree/v2.5.1
[2.5.0]: https://github.com/Mastercard/pkcs11-tools/tree/v2.5.0
[2.4.2]: https://github.com/Mastercard/pkcs11-tools/tree/v2.4.2
[2.4.1]: https://github.com/Mastercard/pkcs11-tools/tree/v2.4.1
[2.4.0]: https://github.com/Mastercard/pkcs11-tools/tree/v2.4.0
[2.3.1]: https://github.com/Mastercard/pkcs11-tools/tree/v2.3.1
[2.3.0]: https://github.com/Mastercard/pkcs11-tools/tree/v2.3.0
[2.2.0]: https://github.com/Mastercard/pkcs11-tools/tree/v2.2.0
[2.1.3]: https://github.com/Mastercard/pkcs11-tools/tree/v2.1.3
[2.1.2]: https://github.com/Mastercard/pkcs11-tools/tree/v2.1.2
[2.1.1]: https://github.com/Mastercard/pkcs11-tools/tree/v2.1.1
[2.1.0]: https://github.com/Mastercard/pkcs11-tools/tree/v2.1.0
[2.0.2]: https://github.com/Mastercard/pkcs11-tools/tree/v2.0.2
[2.0.1]: https://github.com/Mastercard/pkcs11-tools/tree/v2.0.1
[2.0.0]: https://github.com/Mastercard/pkcs11-tools/tree/v2.0.0
[1.2.0]: https://github.com/Mastercard/pkcs11-tools/tree/v1.2.0
[1.1.0]: https://github.com/Mastercard/pkcs11-tools/tree/v1.1.0
[1.0.3]: https://github.com/Mastercard/pkcs11-tools/tree/v1.0.3
[1.0.2]: https://github.com/Mastercard/pkcs11-tools/tree/v1.0.2
[1.0.1]: https://github.com/Mastercard/pkcs11-tools/tree/v1.0.1
[1.0.0]: https://github.com/Mastercard/pkcs11-tools/tree/v1.0.0
