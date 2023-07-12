# Installation instructions
## Important Notes
 * While a prefix can be specified at configuration time, the toolkit utility make no use of any hardcoded path.  Using `--prefix=$PWD`will deploy the binaries into a `bin` subdir, relative to the current directory.
 if that option is omitted, the default is to deploy in `/usr/local`, when invoking `make install`. In which case, you will need to be a `root` user when `make install` (or to use `su` or `sudo`) .
 * OpenSSL v1.1.1e or above is required to compile the toolkit. Please refer to [OpenSSL 1.1.1](#openssl-111) for details how to deploy it on your system.
 * Windows 64 bits is currently not supported. See [Note on 64 bits executables](#note-on-64-bits-executables) for more information.

## Pre-requisites
In order to build the project from scratch, you will need
 - a C compiler (tested with `gcc`, `clang`, `xlc` on `AIX`), and make utility (tested with GNU and BSD `make`)
   If your host is Debian-based (e.g. Ubuntu), you can execute the following command:
   ```sh
   $ sudo apt-get install gcc make perl
   ```
 - the autotools suite: `autoconf`, `automake`>=1.14, `libtool`, and `autoconf-archive`, as well as `pkg-config`.
   If your host is Debian-based (e.g. Ubuntu), you can execute the following command:
   ```sh
   $ sudo apt-get install autoconf-archive autoconf automake libtool pkg-config
   ```
   If the autotools suite is not available or obsolete on your platform, or if the build host has no connection to Internet, please check [this section](#when-autotools-utils-are-not-available-on-my-platform) for an alternative way to build.
 - the OpenSSL header files and libraries. Please check [this section](#openssl-111)  for more details.
   If your host is Debian-based (e.g. Ubuntu), you can execute the following command:
   ```sh
   $ sudo apt-get install libssl-dev
   ```
 - optionally, `lex`/`flex` and `yacc`/`bison`. It is not mandatory; if no suitable lexer and/or parser is found, the pre-generated source files will be used instead. If your platform is esoteric, it is however recommended to have these tools available.
   If your host is Debian-based (e.g. Ubuntu), you can execute the following command:
   ```sh
   $ sudo apt-get install bison flex
   ```
 - a connection to Internet (to fetch `gnulib` and the pkcs11 headers)


### OpenSSL 1.1.1
The vast majority of recent distros (FreeBSD and Linux) have OpenSSL 1.1.1e+ by default.

If your platform does not have it, proceed as follows:

 1. Clone OpenSSL [from GitHub](https://github.com/openssl/openssl.git), and checkout the latest OpenSSL 1.1.1 release.
 2. Configure and build. In the examples below, we assume that OpenSSL will be deployed at `/opt/openssl-1.1.1`, change the location to match your preference.

    - A typical build on linux look as follows:
      ```bash
      $ ./config no-zlib shared --prefix=/opt/openssl-1.1.1 linux-x86_64
      $ make
      $ sudo make install
      ```

    - If you want static libraries instead of dynamic ones, use the following instructions instead:
      ```bash
      $ ./config no-zlib no-shared --prefix=/opt/openssl-1.1.1 linux-x86_64
      $ make
      $ sudo make install
      ```

    - for other platforms, change `linux-x86_x64` to the relevant value:

      | platform               	| value                 	|
      | ------------------------| -----------------------	|
      | Linux/amd64            	| `linux-x86_64`          	|
      | Freebsd/amd64           | `BSD-x86_64`            	|
      | MacOS                  	| `darwin64-x86_64-cc`    	|
      | AIX with XLC           	| `aix64-cc`              	|
      | Windows 32 bits        	| `mingw`                 	|
      | Solaris/Intel, 32 bits 	| `solaris-x86-gcc`       	|
      | Solaris/sparc, 32 bits 	| `solaris-sparcv9-gcc `  	|
      | Solaris/sparc, 64 bits 	| `solaris64-sparcv9-gcc` 	|

    If you encounter issue, your platform may require to use `./Configure` instead. In whichc case, please follow instructions provided by OpenSSL.
    
Note: Usually, building OpenSSL requires `zlib` development package to be present on your system. This option is not useful to `pkcs11-tools`. However, if you wish to have it (in case you also want to use that version of OpenSSL for other purposes), change the `no-zlib` option by `zlib`.

## Installation
### Bootstrapping the environment from GitHub
In order to create the autotools and libtool environment, and before being able to execute the `configure`script, you must execute these steps:
```bash
$ git clone https://github.com/Mastercard/pkcs11-tools.git
$ cd pkcs11-tools
$ ./bootstrap.sh
```

### When autotools utils are not available on my platform
#### The short way (for releases 2.2.0 and beyond)
 1. a tarball is available in the assets section of the release page, on GitHub. Just download the file named `pkcs11-tools-X.Y.Z.tar.gz` on your host.
 2. follow the build process. You can skip the ["Bootstrapping the environment"](#bootstrapping-the-environment) section.

#### The long way (for releases before 2.2.0)
 1. build the package on a platform where the tools are available (Linux, FreeBSD)
 2. create a source distribution tarball:
    ```bash
    $ make dist
    ```
    This will create a `pkcs11-tools-X.Y.Z.tar.gz` file in your build directory.
 3. Transfer the file to the target host
 4. follow the build process. You can skip the ["Bootstrapping the environment"](#bootstrapping-the-environment) section.


### Linux, typical install
To build the toolkit, use the following instructions:
```bash
$ ./configure
$ make
$ sudo make install
```

If OpenSSL 1.1.1 is not available as a package on your platform, you will have to specify where it can be found by using the `PKG_CONFIG_PATH` environment variable and pointing it to the location of your OpenSSL installation. 
In addition, you might want to set the `LIBCRYPTO_RPATH` variable, if the location of OpenSSL libraries is not in the default library path.
```bash
$ ./configure PKG_CONFIG_PATH=/opt/openssl-1.1.1/lib/pkgconfig LIBCRYPTO_RPATH=/opt/openssl-1.1.1/lib
$ make
$ sudo make install
```

Alternatively, if you do not have [`pkg-config`](https://www.freedesktop.org/wiki/Software/pkg-config/) installed on your system, you can use `LIBCRYPTO_CFLAGS` and `LIBCRYPTO_LIBS` variables to point to libraries and includes. Again, `LIBCRYPTO_RPATH` can optionally be specified (see 
```bash
$ ./configure LIBCRYPTO_CFLAGS='-I/opt/openssl-1.1.1i/include' LIBCRYPTO_LIBS='-L/opt/openssl-1.1.1/lib -lcrypto' LIBCRYPTO_RPATH=/opt/openssl-1.1.1/lib
$ make
$ sudo make install
```

### Linux, with OpenSSL statically linked
In case you need to deploy the tooklit on target environments where OpenSSL is not installed, you have the option to statically link the OpenSSL library functions into the binaries. This results, obviously, into larger executables, but you get portable binaries that do not depend upon OpenSSL libraries to run.

To achieve this, please refer to section [OpenSSL 1.1.1](#openssl-1.1.1), to compile OpenSSL statically. the process to build the toolkit itself remains the same.


### FreeBSD
On FreeBSD12 and above, the toolkit is available from ports, under `security/pkcs11-tools`, and can be either built from there, or installed as a package:
```
$ pkg install pkcs11-tools
```

On previous FreeBSD versions, you will have to build it. Deploy first the OpenSSL package from ports, either using `pkg`, or through the port subsystem:
```bash
$ pkg install openssl
```
Then proceed as with Linux. Note that clang should be used instead of gcc.

If you had to install OpenSSL differently (e.g. older versions of FreeBSD), and if the path to OpenSSL libraries is not configured on the system, you need to specify an additional parameter (`LIBCRYPTO_RPATH`) when configuring the pkcs11-tools package, to set a run path to the libraries. See [rtld(1)](https://www.freebsd.org/cgi/man.cgi?query=rtld&apropos=0&sektion=1&manpath=FreeBSD+12.0-RELEASE&arch=default&format=html) for more information.
```bash
$ ./configure CC=clang PKG_CONFIG_PATH=/opt/openssl-1.1.1/lib/pkgconfig LIBCRYPTO_RPATH=/opt/openssl-1.1.1/lib
$ make
$ sudo make install
```

### AIX 7.1, 64 bits, IBM XLC compiler
On AIX, do not try to use the GCC compiler, It won't work.

Use the following commands to build the  toolkit:
```bash
$ PATH=/usr/vac/bin:$PATH
$ ./configure --prefix=$PWD -C AR='ar -X64' CFLAGS='-q64' PKG_CONFIG_PATH=/opt/openssl-1.1.1/lib/pkgconfig
$ make
$ sudo make install
```

Note that the same command can be used for both statically and dynamically-linked versions, on this platform.

### Solaris
#### Pre-requisites
You need to have GCC deployed on your computer. You can obtain and deploy GCC on your Solaris plarform from [OpenCSW](https://www.opencsw.org/).

#### static build
 * To buill 32 bits binaries (both sparc and intel):
   ```bash
   $ CFLAGS='-I/opt/openssl-1.1.1/include' LDFLAGS=-L/opt/openssl-1.1.1/lib ./configure --prefix=$PWD
   ```
 * To build sparcv9 64 bits binaries:
   ```bash
   $ CFLAGS='-m64 -mcpu=ultrasparc3 -I/opt/openssl-1.1.1/include' LDFLAGS=-L/opt/openssl-1.1.1/lib ./configure --prefix=$PWD
   ```
Compile and deploy using `make install`
```bash
$ sudo make install
```
#### OpenCSW build
Alternatively, you could use the openssl library from [OpenCSW](https://www.opencsw.org/). This will result in dynamically linked executables; they are shorter in size, but they rely upon the shared libraries to execute on your target system.

When building with OpenCSW, you may have to change your path to point to `/opt/csw/gnu`:

```bash
$ export PATH=/opt/csw/gnu:$PATH
```
Then proceed as documented for [FreeBSD](#freebsd).

#### Notes
Building OpenSSL 1.1.1 on Solaris 10 may prove to be challenging. Please refer to [https://github.com/openssl/openssl/issues/6333](https://github.com/openssl/openssl/issues/6333) for additional information.

### Windows (cross-compiling)
Cross-compilation works with mingw32-gcc under linux. [Debian](https://www.debian.org/) distros are offering off-the-shelf cross-compilers, so the examples below are assuming [Debian](https://www.debian.org/) as the build platform.

#### To create 32 bits executables:
##### Note on 64 bits executables
The creation of Windows-compatible 64 bits executable is not supported through GCC, as objects are not binary-compatible with those created with Visual Studio, see [this page](https://software.intel.com/en-us/articles/size-of-long-integer-type-on-different-architecture-and-os) for more information. Until the toolkit can be compiled under Visual Studio, no 64 bits executable for Windows can be created.

In theory, producing Win64 executable can be achieved through compiling with Visual C++ platform. Any volunteering welcome :-)


##### Prerequisites
- install cross-compiler (Debian package: `gcc-mingw-w64-i686`)
- install wine on your linux host (Debian package: `wine`)
  Note: if your build platform is 64 bits, `wine` will instruct you at first launch to install a few more packages as well as adding an architecture. 
- have an installation of OpenSSL-Win32 under wine ( see this [link](https://slproweb.com/products/Win32OpenSSL.html) referenced by OpenSSL): download the installer and execute with `wine Win32OpenSSL-1_0_XX.exe` (where `xx` represent the version.)
- in the project root directory, create a symbolic link to the OpenSSL-Win32 directory (assuming that the DLLs are found in `$HOME/.wine/drive_c/OpenSSL-Win32 openssl-win32`):
```bash
$ ln -s $HOME/.wine/drive_c/OpenSSL-Win32 openssl-win32
```

##### compilation:
```bash
$ ./configure --host=i686-w64-mingw32 --prefix=$PWD LIBCRYPTO_LIBS="-L$(pwd)/openssl-win32/lib -lcrypto" LIBCRYPTO_CFLAGS="-I$(pwd)/openssl-win32/include"
$ make install
```

binaries can be found inside the `bin` directory. Don't forget to join the following DLLs:
 - `libcrypto_1_1.dll` from `OpenSSL-Win32` directory
 - `libwinpthread-1.dll` from the cross-compiling environment ( on Debian, this can be found at `/usr/i686-w64-mingw32/lib/libwinpthread-1.dll`)

### MacOS
This expects that brew be installed on your system, and the formula `openssl@1.1` be deployed. check out https://brew.sh for more information.
```bash
$ ./configure PKG_CONFIG_PATH=/usr/local/opt/openssl@1.1/lib/pkgconfig LIBCRYPTO_RPATH=/usr/local/opt/openssl@1.1/lib
$ make
$ sudo make install
```

### AWS CloudHSM support
By default, AWS CloudHSM support is disabled, as it removes some functionality from the `p11ls` command. If you want to build the toolkit with AWS CloudHSM support, add the `--with-awscloudhsm` argument to `configure`:
```bash
$ ./configure --with-awscloudhsm
```

## Packaging
### all platforms
To build a generic binary distribution tarball (all platforms):
```bash
$ ./configure [...] --prefix=$PWD
$ make dist-bin
```

### Solaris pkg
To build solaris package:
```bash
$ ./configure [...] --prefix=$PWD
$ make dist-solaris
```

### RPM
To build an RPM package:
(this assumes that `rpmbuild` is installed and properly configured for the user; it also assumes that OpenSSL 1.1.1 is the default on your platform)
```bash
$ ./configure [...] --prefix=$PWD
$ make dist
$ cp dist/redhat/pkcs11-tools.spec $HOME/rpmbuild/SPECS
$ cp pkcs11-tools-[VERSION].tar.gz $HOME/rpmbuild/SOURCES
$ rpmbuild -ba $HOME/rpmbuild/SPECS/pkcs11-tools.spec
```

RPMs and SRPMs are found in `$HOME/rpmbuild/RPMS` and `$HOME/rpmbuild/SRPMS`, respectively.

#### AWS CloudHSM support in RPM
To build the RPM package with AWS CloudHSM support, use the following command when building:
```bash
$ rpmbuild -ba $HOME/rpmbuild/SPECS/pkcs11-tools.spec --with awscloudhsm
```