# Installation instructions
----
## Important Notes
 * While a prefix can be specified at configuration time, the toolkit utility make no use of any hardcoded path.  Using `--prefix=$PWD`will deploy the binaries into a `bin` subdir, inside the current directory.
 if that option is omitted, the default is to deploy in `/usr/local`, when invoking `make install`. In which case, you might need to use `su` or `sudo` when invoking `make install`.
 * Currently, **only OpenSSL 1.0 is supported**. Conversion to OpenSSL 1.1+ in ongoing. In the meantime, you will have to deploy OpenSSL 1.0.2, if you are using a recent/updated platform. Please refer to [OpenSSL 1.0](#openssl-10) for details how to deploy it on your system.
 * Windows 64 bits is currently not supported. See [Note on 64 bits executables](#note-on-64-bits-executables) for more information.

## Pre-requisites
In order to build the project from scratch, you will need
 - a C compiler (tested with `gcc`, `clang`, `xlc` on `AIX`)
 - the autotools suite: `autoconf`, `automake`, `libtool`
 - optionally, `lex`/`flex` and `yacc`/`bison`
 - a connection to Internet (to checkout `gnulib`)

If the autotools suite is not available or obsolete on your platform, or if the build host has no connection to Internet, please check [this section](#when-autotools-utils-are-not-available-on-my-platform) for an alternative way to build.

### OpenSSL 1.0
To install OpenSSL 1.0, proceed as follows:

 1. Clone OpenSSL [from GitHub](https://github.com/openssl/openssl.git), and checkout the latest OpenSSL 1.0.2 release. (To date, it is tagged `OpenSSL_1_0_2u`). Alternatively, you can directly download it from [here](https://github.com/openssl/openssl/archive/OpenSSL_1_0_2u.tar.gz)
 2. Configure and build. In the examples below, we assume that OpenSSL will be deployed at `/opt/openssl@1.0.2`, change the location to match your preference.
 
    - A typical build on linux look as follows:
      ```bash
      $ ./config zlib shared --openssldir=/opt/openssl@1.0.2 linux-x86_64
      $ make
      $ sudo make install
      ```
      
    - If you need static libraries instead of dynamic ones, use the following instructions instead:
      ```bash
      $ ./config zlib no-shared --openssldir=/opt/openssl@1.0.2 linux-x86_64
      $ make
      $ sudo make install
      ```
      
    - for other platforms, change `linux-x86_x64` to the relevant value:
    
      | platform               	| value                 	|
      | ------------------------	| -----------------------	|
      | Linux/amd64            	| `linux-x86_64`          	|
      | Freebsd/amd64           	| `BSD-x86_64`            	|
      | MacOS                  	| `darwin64-x86_64-cc`    	|
      | AIX with XLC           	| `aix64-cc`              	|
      | Windows 32 bits        	| `mingw`                 	|
      | Solaris/Intel, 32 bits 	| `solaris-x86-gcc`       	|
      | Solaris/sparc, 32 bits 	| `solaris-sparcv9-gcc `  	|
      | Solaris/sparc, 64 bits 	| `solaris64-sparcv9-gcc` 	|
    
Note: building OpenSSL requires `zlib`development package to be present on your system. If you can't have it deployed on your platform, remove the `zlib` parameter from the command line, or change it to `no-zlib` 

## Installation
### Bootstrapping the environment
In order to create the autotools and libtool environment, and before being able to execute the `configure`script, you must execute these steps:
```bash
$ git clone https://github.com/Mastercard/pkcs11-tools.git
$ cd pkcs11-tools
$ ./bootstrap.sh
```

### When autotools utils are not available on my platform
In this case, you will need to:
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

If OpenSSL 1.0 is no more available as a package on your platform, you will have to specify where it can be found by using the `PKG_CONFIG_PATH` environment variable and pointing it to the location of your OpenSSL installation:
```bash
$ ./configure PKG_CONFIG_PATH=/opt/openssl@1.0.2/lib/pkgconfig
$ make
$ sudo make install
```

Alternatively, if you do not have [`pkg-config`](https://www.freedesktop.org/wiki/Software/pkg-config/) installed on your system, you can use `LIBCRYPTO_CFLAGS` and `LIBCRYPTO_LIBS` variables to point to libraries and includes:
```bash
$ ./configure LIBCRYPTO_CFLAGS='-I/opt/openssl@1.0.2/include' LIBCRYPTO_LIBS='-L/opt/openssl@1.0.2/lib -lcrypto'
$ make
$ sudo make install
```

### Linux, with OpenSSL statically linked
In case you need to deploy the tooklit on target environments where OpenSSL is not installed, you have the option to statically link the OpenSSL library functions into the binaries. This results, obviously, into larger executables, but you get portable binaries that do not depend upon OpenSSL libraries to run.

To achieve this, please refer to section [OpenSSL 1.0](#openssl-1.0), to compile OpenSSL statically. the process to build the toolkit itself remains the same.

### FreeBSD
On FreeBSD, proceed as with Linux. If you had to install OpenSSL locally, and if the path to OpenSSL libraries is not configured on the system, you need to specify an additional parameter when configuring the pkcs11-tools package, to adjust run path to the libraries. See [rtld(1)](https://www.freebsd.org/cgi/man.cgi?query=rtld&apropos=0&sektion=1&manpath=FreeBSD+12.0-RELEASE&arch=default&format=html) for more information.
```bash
$ ./configure PKG_CONFIG_PATH=/opt/openssl@1.0.2/lib/pkgconfig LIBCRYPTO_RPATH=/opt/openssl@1.0.2/lib
$ make
$ sudo make install
```

### AIX 7.1, 64 bits, IBM XLC compiler, statically linked to OpenSSL
Use the following commands to build the  toolkit:
```bash
$ PATH=/usr/vac/bin:$PATH
$ AR='ar -X64' CFLAGS='-q64 -qlanglvl=extc99 -I/opt/openssl@1.0.2/include' LDFLAGS=-L/opt/openssl@1.0.2/lib ./configure --prefix=$PWD -C
$ make
$ sudo make install
```

### Solaris
#### Pre-requisites
You need to have GCC deployed on your computer. You can obtain and deploy GCC on your Solaris plarform from [OpenCSW](https://www.opencsw.org/).

#### static build
 * To buill 32 bits binaries (both sparc and intel):
   ```bash
   $ CFLAGS='-I$HOME/openssl/include' LDFLAGS=-L$HOME/openssl ./configure --prefix=$PWD
   ```
 * To build sparcv9 64 bits binaries:
   ```bash
   $ CFLAGS='-m64 -mcpu=ultrasparc3 -I$HOME/openssl/include' LDFLAGS=-L$HOME/openssl ./configure --prefix=$PWD
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

### Windows (cross-compiling)
Cross-compilation works with mingw32-gcc under linux. [Debian](https://www.debian.org/) distros are offering off-the-shelf cross-compilers, so the examples below are assuming [Debian](https://www.debian.org/) as the build platform.

#### To create 32 bits executables:
##### Note on 64 bits executables
the creation of Windows-compatible 64 bits executable is not supported through GCC, as objects are not binary-compatible with those created with Visual Studio, see [this page](https://software.intel.com/en-us/articles/size-of-long-integer-type-on-different-architecture-and-os) for more information. Until the toolkit can be compiled under Visual Studio, no 64 bits executable for Windows can be created.

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
$ CFLAGS="-I$(pwd)/openssl-win32/include" LDFLAGS="-L$(pwd)/openssl-win32" ./configure --host=i686-w64-mingw32 --prefix=$PWD
$ make install
```

##### To compile:
```bash
$ CFLAGS="-I$(pwd)/openssl-win64/include" LDFLAGS=-L$(pwd)/openssl-win64 ./configure --host=x86_64-w64-mingw32 --prefix=$PWD
$ make install
```

### MacOS
This expects that brew is installed on MacOS. check out https://brew.sh for more information.
```bash
$ ./configure PKG_CONFIG_PATH=/opt/openssl@1.0.2/lib/pkginfo
$ make
$ sudo make install
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
(this assumes that `rpmbuild` is installed and properly configured for the user)
```bash
$ ./configure [...] --prefix=$PWD
$ make dist
$ cp dist/redhat/pkcs11-tools.spec $HOME/rpmbuild/SPECS
$ cp pkcs11-tools-[VERSION].tar.gz $HOME/rpmbuild/SRPMS
$ rpmbuild -ba $HOME/rpmbuild/SPECS/pkcs11-tools.spec
```

RPMs and SRPMs are found in `$HOME/rpmbuild/RPMS` and `$HOME/rpmbuild/SRPMS`, respectively.
