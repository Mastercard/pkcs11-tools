# Installation instructions
----
## Notes
The toolkit has no path hardcoded. As such, the prefix does not really matter at compilation time. This variable is adjusted below when invoking configure, in order to allow building the tooklit without requiring root privileges.

The pattern used is `--prefix=$PWD`, that will install the binaries into a bin subdir, where the source code is deployed.

if that option is omitted, the default is to deploy in `/usr/local`, when invoking `make install`. In which case, you might need to use `su` or `sudo` when invoking `make install`.

Currently, only OpenSSL 1.0 is supported.

## Installation
### Linux
```bash
$ ./configure --prefix=$PWD
$ make
$ make install
```

### Linux, with opensssl statically linked
In case you need to deploy the tooklit on target environments, where openssl is not necessarily installed, you have the option to statically link the openssl library functions into the binaries. This results, obviously, into larger executables, but you get portable binaries that do not depend upon external libraries to run.

1. download openssl from http://www.openssl.org.
2. configure openssl the following way, then compile
   ```bash
   $ ./Configure zlib no-shared --prefix=$HOME/openssl linux-x86_64
   $ make install
   ```
   this will install openssl lib and include in $HOME/openssl.

3. proceed to ```pkcs11-tools``` directory, and configure to build against freshly compiled library
   ```bash
   $ CFLAGS=-I$HOME/openssl/include LDFLAGS=-L$HOME/openssl/lib LIBS="-lz -ldl" ./configure --prefix=$PWD
   $ make install
   ```

### AIX 7.1, 64 bits, IBM XLC compiler, statically linked to openssl
(replace *[OPENSSL_TARGET_DIR]* below with the actual target directory)

1. for openssl installation:
   ```bash
   $ PATH=/usr/vac/bin:$PATH
   $ ./Configure no-hw no-zlib no-shared --prefix=[OPENSSL_TARGET_DIR] aix64-cc
   $ make
   $ make install
   ```
2. For the toolkit installation:
   ```bash
   $ PATH=/usr/vac/bin:$PATH
   $ AR='ar -X64' CFLAGS='-q64 -qlanglvl=extc99 -I[OPENSSL_TARGET_DIR]/include' LDFLAGS=-L[OPENSSL_TARGET_DIR]/lib ./configure --prefix=$PWD -C
   $ make
   $ make install
   ```


### Solaris-sparc
#### Pre-requisites
You need to have GCC deployed on your computer. You can obtain and deploy GCC on your solaris plarform from [OpenCSW](https://www.opencsw.org/).

#### static build
1. Build a static openssl library. Please follow the same steps as for Linux or AIX (adapt target accordingly)
2. To buill 32 bits binaries:
   ```bash
   $ CFLAGS='-I$HOME/openssl/include' LDFLAGS=-L$HOME/openssl ./configure
   ```
   To build sparcv9 64 bits binaries:
   ```bash
   $ CFLAGS='-m64 -mcpu=ultrasparc3 -I$HOME/openssl/include' LDFLAGS=-L$HOME/openssl ./configure --prefix=$PWD
   ```
3. Compile and deploy
   ```bash
   $ make install
   ```
#### OpenCSW build
Alternatively, you could use the openssl library from [OpenCSW](https://www.opencsw.org/). This will result in dynamically linked executables; they are shorter in size, but they rely upon the shared libraries to execute on your target system.

When building with OpenCSW, you may have to prefix all the commands with `MAKE=gmake AR=gar` and use gmake instead of make in the examples above, or to change your path to point to `/opt/csw/gnu`:

```bash
$ export PATH=/opt/csw/gnu:$PATH
```

### Solaris x86
Same instructions as for Solaris Sparc, 32 bits.

### Windows (cross-compiling)
Cross-compilation works with mingw32-gcc under linux. [Debian](https://www.debian.org/) distros are offering off-the-shelf cross-compilers, so the examples below are assuming [Debian](https://www.debian.org/) as the build platform.

#### >To create 32 bits executables:
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

#### To create 64 bits executables:
##### Prerequisites
- install cross-compiler (debian package: `gcc-mingw-w64-x86_64`)
- install wine on your linux host (debian package: `wine64`)
- have an installation of OpenSSL-Win64 under wine ( see this [link](https://slproweb.com/products/Win32OpenSSL.html) referenced by OpenSSL): download the installer and execute with `wine Win64OpenSSL-1_0_XX.exe` (where `xx` represent the version.)
- in the project root directory, create a symbolic link to the OpenSSL-Win64 directory: (assuming that the DLLs are found in `$HOME/.wine/drive_c/OpenSSL-Win64 openssl-win64`)
```bash
$ ln -s $HOME/.wine/drive_c/OpenSSL-Win64 openssl-win64
```

##### To compile:
```bash
$ CFLAGS="-I$(pwd)/openssl-win64/include" LDFLAGS=-L$(pwd)/openssl-win32 ./configure --host=x86_64-w64-mingw32 --prefix=$PWD
$ make install
```

**********************************

### MacOS - with brew
This expects that brew is installed on MacOS. checkout https://brew.sh/ for more information.
```bash
$ eval $(brew shellenv)
$ CFLAGS=-I$HOMEBREW_PREFIX/opt/openssl/include LDFLAGS=-L$HOMEBREW_PREFIX/opt/openssl/lib ./configure [...]
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
