dnl Copyright (c) 2018 Mastercard

dnl Licensed under the Apache License, Version 2.0 (the "License");
dnl you may not use this file except in compliance with the License.
dnl You may obtain a copy of the License at

dnl   http://www.apache.org/licenses/LICENSE-2.0

dnl Unless required by applicable law or agreed to in writing, software
dnl distributed under the License is distributed on an "AS IS" BASIS,
dnl WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
dnl See the License for the specific language governing permissions and
dnl limitations under the License.


AC_PREREQ(2.59)
AC_INIT([pkcs11-tools], [1.0.3-devel], [https://github.com/Mastercard/pkcs11-tools/issues], [pkcs11-tools], [https://github.com/Mastercard/pkcs11-tools])
AC_CONFIG_MACRO_DIR([m4])

dnl adding AM_MAINTAINER_MODE to address autotools issues with git
AM_MAINTAINER_MODE

dnl pkginfo_pkgname contains the name of the package in Solaris packaging system
AC_SUBST([pkginfo_pkgname], MApkcs11tools)
dnl pkginfo_prefix contains the prefix for Solaris pkg build
dnl typical value is /usr/local
AC_SUBST([pkginfo_prefix], /usr/local)
dnl pkginfo_timestamp for pkginfo file, in dist/solaris
AC_SUBST([pkginfo_timestamp], $(LANG=C TZ=GMT date +%Y%m%d-%H%M%S))

dnl detection of cross-compilation
AC_CANONICAL_HOST
AC_CANONICAL_TARGET
AC_PROG_CC
AC_PATH_PROG([PERL],[perl])	dnl needed to execute scripts in lib directory
AC_PROG_MKDIR_P			dnl needed for dist/solaris build
AC_CHECK_PROGS([TAR], [gtar tar]) dnl need to find tar (GNU tar preferred)

dnl need FLEX, not LEX
dnl in case it is not there,
AC_PROG_LEX
if test "x$LEX" != xflex; then
   AC_MSG_WARN([flex 2.5.22+ is required to regenerate lexer. Generated source code is provided, so it should be OK, unless you change the lexer source file.])
fi

dnl need BISON, not YACC
AC_PROG_YACC
if test "x$YACC" != "xbison -y"; then
   AC_MSG_WARN([bison is required to regenerate parser. Generated source code is provided, so it should be OK, unless you change the parser source file.])
fi

gl_EARLY			dnl GNULIB early macro init
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AM_PROG_AR			dnl AM_PROG_AR is required on Solaris

LT_INIT				dnl libtool init
AC_PROG_LIBTOOL			dnl libtool init
gl_INIT				dnl GNULIB init

dnl detect if we are cross-compiling for mingw32
MINGW32=0
case "$host_os" in
  mingw32)
    MINGW32=1;
  ;;
esac

AM_CONDITIONAL([TARGET_OS_MINGW32], [test "$MINGW32" = "1"])

PKG_PROG_PKG_CONFIG
PKG_CHECK_MODULES([LIBCRYPTO],
	          [libcrypto < 1.1.0],
		  [ ac_save_CPPFLAGS=$CPPFLAGS
		    CPPFLAGS="${CPPFLAGS} ${LIBCRYPTO_CFLAGS}"
		    AC_CHECK_DECLS([OPENSSL_NO_RSA, OPENSSL_NO_DSA, OPENSSL_NO_DH, OPENSSL_NO_EC],
		                  [AC_MSG_FAILURE([The OpenSSL crypto library is missing features/algorithm to allow compilation])],
    				  [],
				  [[#include <openssl/opensslconf.h>]])
		    CPPFLAGS=${ac_save_CPPFLAGS} ])

dnl on UNIX platforms, check for dynamic loader lib
AM_COND_IF( [TARGET_OS_MINGW32],
	    [],
	    dnl UNIXish platforms
	    [	dnl find dynamic linker library
		AC_SEARCH_LIBS([dlopen], [dl dld], [], [AC_MSG_ERROR([unable to find the dlopen() function]) ])
		] )

AX_LIB_SOCKET_NSL		dnl needed on Solaris hosts, to add proper library nsl and socket
AX_WITH_DMALLOC			dnl the project can be compiled with dmalloc for memory debugging

dnl check if nCipher extensions can be compiled. If requested, specific file
AC_ARG_WITH([ncipher],
	[AS_HELP_STRING([--with-ncipher],
	[enable support for the nCipher extensions (requires a separate ncipher.h header file to compile)])],
        [],
        [with_ncipher=check])

hasncipher="no"
AS_IF([test "x$with_ncipher" != xno],
      [AS_IF([test -r $srcdir/include/cryptoki/ncipher.h],
              [AC_DEFINE([HAVE_NCIPHER], [1], [define to compile with the nCipher extensions.])
	      hasncipher="yes"
              ],
              [if test "x$with_ncipher" != xcheck; then
                 AC_MSG_FAILURE(
                   [--with-ncipher was given, but required ncipher.h include file missing])
               fi
              ] )])

dnl check endianness
AC_C_BIGENDIAN
dnl we need to know sizeof(long) for dealing with endianness conversion
AC_CHECK_SIZEOF([unsigned long int])

dnl try to find a proper bswap() function, defined in m4/local_fix_bswap.m4
LOCAL_FIX_BSWAP


dnl ========================================================================
AC_CONFIG_HEADERS([include/config.h])
AC_CONFIG_FILES([	gl/Makefile
			lib/Makefile
			src/Makefile
			Makefile
			dist/solaris/pkgproto
			dist/solaris/pkginfo
			dist/solaris/checkinstall
			dist/redhat/pkcs11-tools.spec])
AC_OUTPUT
AX_CREATE_TARGET_H([include/target.h])

AC_MSG_NOTICE([------------------------------------------------------------------------])
AC_MSG_NOTICE([compiler      : $CC])
AC_MSG_NOTICE([compiler flags: ${LIBCRYPTO_CFLAGS} $CFLAGS])
AC_MSG_NOTICE([linker        : $LD])
AC_MSG_NOTICE([linker flags  : $LDFLAGS ])
AC_MSG_NOTICE([libraries     : ${LIBCRYPTO_LIBS} $LIBS])
AC_MSG_NOTICE([lex           : $LEX])
AC_MSG_NOTICE([yacc          : $YACC])
AC_MSG_NOTICE([yacc flags    : $FLAGS])
AC_MSG_NOTICE([with_ncipher  : $hasncipher])
AC_MSG_NOTICE([------------------------------------------------------------------------])

