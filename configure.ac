dnl Copyright (c) 2018-2021 Mastercard

dnl Licensed under the Apache License, Version 2.0 (the "License");
dnl you may not use this file except in compliance with the License.
dnl You may obtain a copy of the License at

dnl   http://www.apache.org/licenses/LICENSE-2.0

dnl Unless required by applicable law or agreed to in writing, software
dnl distributed under the License is distributed on an "AS IS" BASIS,
dnl WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
dnl See the License for the specific language governing permissions and
dnl limitations under the License.


AC_PREREQ([2.64])
AC_INIT([pkcs11-tools], [2.6.0], [https://github.com/Mastercard/pkcs11-tools/issues], [pkcs11-tools], [https://github.com/Mastercard/pkcs11-tools])
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

dnl we enforce C99
AC_PROG_CC_C99
AS_IF([test "x$ac_cv_prog_cc_c99" == "no"],[AC_MSG_FAILURE([The C compiler '$CC' does not supports C99 standard.])],[])
gl_EARLY		dnl GNULIB early macro init
			dnl must be right after AC_PROG_CC_C99
			dnl according to domumentation


AC_PATH_PROG([PERL],[perl])	dnl needed to execute scripts in lib directory
AC_PROG_MKDIR_P			dnl needed for dist/solaris build
AC_CHECK_PROGS([TAR], [gtar tar]) dnl need to find tar (GNU tar preferred)

dnl we need FLEX, not LEX
AM_PROG_LEX([noyywrap])
AS_VAR_COPY([FLEX], [LEX])
AX_PROG_FLEX([],[AC_MSG_WARN([GNU flex is required to regenerate lexer. Generated source code is provided, so it should be OK, until you change the lexer source file. Hint: use LEX variable to point to flex on your system.])])
AX_PROG_FLEX_VERSION([2.5.0],[],[AC_MSG_WARN([GNU flex 2.5+ is required to regenerate lexer. Generated source code is provided, so it should be OK, until you change the lexer source file.])])

dnl we need BISON, not YACC
AC_PROG_YACC
AS_VAR_COPY([BISON], [YACC])
AX_PROG_BISON([],[AC_MSG_WARN([GNU bison is required to regenerate parser. Generated source code is provided, so it should be OK, until you change the parser source file.])])
AX_PROG_BISON_VERSION([3.0.0],[],[AC_MSG_WARN([GNU bison v3+ is required to regenerate parser. Generated source code is provided, so it should be OK, until you change the parser source file. Hint: use YACC variable to point to bison on your system.])])

AM_INIT_AUTOMAKE([-Wall -Werror foreign subdir-objects])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AM_PROG_AR			dnl AM_PROG_AR is required on Solaris

LT_INIT				dnl libtool init
AC_PROG_LIBTOOL			dnl libtool init
gl_INIT				dnl GNULIB init

dnl detect if we are cross-compiling for mingw32
AS_IF([test "x$host_os" == "xmingw32"],[mingw32=1],[mingw32=0])
AM_CONDITIONAL([TARGET_OS_MINGW32], [test "$mingw32" = "1"])
AM_CONDITIONAL([TARGET_OS_SOLARIS], [test "x$host_os" == "xsolaris2.10"])

PKG_PROG_PKG_CONFIG
dnl for libcrypto, we are first detecting libcrypo11,
dnl as older distros may still run on top of openssl 1.0,
dnl but have v1.1.x accessible through libcrypto11.pc file
dnl if libcrypto11 is detected, a guess is made that for redhat-based systems,
dnl the rpm package will have a "11" suffix in the nam; openssl_rpm_suffix variable
dnl is substituted for that purpose.

PKG_CHECK_MODULES([LIBCRYPTO],
	          [libcrypto11 >= 1.1.1e],
		  [ ac_save_CPPFLAGS=$CPPFLAGS
		    CPPFLAGS="${CPPFLAGS} ${LIBCRYPTO_CFLAGS}"
		    AC_CHECK_DECLS([OPENSSL_NO_RSA, OPENSSL_NO_DSA, OPENSSL_NO_DH, OPENSSL_NO_EC],
		                  [AC_MSG_FAILURE([The OpenSSL crypto library is missing features/algorithm to allow compilation])],
    				  [],
				  [[ #include <openssl/opensslconf.h> ]])
		    CPPFLAGS=${ac_save_CPPFLAGS}
		    AC_SUBST([openssl_rpm_suffix],[11])
		    ],
		    [ PKG_CHECK_MODULES([LIBCRYPTO],
					[libcrypto >= 1.1.1e],
				    	[ ac_save_CPPFLAGS=$CPPFLAGS
				      	  CPPFLAGS="${CPPFLAGS} ${LIBCRYPTO_CFLAGS}"
				      	  AC_CHECK_DECLS([OPENSSL_NO_RSA, OPENSSL_NO_DSA, OPENSSL_NO_DH, OPENSSL_NO_EC],
		                      	  	     	 [AC_MSG_FAILURE([The OpenSSL crypto library is missing features/algorithm to allow compilation])],
						     	 [],
						     	 [[ #include <openssl/opensslconf.h> ]])
					  CPPFLAGS=${ac_save_CPPFLAGS}
					  AC_SUBST([openssl_rpm_suffix],[]) ])])

dnl on UNIX platforms, check for dynamic loader lib
AM_COND_IF( [TARGET_OS_MINGW32],
	    [],
	    dnl UNIXish platforms
	    [	dnl find dynamic linker library
		AC_SEARCH_LIBS([dlopen], [dl dld], [], [AC_MSG_ERROR([unable to find the dlopen() function]) ]) ] )

AM_COND_IF( [TARGET_OS_SOLARIS],
	    [  dnl on Solaris, OpenSSL needs librt.so, and it is not advertised properly
	       AC_CHECK_LIB([rt], [clock_gettime]) ] )

AX_LIB_SOCKET_NSL		dnl needed on Solaris hosts, to add proper library nsl and socket
AX_WITH_DMALLOC			dnl the project can be compiled with dmalloc for memory debugging

dnl support for pthread is needed if we link with a statically-linked version of OpenSSL
AX_PTHREAD( [], [ AC_MSG_WARN(Caution: no pthread library found, might be an issue when linking)] )


dnl check if nCipher extensions can be compiled. If requested, specific file must exist in include/cryptoki
AC_ARG_WITH([ncipher],
	[AS_HELP_STRING([--with-ncipher],
	[enable support for the nCipher extensions (requires a separate ncipher.h header file inside include/cryptoki to compile)])],
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

hasduplicate="no"
AC_ARG_ENABLE([duplicate],
			[AS_HELP_STRING([--enable-duplicate],
			 	[allows the creation of duplicate objects])],
			[AC_DEFINE([HAVE_DUPLICATES_ENABLED],
				[1],
				[Flag used to enable duplicates])hasduplicate="yes"],
			[])

dnl check if Gemalto Luna extensions can be compiled. If requested, specific file must exist in include/cryptoki
AC_ARG_WITH([luna],
	[AS_HELP_STRING([--with-luna],
	[enable support for the Gemalto Safenet Luna extensions (requires a separate luna.h header file inside include/cryptoki to compile)])],
        [],
        [with_luna=check])

hasluna="no"
AS_IF([test "x$with_luna" != xno],
      [AS_IF([test -r $srcdir/include/cryptoki/luna.h],
              [AC_DEFINE([HAVE_LUNA], [1], [define to compile with the Gemalto Safenet Luna extensions.])
	      hasluna="yes"
              ],
              [if test "x$with_luna" != xcheck; then
                 AC_MSG_FAILURE(
                   [--with-luna was given, but required luna.h include file missing])
               fi
              ] )])

dnl check if aws CloudHSM extensions can be compiled. If requested, specific file must exist in include/cryptoki
dnl Note that awscloudhsm is set to "no" instead of "check" by default, as the file is shipped with source code
dnl and as enabling awscloudhsm disable support for template attributes on p11ls.
AC_ARG_WITH([awscloudhsm],
	[AS_HELP_STRING([--with-awscloudhsm],
	[enable support for the AWS CloudHSM extensions (requires a separate awscloudhsm.h header file inside include/cryptoki to compile)])],
        [],
        [with_awscloudhsm=no])

hasawscloudhsm="no"
AS_IF([test "x$with_awscloudhsm" != xno],
      [AS_IF([test -r $srcdir/include/cryptoki/awscloudhsm.h],
              [AC_DEFINE([HAVE_AWSCLOUDHSM], [1], [define to compile with the AWS CloudHSM extensions.])
	      hasawscloudhsm="yes"
              ],
              [if test "x$with_awscloudhsm" != xcheck; then
                 AC_MSG_FAILURE(
                   [--with-awscloudhsm was given, but required awscloudhsm.h include file missing])
               fi
              ] )])

dnl check if a specific rpath is provided when linking.
dnl this option is needed when openssl is not deployed to a system-wide location
AC_ARG_VAR([LIBCRYPTO_RPATH], 	[provide RPATH to LIBCRYPTO, e.g. LIBCRYPTO_RPATH=/usr/local/ssl/lib (useful when openssl is not deployed to a system-wide location)])
AM_CONDITIONAL([HAS_LIBCRYPTO_RPATH], [test "x$LIBCRYPTO_RPATH" != "x"])


AS_IF([test "x$with_libcrypto_rpath" != xno] && [test "x$with_libcrypto_rpath" != xyes],
      [AC_DEFINE([LIBCRYPTO_RPATH], [$with_libcrypto_rpath], [RPATH to libcrypto]) ])


dnl check endianness
AC_C_BIGENDIAN
dnl we need to know sizeof(long) for dealing with endianness conversion
AC_CHECK_SIZEOF([unsigned long int])


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
AC_MSG_NOTICE([compiler           : $CC])
AC_MSG_NOTICE([compiler flags     : ${LIBCRYPTO_CFLAGS} ${PTHREAD_CFLAGS} $CFLAGS])
AC_MSG_NOTICE([linker             : $LD])
AC_MSG_NOTICE([linker flags       : $LDFLAGS])
AC_MSG_NOTICE([libraries          : ${LIBCRYPTO_LIBS} ${PTHREAD_LIBS} $LIBS])
AC_MSG_NOTICE([lexer              : $LEX])
AC_MSG_NOTICE([parser             : $YACC])
AC_MSG_NOTICE([parser flags       : $YFLAGS])
AC_MSG_NOTICE([with_luna          : $hasluna])
AC_MSG_NOTICE([with_ncipher       : $hasncipher])
AC_MSG_NOTICE([with_awscloudhsm   : $hasawscloudhsm])
AC_MSG_NOTICE([libcrypto rpath    : $LIBCRYPTO_RPATH])
AC_MSG_NOTICE([enable_duplicate   : $hasduplicate])
AC_MSG_NOTICE([------------------------------------------------------------------------])

