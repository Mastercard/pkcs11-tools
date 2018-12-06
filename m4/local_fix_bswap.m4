# Original GPL notice 
# from http://ftp.vim.org/NetBSD/NetBSD-current/xsrc/external/mit/xf86-video-ati/dist/configure.ac

#  Copyright 2005 Adam Jackson.
#
#  Permission is hereby granted, free of charge, to any person obtaining a
#  copy of this software and associated documentation files (the "Software"),
#  to deal in the Software without restriction, including without limitation
#  on the rights to use, copy, modify, merge, publish, distribute, sub
#  license, and/or sell copies of the Software, and to permit persons to whom
#  the Software is furnished to do so, subject to the following conditions:
#
#  The above copyright notice and this permission notice (including the next
#  paragraph) shall be included in all copies or substantial portions of the
#  Software.
#
#  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#  FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT.  IN NO EVENT SHALL
#  ADAM JACKSON BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
#  IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
#  CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#

AC_DEFUN([LOCAL_FIX_BSWAP],[

# Checks for headers/macros for byte swapping
# Known variants:
#	<byteswap.h> bswap_16, bswap_32, bswap_64  (glibc)
#	<sys/endian.h> __swap16, __swap32, __swap64 (OpenBSD)
#	<sys/endian.h> bswap16, bswap32, bswap64 (other BSD's)
#	and a fallback to local macros if none of the above are found

# if <byteswap.h> is found, assume it's the correct version
AC_CHECK_HEADERS([byteswap.h])

# if <sys/endian.h> is found, have to check which version
AC_CHECK_HEADER([sys/endian.h], [HAVE_SYS_ENDIAN_H="yes"], [HAVE_SYS_ENDIAN_H="no"])

if test "x$HAVE_SYS_ENDIAN_H" = "xyes" ; then
 AC_MSG_CHECKING([for __swap16 variant of <sys/endian.h> byteswapping macros])
 AC_LINK_IFELSE([AC_LANG_PROGRAM([
#include <sys/types.h>
#include <sys/endian.h>
 ], [
int a = 1, b;
b = __swap16(a);
 ])
], [SYS_ENDIAN__SWAP='yes'], [SYS_ENDIAN__SWAP='no'])
 AC_MSG_RESULT([$SYS_ENDIAN__SWAP])

 AC_MSG_CHECKING([for bswap16 variant of <sys/endian.h> byteswapping macros])
 AC_LINK_IFELSE([AC_LANG_PROGRAM([
#include <sys/types.h>
#include <sys/endian.h>
 ], [
int a = 1, b;
b = bswap16(a);
 ])
], [SYS_ENDIAN_BSWAP='yes'], [SYS_ENDIAN_BSWAP='no'])
 AC_MSG_RESULT([$SYS_ENDIAN_BSWAP])

	if test "$SYS_ENDIAN_BSWAP" = "yes" ; then
		USE_SYS_ENDIAN_H=yes
		BSWAP=bswap
	else	
	    	if test "$SYS_ENDIAN__SWAP" = "yes" ; then
			USE_SYS_ENDIAN_H=yes
			BSWAP=__swap
		else
			USE_SYS_ENDIAN_H=no
		fi
	fi

	if test "$USE_SYS_ENDIAN_H" = "yes" ; then
	    AC_DEFINE([USE_SYS_ENDIAN_H], 1, 
		[Define to use byteswap macros from <sys/endian.h>])
	    AC_DEFINE_UNQUOTED([bswap_16], ${BSWAP}16, 
			[Define to 16-bit byteswap macro])
	    AC_DEFINE_UNQUOTED([bswap_32], ${BSWAP}32, 
			[Define to 32-bit byteswap macro])
	    AC_DEFINE_UNQUOTED([bswap_64], ${BSWAP}64, 
			[Define to 64-bit byteswap macro])
	fi
fi
])dnl


dnl TODO:
dnl add Windows support
dnl _byteswap_ushort from <stdlib.h>
dnl _byteswap_ulong  from <stdlib.h>
dnl _byteswap_uint64 from <stdlib.h>
dnl https://msdn.microsoft.com/en-us/library/a3140177.aspx
