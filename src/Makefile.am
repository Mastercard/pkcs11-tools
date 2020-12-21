# Copyright (c) 2018 Mastercard

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#   http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

AM_CPPFLAGS = \
	-I$(top_builddir)/gl \
	-I$(top_srcdir)/gl \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/include/oasis-pkcs11/working/3-00-current \
	-I$(top_srcdir)/include/cryptoki

AM_CFLAGS = $(LIBCRYPTO_CFLAGS)

if HAS_LIBCRYPTO_RPATH
AM_LDFLAGS = -rpath $(LIBCRYPTO_RPATH)
endif

################################################################################
# libcommon

# libcommon contain code common to all executables.
# it is statically linked.

noinst_LTLIBRARIES = libcommon.la
libcommon_la_SOURCES = version.c

libcommon_la_CFLAGS = $(LIBCRYPTO_CFLAGS)
libcommon_la_LDFLAGS = -static

################################################################################
# p11 toolkit

# the actual list of programs being compiled
bin_PROGRAMS = p11mkcert p11rewrap p11wrap p11unwrap p11cp p11ls p11cat p11more p11od p11rm p11mv p11slotinfo p11req p11importcert p11importpubk p11importdata p11keycomp p11setattr masqreq p11keygen p11kcv


SOURCES = $(bin_PROGRAMS:%=%.c)

LDADD = libcommon.la $(top_builddir)/lib/libp11.la $(top_builddir)/gl/libgnu.a $(LIBCRYPTO_LIBS) $(GETHOSTNAME_LIB) $(LIBSOCKET) $(LIBINTL) $(LIBTHREAD)

$(SOURCES): $(top_srcdir)/include/pkcs11lib.h

