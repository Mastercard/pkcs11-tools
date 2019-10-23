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
	-I$(top_srcdir)/include/cryptoki

#AM_LDFLAGS = -L$(top_srcdir)/lib -L$(top_srcdir)/gl/lib

################################################################################
# libcommon

# libcommon contain code common to all executables.
# it is statically linked.

noinst_LIBRARIES = libcommon.a
libcommon_a_SOURCES = version.c

# special treat for minw32/windows build
if TARGET_OS_MINGW32
libcommon_a_SOURCES += win_applink.c
endif


################################################################################
# p11 toolkit

# the actual list of programs being compiled
bin_PROGRAMS = p11wrap p11unwrap p11cp p11ls p11cat p11more p11od p11rm p11mv p11slotinfo p11req p11importcert p11importpubk p11importdata p11keycomp p11setattr masqreq p11keygen p11kcv


SOURCES = $(bin_PROGRAMS:%=%.c)

LDADD = $(builddir)/libcommon.a $(top_builddir)/lib/libp11.la $(top_builddir)/gl/libgnu.a $(LIBCRYPTO_LIBS) $(GETHOSTNAME_LIB) $(LIBSOCKET) $(LIBINTL) $(LIBTHREAD)


#%.c: $(top_srcdir)/include/libpkcs11.h
$(SOURCES): $(top_srcdir)/include/pkcs11lib.h

#LDFLAGS = -static
