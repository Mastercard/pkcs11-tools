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


SUFFIXES = .c .h .y .l

ACLOCAL_AMFLAGS= -I m4

AM_YFLAGS= -d

AM_CPPFLAGS = \
	-I$(top_builddir)/gl \
	-I$(top_srcdir)/gl \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/include/cryptoki

noinst_LTLIBRARIES = libp11.la

# pick appropriate low-level routines file

if TARGET_OS_MINGW32
libp11_la_SOURCES = pkcs11_ll_win.c
else
libp11_la_SOURCES = pkcs11_ll_unix.c
endif

libp11_la_SOURCES += pkcs11_attr.c \
	wrappedkey_parser.c wrappedkey_parser.h \
	wrappedkey_lexer.c wrappedkey_lexer.h \
	wrappedkey_helper.c wrappedkey_helper.h \
	pkcs11_wctx.c \
	pkcs11_wrap.c \
	pkcs11_unwrap.c \
	pkcs11_random.c \
	pkcs11_chattr.c \
	pkcs11_od.c \
	pkcs11_cat.c \
	pkcs11_more.c \
	pkcs11_cp.c \
	pkcs11_error.c \
	pkcs11_context.c \
	pkcs11_session.c \
	pkcs11_template.c \
	pkcs11_kcv.c \
	pkcs11_keycomp.c \
	pkcs11_keygen.c \
	pkcs11_ls.c \
	pkcs11_masq.c \
	pkcs11_mechanism.c \
	pkcs11_attrdesc.c \
	pkcs11_mv.c \
	pkcs11_peekpoke.c \
	pkcs11_req.c \
	pkcs11_rm.c \
	pkcs11_search.c \
	pkcs11_slotinfo.c \
	pkcs11_utils.c \
	pkcs11_x509.c \
	pkcs11_pubk.c \
	pkcs11_data.c \
	pkcs11_ec.c \
	pkcs11_openssl.c \
	pkcs11_dsa.c \
	pkcs11_dh.c



dist_libp11_la_SOURCES = gen_attrinfo_h.pl gen_mechinfo_h.pl wrappedkey_parser.y wrappedkey_lexer.l

# because it may be tricky to use bison and flex on the target environment,
# we ship the generated lexer and parser.
# in case they are modified, the rules below should cover
wrappedkey_parser.c wrappedkey_parser.h: wrappedkey_parser.y wrappedkey_lexer.h
wrappedkey_lexer.c wrappedkey_lexer.h: wrappedkey_lexer.l
wrappedkey_helper.c wrappedkey_helper.h: wrappedkey_lexer.c wrappedkey_lexer.h wrappedkey_parser.c wrappedkey_parser.h
wrappedkey_helper.c: wrappedkey_helper.h

CLEANFILES = _mechinfo.h _attrinfo.h 
BUILT_SOURCES = _mechinfo.h _attrinfo.h


pkcs11_mechanism.$(OBJEXT): _mechinfo.h

_mechinfo.h: Makefile gen_mechinfo_h.pl
	$(PERL) $(srcdir)/gen_mechinfo_h.pl $(top_srcdir)/include/cryptoki/*.h >$@

pkcs11_attrdesc.$(OBJEXT): _attrinfo.h

_attrinfo.h: Makefile gen_attrinfo_h.pl
	$(PERL) $(srcdir)/gen_attrinfo_h.pl $(top_srcdir)/include/cryptoki/*.h >$@


