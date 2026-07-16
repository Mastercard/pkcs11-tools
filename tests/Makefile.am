# Copyright (c) 2025 Mastercard

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#   http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

################################################################################
# Test suite
#
# Two kinds of tests, both driven by `make check':
#   - unit tests: small C programs linked against libp11, testing pure helpers
#     that need no PKCS#11 token (they run everywhere);
#   - integration tests: POSIX shell scripts that drive the built CLI binaries
#     against a throwaway SoftHSM2 token. They self-skip (exit 77) when SoftHSM2
#     is not available, so `make check' stays green on build-only machines.
################################################################################

AM_CPPFLAGS = \
	-I$(top_builddir)/include \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/include/oasis-pkcs11/published/3-02 \
	-I$(top_srcdir)/include/cryptoki \
	-I$(top_builddir)/gl \
	-I$(top_srcdir)/gl

################################################################################
# Unit tests (compiled C programs)

check_PROGRAMS = unit/test_utils unit/test_ec unit/test_error unit/test_template unit/test_version unit/test_attribctx unit/test_wrappedkey unit/test_pqc

unit_test_utils_SOURCES = unit/test_utils.c unit/test_harness.h
unit_test_utils_CPPFLAGS = $(AM_CPPFLAGS) -I$(srcdir)/unit
unit_test_utils_CFLAGS = $(LIBCRYPTO_CFLAGS) $(PTHREAD_CFLAGS)
unit_test_utils_LDADD = \
	$(top_builddir)/lib/libp11.la \
	$(top_builddir)/gl/libgnu.a \
	$(LIBCRYPTO_LIBS) $(PTHREAD_LIBS) \
	$(GETHOSTNAME_LIB) $(LIBSOCKET) $(LIBINTL) $(LIBTHREAD)

unit_test_ec_SOURCES = unit/test_ec.c unit/test_harness.h
unit_test_ec_CPPFLAGS = $(AM_CPPFLAGS) -I$(srcdir)/unit
unit_test_ec_CFLAGS = $(LIBCRYPTO_CFLAGS) $(PTHREAD_CFLAGS)
unit_test_ec_LDADD = \
	$(top_builddir)/lib/libp11.la \
	$(top_builddir)/gl/libgnu.a \
	$(LIBCRYPTO_LIBS) $(PTHREAD_LIBS) \
	$(GETHOSTNAME_LIB) $(LIBSOCKET) $(LIBINTL) $(LIBTHREAD)

unit_test_error_SOURCES = unit/test_error.c unit/test_harness.h
unit_test_error_CPPFLAGS = $(AM_CPPFLAGS) -I$(srcdir)/unit
unit_test_error_CFLAGS = $(LIBCRYPTO_CFLAGS) $(PTHREAD_CFLAGS)
unit_test_error_LDADD = \
	$(top_builddir)/lib/libp11.la \
	$(top_builddir)/gl/libgnu.a \
	$(LIBCRYPTO_LIBS) $(PTHREAD_LIBS) \
	$(GETHOSTNAME_LIB) $(LIBSOCKET) $(LIBINTL) $(LIBTHREAD)

unit_test_template_SOURCES = unit/test_template.c unit/test_harness.h
unit_test_template_CPPFLAGS = $(AM_CPPFLAGS) -I$(srcdir)/unit
unit_test_template_CFLAGS = $(LIBCRYPTO_CFLAGS) $(PTHREAD_CFLAGS)
unit_test_template_LDADD = \
	$(top_builddir)/lib/libp11.la \
	$(top_builddir)/gl/libgnu.a \
	$(LIBCRYPTO_LIBS) $(PTHREAD_LIBS) \
	$(GETHOSTNAME_LIB) $(LIBSOCKET) $(LIBINTL) $(LIBTHREAD)

# test_version links libcommon.la for print_version_info() (src/version.c), so
# the unit test exercises the very object the shipped tools use.
unit_test_version_SOURCES = unit/test_version.c unit/test_harness.h
unit_test_version_CPPFLAGS = $(AM_CPPFLAGS) -I$(srcdir)/unit
unit_test_version_CFLAGS = $(LIBCRYPTO_CFLAGS) $(PTHREAD_CFLAGS)
unit_test_version_LDADD = \
	$(top_builddir)/src/libcommon.la \
	$(top_builddir)/lib/libp11.la \
	$(top_builddir)/gl/libgnu.a \
	$(LIBCRYPTO_LIBS) $(PTHREAD_LIBS) \
	$(GETHOSTNAME_LIB) $(LIBSOCKET) $(LIBINTL) $(LIBTHREAD)

# test_attribctx exercises the flex/bison attribute-context grammar
# (lib/attribctx_lexer.l + lib/attribctx_parser.y), reachable via the public
# pkcs11_parse_attribs_from_argv() API in libp11. Pure parser, no token needed.
unit_test_attribctx_SOURCES = unit/test_attribctx.c unit/test_harness.h
unit_test_attribctx_CPPFLAGS = $(AM_CPPFLAGS) -I$(srcdir)/unit
unit_test_attribctx_CFLAGS = $(LIBCRYPTO_CFLAGS) $(PTHREAD_CFLAGS)
unit_test_attribctx_LDADD = \
	$(top_builddir)/lib/libp11.la \
	$(top_builddir)/gl/libgnu.a \
	$(LIBCRYPTO_LIBS) $(PTHREAD_LIBS) \
	$(GETHOSTNAME_LIB) $(LIBSOCKET) $(LIBINTL) $(LIBTHREAD)

# test_wrappedkey exercises the flex/bison wrapping-job grammar
# (lib/wrappedkey_lexer.l + lib/wrappedkey_parser.y), reachable via the public
# pkcs11_prepare_wrappingctx() API in libp11. Pure parser, no token needed.
unit_test_wrappedkey_SOURCES = unit/test_wrappedkey.c unit/test_harness.h
unit_test_wrappedkey_CPPFLAGS = $(AM_CPPFLAGS) -I$(srcdir)/unit
unit_test_wrappedkey_CFLAGS = $(LIBCRYPTO_CFLAGS) $(PTHREAD_CFLAGS)
unit_test_wrappedkey_LDADD = \
	$(top_builddir)/lib/libp11.la \
	$(top_builddir)/gl/libgnu.a \
	$(LIBCRYPTO_LIBS) $(PTHREAD_LIBS) \
	$(GETHOSTNAME_LIB) $(LIBSOCKET) $(LIBINTL) $(LIBTHREAD)

# test_pqc exercises the Post-Quantum parameter-set registry (lib/pkcs11_pqc.c):
# pure table lookups and string formatting reachable via the public API in
# libp11. No token needed; self-skips when PQC support is not built in.
unit_test_pqc_SOURCES = unit/test_pqc.c unit/test_harness.h
unit_test_pqc_CPPFLAGS = $(AM_CPPFLAGS) -I$(srcdir)/unit
unit_test_pqc_CFLAGS = $(LIBCRYPTO_CFLAGS) $(PTHREAD_CFLAGS)
unit_test_pqc_LDADD = \
	$(top_builddir)/lib/libp11.la \
	$(top_builddir)/gl/libgnu.a \
	$(LIBCRYPTO_LIBS) $(PTHREAD_LIBS) \
	$(GETHOSTNAME_LIB) $(LIBSOCKET) $(LIBINTL) $(LIBTHREAD)

################################################################################
# Integration tests (shell scripts)

integration_tests = \
	integration/slotinfo.sh \
	integration/keygen_ls_req.sh \
	integration/symkeys_kcv.sh \
	integration/wrap_unwrap.sh \
	integration/attr_od.sh \
	integration/objmgmt.sh \
	integration/import.sh \
	integration/wrap_algos.sh \
	integration/rewrap.sh \
	integration/more.sh \
	integration/mkcert.sh \
	integration/masqreq.sh \
	integration/cat_extended.sh \
	integration/envelope.sh \
	integration/jwk.sh \
	integration/od_more.sh \
	integration/importpubk.sh \
	integration/init.sh \
	integration/init_validation.sh \
	integration/keytypes.sh \
	integration/setattr_cpmv.sh \
	integration/req_options.sh \
	integration/importcert.sh \
	integration/eddsa_sign.sh \
	integration/dsa_sign.sh \
	integration/wrap_privkey.sh \
	integration/mkcert_options.sh \
	integration/od_cat_types.sh \
	integration/filters.sh \
	integration/wrap_specifier.sh \
	integration/wrap_more.sh \
	integration/pubk_render.sh \
	integration/render_more_types.sh \
	integration/keygen_options.sh \
	integration/keygen_all_types.sh \
	integration/slotinfo_ec.sh \
	integration/pin_prompt.sh \
	integration/init_interactive.sh \
	integration/slot_prompt.sh \
	integration/version_option.sh \
	integration/usage_option.sh \
	integration/mock_keycomp.sh \
	integration/mock_faults.sh \
	integration/mock_init.sh \
	integration/mock_pqc.sh \
	integration/nss_mode.sh \
	integration/nss_wrap.sh

################################################################################
# Preload stub used to drive interactive password/PIN prompts from a pipe.
#
# Built as a standalone shared object (not linked against libp11, and compiled
# without the coverage flags so it never emits .gcda files). Preloading is a
# Unix mechanism (LD_PRELOAD on ELF, DYLD_INSERT_LIBRARIES on macOS), so the
# stub is built everywhere except Windows/MinGW; the tests that use it self-skip
# on platforms where preloading is unavailable. `cc -shared -fPIC' produces a
# usable module on both ELF systems and macOS (a Mach-O dylib under clang).

if TARGET_OS_MINGW32
# No LD_PRELOAD/DYLD on Windows/MinGW: skip building the stub entirely.
else
check_DATA = preload/notty.so mock/mock_pkcs11.so
CLEANFILES = preload/notty.so mock/mock_pkcs11.so

preload/notty.so: $(srcdir)/preload/notty.c
	$(AM_V_at)$(MKDIR_P) preload
	$(AM_V_CC)$(CC) -shared -fPIC -o $@ $(srcdir)/preload/notty.c

# Programmable mock PKCS#11 module. Unlike the notty stub it links libcrypto
# (it needs real RSA key material so p11keycomp's PKCS#1 unwrap round-trips and
# exotic wrap/derive paths run). Built as a loadable module the tools dlopen()
# via the usual C_GetFunctionList entry point. Its behaviour is driven entirely
# by MOCK_P11_* environment variables (default world + fault injection).
#
# It is compiled with only the cryptoki headers, deliberately WITHOUT the gnulib
# include directories: on platforms where gnulib replaces libc functions (e.g.
# FreeBSD, where <stdlib.h> gets `#define free rpl_free'), pulling in gl/ would
# make the module reference rpl_free & friends without linking libgnu, so
# dlopen() would fail with `Undefined symbol "rpl_free"'. The mock only needs
# plain libc, so it must not see the gnulib overrides.
MOCK_CPPFLAGS = \
	-I$(top_builddir)/include \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/include/oasis-pkcs11/published/3-02 \
	-I$(top_srcdir)/include/cryptoki

mock/mock_pkcs11.so: $(srcdir)/mock/mock_pkcs11.c
	$(AM_V_at)$(MKDIR_P) mock
	$(AM_V_CC)$(CC) -shared -fPIC $(MOCK_CPPFLAGS) $(LIBCRYPTO_CFLAGS) \
		-o $@ $(srcdir)/mock/mock_pkcs11.c $(LIBCRYPTO_LIBS)
endif

################################################################################
# Test harness registration

TESTS = $(check_PROGRAMS) $(integration_tests)

# Run *.sh tests through the shell (no need for the execute bit in the tree).
TEST_EXTENSIONS = .sh
SH_LOG_COMPILER = $(SHELL)

# Environment exported to every test. Make expands the $(...) variables; the
# shell sees plain values at run time.
AM_TESTS_ENVIRONMENT = \
	PKCS11_TOOLS_BINDIR='$(abs_top_builddir)/src'; export PKCS11_TOOLS_BINDIR; \
	PKCS11_TESTS_COMMON='$(abs_srcdir)/common.sh'; export PKCS11_TESTS_COMMON; \
	PKCS11_TESTS_MOCK_COMMON='$(abs_srcdir)/mock_common.sh'; export PKCS11_TESTS_MOCK_COMMON; \
	PKCS11_TESTS_NSS_COMMON='$(abs_srcdir)/nss_common.sh'; export PKCS11_TESTS_NSS_COMMON; \
	PKCS11_PRELOAD_NOTTY='$(abs_builddir)/preload/notty.so'; export PKCS11_PRELOAD_NOTTY; \
	PKCS11_MOCK='$(abs_builddir)/mock/mock_pkcs11.so'; export PKCS11_MOCK;

# Ship everything needed to run `make check' from a distribution tarball.
EXTRA_DIST = \
	common.sh \
	mock_common.sh \
	nss_common.sh \
	preload/notty.c \
	mock/mock_pkcs11.c \
	$(integration_tests)
