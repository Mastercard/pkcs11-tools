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

EXTRA_DIST = \
	m4/ax_create_target_h.m4 \
	m4/ax_lib_socket_nsl.m4  \
	m4/ax_with_dmalloc.m4	 \
	include/cryptoki	 \
	include/pkcs11lib.h      \
	include/oasis-pkcs11/published/3-02 \
	with_beid	         \
	with_luna	         \
	with_nfast               \
	with_nss                 \
	with_softhsm             \
	with_utimaco	         \
	with_aws		 \
	docs/INSTALL.md	         \
	docs/CONTRIBUTING.md     \
	docs/MANUAL.md           \
	docs/TPLICENSES.md	 \
	README.md                \
	LICENSE.md               \
	CHANGELOG.md             \
	COPYING


SUBDIRS = gl lib src

ACLOCAL_AMFLAGS = -I m4


completionsdir = $(datadir)/bash-completion/completions
completions_DATA = \
	completion/bash/p11-common \
	completion/bash/p11cat \
	completion/bash/p11cp \
	completion/bash/p11importcert \
	completion/bash/p11importdata \
	completion/bash/p11importpubk \
	completion/bash/p11init \
	completion/bash/p11kcv \
	completion/bash/p11keycomp \
	completion/bash/p11keygen \
	completion/bash/p11ls \
	completion/bash/p11mkcert \
	completion/bash/p11more \
	completion/bash/p11mv \
	completion/bash/p11od \
	completion/bash/p11req \
	completion/bash/p11rewrap \
	completion/bash/p11rm \
	completion/bash/p11setattr \
	completion/bash/p11slotinfo \
	completion/bash/p11unwrap \
	completion/bash/p11wrap
EXTRA_DIST += $(completions_DATA)


zshcompletionsdir = $(datadir)/zsh/site-functions
zshcompletions_DATA = _p11tools
EXTRA_DIST += completion/zsh/_p11tools.in
CLEANFILES = $(zshcompletions_DATA)

_p11tools: $(srcdir)/completion/zsh/_p11tools.in Makefile
	@# Replace @COMPLETIONSDIR@ with the actual completionsdir path
	sed "s|@COMPLETIONSDIR@|$(completionsdir)|g" $(srcdir)/completion/zsh/_p11tools.in > $@


install-exec-hook:
	$(INSTALL) 	               \
		$(srcdir)/with_beid    \
		$(srcdir)/with_luna    \
		$(srcdir)/with_nfast   \
		$(srcdir)/with_nss     \
		$(srcdir)/with_softhsm \
		$(srcdir)/with_utimaco \
		$(srcdir)/with_aws     \
		$(DESTDIR)$(bindir)

dist-hook:
	-rm -rf $$(find $(distdir)/include -type d -name .svn)

dist-solaris: install
	-$(MKDIR_P) pkg
	cp COPYING README.md CHANGELOG.md LICENSE.md docs
	pkgmk -o -f dist/solaris/pkgproto -p @pkginfo_timestamp@ -r . -d pkg
	@echo
	pkgtrans pkg ../$(distdir).pkg @pkginfo_pkgname@
	rm docs/COPYING docs/README.md docs/CHANGELOG.md docs/LICENSE.md docs/TPLICENSES.md
	@echo "----------------------------------"
	@echo "package saved under $(distdir).pkg"
	@echo


dist-bin:
	@$(TAR) -cvf @PACKAGE_TARNAME@-bin-$(target_triplet)-@PACKAGE_VERSION@.tar bin
