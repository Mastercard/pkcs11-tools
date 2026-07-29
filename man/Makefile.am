# Copyright (c) 2026 Mastercard

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#   http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Manual pages are authored in markdown (*.N.md) and converted to roff with
# pandoc. pandoc is optional: when it is not available, the pre-generated
# pages shipped in the distribution tarball are installed instead.


MAN1_PAGES = \
	masqreq.1 \
	p11cat.1 \
	p11cp.1 \
	p11importcert.1 \
	p11importdata.1 \
	p11importpubk.1 \
	p11init.1 \
	p11kcv.1 \
	p11keycomp.1 \
	p11keygen.1 \
	p11ls.1 \
	p11mkcert.1 \
	p11more.1 \
	p11mv.1 \
	p11od.1 \
	p11req.1 \
	p11rewrap.1 \
	p11rm.1 \
	p11setattr.1 \
	p11slotinfo.1 \
	p11unwrap.1 \
	p11wrap.1 \
	with_pkcs11_common.1

MAN1_LINKS = \
	with_aws.1 \
	with_beid.1 \
	with_kryoptic.1 \
	with_luna.1 \
	with_nfast.1 \
	with_nss.1 \
	with_softhsm.1 \
	with_utimaco.1 \
	with_yubico.1

MAN5_PAGES = \
	pkcs11-wrap.5 \
	pkcs11rc.5

MAN7_PAGES = \
	pkcs11-tools.7

ALL_MANPAGES = $(MAN1_PAGES) $(MAN1_LINKS) $(MAN5_PAGES) $(MAN7_PAGES)

MARKDOWN_PAGES = \
	masqreq.1.md \
	p11cat.1.md \
	p11cp.1.md \
	p11importcert.1.md \
	p11importdata.1.md \
	p11importpubk.1.md \
	p11init.1.md \
	p11kcv.1.md \
	p11keycomp.1.md \
	p11keygen.1.md \
	p11ls.1.md \
	p11mkcert.1.md \
	p11more.1.md \
	p11mv.1.md \
	p11od.1.md \
	p11req.1.md \
	p11rewrap.1.md \
	p11rm.1.md \
	p11setattr.1.md \
	p11slotinfo.1.md \
	p11unwrap.1.md \
	p11wrap.1.md \
	with_pkcs11_common.1.md \
	pkcs11-wrap.5.md \
	pkcs11rc.5.md \
	pkcs11-tools.7.md

HTML_PAGES = $(MARKDOWN_PAGES:.md=.html)

# metadata injected into every page; MAN_DATE is bumped manually when the
# manual pages are substantially revised, to keep builds reproducible.
MAN_DATE = 2026-07-29
PANDOC_FLAGS = -s -f markdown -t man \
	-V header="pkcs11-tools" \
	-V footer="pkcs11-tools @PACKAGE_VERSION@" \
	-V date="$(MAN_DATE)"

PANDOC_HTML_FLAGS = -s -f markdown -t html \
	-M title-prefix="pkcs11-tools" \
	-V date="$(MAN_DATE)"

if HAVE_PANDOC
man_MANS = $(ALL_MANPAGES)
else
if HAVE_PREBUILT_MANPAGES
man_MANS = $(ALL_MANPAGES)
else
man_MANS =
endif
endif

EXTRA_DIST = $(MARKDOWN_PAGES)

# The generated pages are built as part of 'make all' when pandoc is available,
# so that 'make install' and the packaging recipes always find them.
if HAVE_PANDOC
all-local: $(ALL_MANPAGES)
DIST_HOOK_DEPS = $(ALL_MANPAGES)
else
DIST_HOOK_DEPS =
endif

if HAVE_PANDOC
CLEANFILES = $(ALL_MANPAGES) $(HTML_PAGES)
else
CLEANFILES =
endif

# HTML rendition of the manual pages, used for platforms without a man(1)
# command (e.g. Windows builds). Not installed by default.
html-manpages: $(HTML_PAGES)

.PHONY: html-manpages


masqreq.1: $(srcdir)/masqreq.1.md
	$(AM_V_GEN)$(PANDOC) $(PANDOC_FLAGS) -o $@ $(srcdir)/masqreq.1.md

p11cat.1: $(srcdir)/p11cat.1.md
	$(AM_V_GEN)$(PANDOC) $(PANDOC_FLAGS) -o $@ $(srcdir)/p11cat.1.md

p11cp.1: $(srcdir)/p11cp.1.md
	$(AM_V_GEN)$(PANDOC) $(PANDOC_FLAGS) -o $@ $(srcdir)/p11cp.1.md

p11importcert.1: $(srcdir)/p11importcert.1.md
	$(AM_V_GEN)$(PANDOC) $(PANDOC_FLAGS) -o $@ $(srcdir)/p11importcert.1.md

p11importdata.1: $(srcdir)/p11importdata.1.md
	$(AM_V_GEN)$(PANDOC) $(PANDOC_FLAGS) -o $@ $(srcdir)/p11importdata.1.md

p11importpubk.1: $(srcdir)/p11importpubk.1.md
	$(AM_V_GEN)$(PANDOC) $(PANDOC_FLAGS) -o $@ $(srcdir)/p11importpubk.1.md

p11init.1: $(srcdir)/p11init.1.md
	$(AM_V_GEN)$(PANDOC) $(PANDOC_FLAGS) -o $@ $(srcdir)/p11init.1.md

p11kcv.1: $(srcdir)/p11kcv.1.md
	$(AM_V_GEN)$(PANDOC) $(PANDOC_FLAGS) -o $@ $(srcdir)/p11kcv.1.md

p11keycomp.1: $(srcdir)/p11keycomp.1.md
	$(AM_V_GEN)$(PANDOC) $(PANDOC_FLAGS) -o $@ $(srcdir)/p11keycomp.1.md

p11keygen.1: $(srcdir)/p11keygen.1.md
	$(AM_V_GEN)$(PANDOC) $(PANDOC_FLAGS) -o $@ $(srcdir)/p11keygen.1.md

p11ls.1: $(srcdir)/p11ls.1.md
	$(AM_V_GEN)$(PANDOC) $(PANDOC_FLAGS) -o $@ $(srcdir)/p11ls.1.md

p11mkcert.1: $(srcdir)/p11mkcert.1.md
	$(AM_V_GEN)$(PANDOC) $(PANDOC_FLAGS) -o $@ $(srcdir)/p11mkcert.1.md

p11more.1: $(srcdir)/p11more.1.md
	$(AM_V_GEN)$(PANDOC) $(PANDOC_FLAGS) -o $@ $(srcdir)/p11more.1.md

p11mv.1: $(srcdir)/p11mv.1.md
	$(AM_V_GEN)$(PANDOC) $(PANDOC_FLAGS) -o $@ $(srcdir)/p11mv.1.md

p11od.1: $(srcdir)/p11od.1.md
	$(AM_V_GEN)$(PANDOC) $(PANDOC_FLAGS) -o $@ $(srcdir)/p11od.1.md

p11req.1: $(srcdir)/p11req.1.md
	$(AM_V_GEN)$(PANDOC) $(PANDOC_FLAGS) -o $@ $(srcdir)/p11req.1.md

p11rewrap.1: $(srcdir)/p11rewrap.1.md
	$(AM_V_GEN)$(PANDOC) $(PANDOC_FLAGS) -o $@ $(srcdir)/p11rewrap.1.md

p11rm.1: $(srcdir)/p11rm.1.md
	$(AM_V_GEN)$(PANDOC) $(PANDOC_FLAGS) -o $@ $(srcdir)/p11rm.1.md

p11setattr.1: $(srcdir)/p11setattr.1.md
	$(AM_V_GEN)$(PANDOC) $(PANDOC_FLAGS) -o $@ $(srcdir)/p11setattr.1.md

p11slotinfo.1: $(srcdir)/p11slotinfo.1.md
	$(AM_V_GEN)$(PANDOC) $(PANDOC_FLAGS) -o $@ $(srcdir)/p11slotinfo.1.md

p11unwrap.1: $(srcdir)/p11unwrap.1.md
	$(AM_V_GEN)$(PANDOC) $(PANDOC_FLAGS) -o $@ $(srcdir)/p11unwrap.1.md

p11wrap.1: $(srcdir)/p11wrap.1.md
	$(AM_V_GEN)$(PANDOC) $(PANDOC_FLAGS) -o $@ $(srcdir)/p11wrap.1.md

with_pkcs11_common.1: $(srcdir)/with_pkcs11_common.1.md
	$(AM_V_GEN)$(PANDOC) $(PANDOC_FLAGS) -o $@ $(srcdir)/with_pkcs11_common.1.md

pkcs11-wrap.5: $(srcdir)/pkcs11-wrap.5.md
	$(AM_V_GEN)$(PANDOC) $(PANDOC_FLAGS) -o $@ $(srcdir)/pkcs11-wrap.5.md

pkcs11rc.5: $(srcdir)/pkcs11rc.5.md
	$(AM_V_GEN)$(PANDOC) $(PANDOC_FLAGS) -o $@ $(srcdir)/pkcs11rc.5.md

pkcs11-tools.7: $(srcdir)/pkcs11-tools.7.md
	$(AM_V_GEN)$(PANDOC) $(PANDOC_FLAGS) -o $@ $(srcdir)/pkcs11-tools.7.md

masqreq.1.html: $(srcdir)/masqreq.1.md
	$(AM_V_GEN)$(PANDOC) $(PANDOC_HTML_FLAGS) -o $@ $(srcdir)/masqreq.1.md

p11cat.1.html: $(srcdir)/p11cat.1.md
	$(AM_V_GEN)$(PANDOC) $(PANDOC_HTML_FLAGS) -o $@ $(srcdir)/p11cat.1.md

p11cp.1.html: $(srcdir)/p11cp.1.md
	$(AM_V_GEN)$(PANDOC) $(PANDOC_HTML_FLAGS) -o $@ $(srcdir)/p11cp.1.md

p11importcert.1.html: $(srcdir)/p11importcert.1.md
	$(AM_V_GEN)$(PANDOC) $(PANDOC_HTML_FLAGS) -o $@ $(srcdir)/p11importcert.1.md

p11importdata.1.html: $(srcdir)/p11importdata.1.md
	$(AM_V_GEN)$(PANDOC) $(PANDOC_HTML_FLAGS) -o $@ $(srcdir)/p11importdata.1.md

p11importpubk.1.html: $(srcdir)/p11importpubk.1.md
	$(AM_V_GEN)$(PANDOC) $(PANDOC_HTML_FLAGS) -o $@ $(srcdir)/p11importpubk.1.md

p11init.1.html: $(srcdir)/p11init.1.md
	$(AM_V_GEN)$(PANDOC) $(PANDOC_HTML_FLAGS) -o $@ $(srcdir)/p11init.1.md

p11kcv.1.html: $(srcdir)/p11kcv.1.md
	$(AM_V_GEN)$(PANDOC) $(PANDOC_HTML_FLAGS) -o $@ $(srcdir)/p11kcv.1.md

p11keycomp.1.html: $(srcdir)/p11keycomp.1.md
	$(AM_V_GEN)$(PANDOC) $(PANDOC_HTML_FLAGS) -o $@ $(srcdir)/p11keycomp.1.md

p11keygen.1.html: $(srcdir)/p11keygen.1.md
	$(AM_V_GEN)$(PANDOC) $(PANDOC_HTML_FLAGS) -o $@ $(srcdir)/p11keygen.1.md

p11ls.1.html: $(srcdir)/p11ls.1.md
	$(AM_V_GEN)$(PANDOC) $(PANDOC_HTML_FLAGS) -o $@ $(srcdir)/p11ls.1.md

p11mkcert.1.html: $(srcdir)/p11mkcert.1.md
	$(AM_V_GEN)$(PANDOC) $(PANDOC_HTML_FLAGS) -o $@ $(srcdir)/p11mkcert.1.md

p11more.1.html: $(srcdir)/p11more.1.md
	$(AM_V_GEN)$(PANDOC) $(PANDOC_HTML_FLAGS) -o $@ $(srcdir)/p11more.1.md

p11mv.1.html: $(srcdir)/p11mv.1.md
	$(AM_V_GEN)$(PANDOC) $(PANDOC_HTML_FLAGS) -o $@ $(srcdir)/p11mv.1.md

p11od.1.html: $(srcdir)/p11od.1.md
	$(AM_V_GEN)$(PANDOC) $(PANDOC_HTML_FLAGS) -o $@ $(srcdir)/p11od.1.md

p11req.1.html: $(srcdir)/p11req.1.md
	$(AM_V_GEN)$(PANDOC) $(PANDOC_HTML_FLAGS) -o $@ $(srcdir)/p11req.1.md

p11rewrap.1.html: $(srcdir)/p11rewrap.1.md
	$(AM_V_GEN)$(PANDOC) $(PANDOC_HTML_FLAGS) -o $@ $(srcdir)/p11rewrap.1.md

p11rm.1.html: $(srcdir)/p11rm.1.md
	$(AM_V_GEN)$(PANDOC) $(PANDOC_HTML_FLAGS) -o $@ $(srcdir)/p11rm.1.md

p11setattr.1.html: $(srcdir)/p11setattr.1.md
	$(AM_V_GEN)$(PANDOC) $(PANDOC_HTML_FLAGS) -o $@ $(srcdir)/p11setattr.1.md

p11slotinfo.1.html: $(srcdir)/p11slotinfo.1.md
	$(AM_V_GEN)$(PANDOC) $(PANDOC_HTML_FLAGS) -o $@ $(srcdir)/p11slotinfo.1.md

p11unwrap.1.html: $(srcdir)/p11unwrap.1.md
	$(AM_V_GEN)$(PANDOC) $(PANDOC_HTML_FLAGS) -o $@ $(srcdir)/p11unwrap.1.md

p11wrap.1.html: $(srcdir)/p11wrap.1.md
	$(AM_V_GEN)$(PANDOC) $(PANDOC_HTML_FLAGS) -o $@ $(srcdir)/p11wrap.1.md

with_pkcs11_common.1.html: $(srcdir)/with_pkcs11_common.1.md
	$(AM_V_GEN)$(PANDOC) $(PANDOC_HTML_FLAGS) -o $@ $(srcdir)/with_pkcs11_common.1.md

pkcs11-wrap.5.html: $(srcdir)/pkcs11-wrap.5.md
	$(AM_V_GEN)$(PANDOC) $(PANDOC_HTML_FLAGS) -o $@ $(srcdir)/pkcs11-wrap.5.md

pkcs11rc.5.html: $(srcdir)/pkcs11rc.5.md
	$(AM_V_GEN)$(PANDOC) $(PANDOC_HTML_FLAGS) -o $@ $(srcdir)/pkcs11rc.5.md

pkcs11-tools.7.html: $(srcdir)/pkcs11-tools.7.md
	$(AM_V_GEN)$(PANDOC) $(PANDOC_HTML_FLAGS) -o $@ $(srcdir)/pkcs11-tools.7.md

with_aws.1:
	$(AM_V_GEN)echo '.so man1/with_pkcs11_common.1' > $@

with_beid.1:
	$(AM_V_GEN)echo '.so man1/with_pkcs11_common.1' > $@

with_kryoptic.1:
	$(AM_V_GEN)echo '.so man1/with_pkcs11_common.1' > $@

with_luna.1:
	$(AM_V_GEN)echo '.so man1/with_pkcs11_common.1' > $@

with_nfast.1:
	$(AM_V_GEN)echo '.so man1/with_pkcs11_common.1' > $@

with_nss.1:
	$(AM_V_GEN)echo '.so man1/with_pkcs11_common.1' > $@

with_softhsm.1:
	$(AM_V_GEN)echo '.so man1/with_pkcs11_common.1' > $@

with_utimaco.1:
	$(AM_V_GEN)echo '.so man1/with_pkcs11_common.1' > $@

with_yubico.1:
	$(AM_V_GEN)echo '.so man1/with_pkcs11_common.1' > $@


# The generated manual pages are added to the distribution tarball, so that it
# can be built and installed without pandoc. When pandoc is available they are
# (re)generated first; otherwise the pages already present in the source tree
# (i.e. those of a distribution tarball) are used.
dist-hook: $(DIST_HOOK_DEPS)
	@for f in $(ALL_MANPAGES); do \
		if test -f $$f; then \
			cp -p $$f $(distdir)/$$f; \
		elif test -f $(srcdir)/$$f; then \
			cp -p $(srcdir)/$$f $(distdir)/$$f; \
		else \
			echo "warning: manual page $$f is missing from the distribution (pandoc not available)" >&2; \
		fi; \
	done
