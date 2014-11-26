# Written by Simon Josefsson <simon@josefsson.org>.
# Copyright (c) 2006-2014 Yubico AB
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
#   * Redistributions of source code must retain the above copyright
#      notice, this list of conditions and the following disclaimer.
#
#   * Redistributions in binary form must reproduce the above
#      copyright notice, this list of conditions and the following
#      disclaimer in the documentation and/or other materials provided
#      with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

SUBDIRS=. tests

ACLOCAL_AMFLAGS = -I m4

DISTCHECK_CONFIGURE_FLAGS = --enable-gcc-warnings

AM_CFLAGS = $(WARN_CFLAGS)

# The library.

lib_LTLIBRARIES = libyubikey.la
include_HEADERS = yubikey.h

libyubikey_la_SOURCES = yktoken.c ykhex.c ykcrc.c ykaes.c
libyubikey_la_SOURCES += libyubikey.map
libyubikey_la_LDFLAGS = -no-undefined \
	-version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE)

if HAVE_LD_VERSION_SCRIPT
libyubikey_la_LDFLAGS += -Wl,--version-script=$(srcdir)/libyubikey.map
else
libyubikey_la_LDFLAGS += -export-symbols-regex '^yubikey_.*'
endif

# The command line tools.

bin_PROGRAMS = modhex ykparse ykgenerate

modhex_SOURCES = modhex.c
modhex_LDADD = ./libyubikey.la

ykparse_SOURCES = ykparse.c
ykparse_LDADD = ./libyubikey.la

ykgenerate_SOURCES = ykgenerate.c
ykgenerate_LDADD = ./libyubikey.la

dist_man_MANS = modhex.1 ykparse.1 ykgenerate.1
DISTCLEANFILES = $(dist_man_MANS)

SUFFIXES = .1.txt .1
.1.txt.1:
	$(A2X) --format=manpage -a revdate="Version $(VERSION)" $<

MANSOURCES = modhex.1.txt ykparse.1.txt ykgenerate.1.txt
EXTRA_DIST = $(MANSOURCES) simple.mk THANKS

# Maintainer rules

indent:
	indent *.c *.h tests/*.c
	indent *.c *.h tests/*.c

ChangeLog:
	cd $(srcdir) && git2cl > ChangeLog

PROJECT = yubico-c

release:
	@if test -z "$(KEYID)"; then \
		echo "Try this instead:"; \
		echo "  make release KEYID=[PGPKEYID]"; \
		echo "For example:"; \
		echo "  make release KEYID=2117364A"; \
		exit 1; \
	fi
	@if test ! -d "$(YUBICO_WWW_REPO)"; then \
		echo "yubico www repo not found!"; \
		echo "Make sure that YUBICO_WWW_REPO is set"; \
		exit 1; \
	fi
	@head -3 $(srcdir)/NEWS | grep -q "Version $(VERSION) .released `date -I`" || \
		(echo 'error: You need to update date/version in $(srcdir)/NEWS'; exit 1)
	rm -f $(srcdir)/ChangeLog
	make ChangeLog distcheck
	gpg --detach-sign --default-key $(KEYID) $(PACKAGE)-$(VERSION).tar.gz
	gpg --verify $(PACKAGE)-$(VERSION).tar.gz.sig
	cd $(srcdir) && git push
	cd $(srcdir) && git tag -u $(KEYID) -m $(VERSION) $(PACKAGE)-$(VERSION)
	cd $(srcdir) && git push --tags
	$(YUBICO_WWW_REPO)/save-mans $(PROJECT) $(MANSOURCES)
	$(YUBICO_WWW_REPO)/publish $(PROJECT) $(VERSION) $(PACKAGE)-$(VERSION).tar.gz*
