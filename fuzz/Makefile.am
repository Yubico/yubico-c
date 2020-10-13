# Copyright (C) 2020 Yubico AB - See COPYING

AM_CPPFLAGS = -I$(srcdir)/.. -Wno-pointer-sign -g
AM_CPPFLAGS+=-fsanitize=fuzzer,address,signed-integer-overflow
AM_CPPFLAGS+=-fno-sanitize-recover=all

fuzz_libyubikey_SOURCES = fuzz_libyubikey.c

fuzz_libyubikey_LDADD = ../.libs/libyubikey.a
fuzz_libyubikey_LDFLAGS = -fsanitize=fuzzer,address,signed-integer-overflow

bin_PROGRAMS = fuzz_libyubikey
