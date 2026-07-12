#! /usr/bin/make

# speculad: the Specula keyless watchtower broadcaster (Phase C).
#
# A standalone, always-on, device-INDEPENDENT daemon with its OWN systemd unit
# (NOT a CLN plugin, NOT spawned by lightningd).  It loads no secret and runs no
# crypto: it reads the fsync-durable watchtower store (see
# lightningd/watchtower_store.h), watches the chain via elements-cli RPC, and
# broadcasts the device-pre-signed justice/sweep blobs while the signing device
# is offline.
#
# Like cli/lightning-cli it is a single translation unit linked over libcommon.a
# (which pulls libwallycore/libsecp256k1 in via EXTERNAL_LDLIBS); it needs no
# lightningd/channeld object because it carries its own decoupled store decoder.
SPECULAD_SRC := speculad/speculad.c
SPECULAD_OBJS := $(SPECULAD_SRC:.c=.o)

ALL_C_SOURCES += $(SPECULAD_SRC)
ALL_C_HEADERS +=
ALL_PROGRAMS += speculad/speculad

$(SPECULAD_OBJS): speculad/Makefile

speculad/speculad: $(SPECULAD_OBJS) libcommon.a
