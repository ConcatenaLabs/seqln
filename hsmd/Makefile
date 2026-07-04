#! /usr/bin/make

HSMD_SRC := hsmd/hsmd.c	\
	hsmd/hsmd_wiregen.c \
	hsmd/hsm_utxo.c \
	hsmd/libhsmd.c

HSMD_HEADERS := hsmd/hsmd_wiregen.h hsmd/permissions.h
HSMD_OBJS := $(HSMD_SRC:.c=.o)

$(HSMD_OBJS): $(HSMD_HEADERS)

# Other programs which use the hsm need this.
HSMD_CLIENT_OBJS := \
	hsmd/hsmd_wiregen.o			\
	hsmd/hsm_utxo.o				\

# Make sure these depend on everything.
ALL_C_SOURCES += $(HSMD_SRC)
ALL_C_HEADERS += $(HSMD_HEADERS)
ALL_PROGRAMS += lightningd/lightning_hsmd

lightningd/lightning_hsmd: $(HSMD_OBJS) libcommon.a

# SeqLN Tier-2 signer split (M1): hsmd-proxy + out-of-process signerd.
# Tier-2 secure transport: hsmd/signer_noise.c (BOLT-8 Noise_XK, remote link).
HSMD_PROXY_SRC := hsmd/hsmd_proxy.c hsmd/signer_noise.c
SIGNERD_SRC := hsmd/signerd.c
HSMD_SPLIT_HEADERS := hsmd/signer_frame.h hsmd/signer_noise.h

ALL_C_SOURCES += $(HSMD_PROXY_SRC) $(SIGNERD_SRC)
ALL_C_HEADERS += $(HSMD_SPLIT_HEADERS)
ALL_PROGRAMS += lightningd/lightning_hsmd_proxy lightningd/lightning_signerd

# Both new objects need the wiregen/permissions headers and the frame header.
hsmd/hsmd_proxy.o hsmd/signerd.o hsmd/signer_noise.o: $(HSMD_HEADERS) $(HSMD_SPLIT_HEADERS)

# hsmd-proxy = the hsmd objects minus hsmd.o, plus our proxy + noise-transport
# objects.  It links libhsmd.o only for the pure hsmd_check_client_capabilities
# helper (+ dev flag globals); it never loads a secret.  The Noise transport
# reuses common/cryptomsg.c (libcommon.a) + libsodium (EXTERNAL_LDLIBS).
lightningd/lightning_hsmd_proxy: hsmd/hsmd_proxy.o hsmd/signer_noise.o hsmd/hsmd_wiregen.o hsmd/hsm_utxo.o hsmd/libhsmd.o libcommon.a

# signerd links libhsmd (the real crypto), the wiregen (de)serializers and the
# utxo helper, over libcommon.
lightningd/lightning_signerd: hsmd/signerd.o hsmd/libhsmd.o hsmd/hsmd_wiregen.o hsmd/hsm_utxo.o libcommon.a

check-source: check-hsm-versions

# common/hsm_version.h should at least *mention* this!
check-hsm-versions: hsmd/hsmd_wire.csv common/hsm_version.h
	@SUM=`grep -vE '^(#| *$$)' hsmd/hsmd_wire.csv  | sha256sum | cut -c1-64`; if ! grep -q "$$SUM" common/hsm_version.h; then echo "*** hsmd_wire.csv changed to $$SUM without update to common/hsm_version.h">&2; exit 1; fi

-include hsmd/test/Makefile
