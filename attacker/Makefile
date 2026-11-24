CONTIKI_PROJECT = attacker
all: $(CONTIKI_PROJECT)

# --- Adversary configuration -------------------------------------------------
# Select the attack at build time, e.g.:
#   make ATTACK=RANK_DECREASE
#   make ATTACK=VERSION
#   make ATTACK=SELECTIVE_FWD DROP_PCT=30
ATTACK   ?= RANK_DECREASE
RANK_DELTA ?= 256
DROP_PCT   ?= 50

# Map the friendly name to the RPL_ATTACK_* code in rpl-attack.h
ATTACK_RANK_DECREASE = 1
ATTACK_RANK_INCREASE = 2
ATTACK_VERSION       = 4
ATTACK_BLACKHOLE     = 5
ATTACK_SELECTIVE_FWD = 6
ATTACK_SINKHOLE      = 7
ATTACK_DIS_FLOOD     = 8
ATTACK_CODE = $(ATTACK_$(ATTACK))

# Fail early and clearly on an unknown ATTACK rather than emitting an empty
# -DRPL_SEC_ATTACK_TYPE= and letting the C compiler report a syntax error.
ifeq ($(ATTACK_CODE),)
$(error Unknown ATTACK '$(ATTACK)'. Use one of: RANK_DECREASE RANK_INCREASE VERSION BLACKHOLE SELECTIVE_FWD SINKHOLE DIS_FLOOD)
endif

# Turn the adversary hooks on for this image only. The hook macros themselves
# live in ../common/rpl-hooks.h, gated on RPL_SEC_ATTACK, so only this image
# gets the adversary behaviour; root and node keep stock RPL.
CFLAGS += -DRPL_SEC_ATTACK=1
CFLAGS += -DRPL_SEC_ATTACK_TYPE=$(ATTACK_CODE)
CFLAGS += -DRPL_SEC_ATTACK_RANK_DELTA=$(RANK_DELTA)
CFLAGS += -DRPL_SEC_ATTACK_DROP_PCT=$(DROP_PCT)

# Adversary implementation goes only into this image.
PROJECT_SOURCEFILES += rpl-attack.c

include ../common/Makefile.rpl-sec
