NF := p4/nat.p4
P4C := $(SDE_INSTALL)/bin/bf-p4c
P4_DEBUG_FLAGS := -g --verbose 2 --create-graphs
BUILD_DIR := build
MKDIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))

INSTALL_SCRIPT=$(MKDIR)/build_tools/p4_build.sh

debug: $(NF)
	$(P4C) $(P4_DEBUG_FLAGS) -o $(BUILD_DIR) $(NF)

install: $(NF)
	$(INSTALL_SCRIPT) $(NF)

.PHONY: clean

clean:
	rm -rf build
