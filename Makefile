# NetShield Agent Simulator
#
# Common workflows:
#   make                              # build C++ data plane (default)
#   make install                      # create venv + install Python deps
#   make run                          # launch control plane (needs GEMINI_API_KEY)
#   make ddos 1 8                     # inject a flood (attacker=1, target=8)
#   make traffic                      # generate benign background traffic
#   make ai                           # run orchestrator against latest snapshot
#   make smoke                        # end-to-end smoke test
#   make test                         # routing unit test
#   make clean                        # remove compiled binaries
#   make clean-logs                   # remove dashboard + per-node logs
#   make distclean                    # also wipe the venv
#   make help                         # list all targets

# -- Toolchain ----------------------------------------------------------------
CXX        ?= g++
CXXSTD     ?= -std=c++17
CXXWARN    ?= -Wall -Wextra
CXXOPT     ?= -O2
CXXFLAGS   ?= $(CXXSTD) $(CXXWARN) $(CXXOPT) -pthread
LDFLAGS    ?= -pthread

PYTHON     ?= python3
VENV       := venv
VENV_PY    := $(VENV)/bin/python
VENV_PIP   := $(VENV)/bin/pip
INSTALL_STAMP := $(VENV)/.installed

# -- Layout -------------------------------------------------------------------
SRC_DIR    := src
BIN_DIR    := bin
CTL_DIR    := control_plane
SCRIPT_DIR := scripts
LOG_DIR    := logs
RUNTIME_LOG_DIR := /tmp/netshield

NODE_SRC   := $(SRC_DIR)/node.cpp
NODE_HDRS  := $(wildcard $(SRC_DIR)/*.h)
NODE_BIN   := $(BIN_DIR)/node

# -- DDoS args ----------------------------------------------------------------
# Two ways to pass attacker/target IDs:
#   1. Positional:   `make ddos 1 8`
#   2. Named:        `make ddos ATTACKER=1 TARGET=8`
#
# Make normally treats every word on the command line as a target. To support
# positional args we grab everything after `ddos` from MAKECMDGOALS and define
# them as empty rules below so make doesn't error with "No rule to make 1".
ifeq (ddos,$(firstword $(MAKECMDGOALS)))
  DDOS_POS_ARGS := $(wordlist 2,$(words $(MAKECMDGOALS)),$(MAKECMDGOALS))
  ifneq ($(DDOS_POS_ARGS),)
    ATTACKER := $(word 1,$(DDOS_POS_ARGS))
    TARGET   := $(word 2,$(DDOS_POS_ARGS))
    # Silently swallow the positional words as no-op goals.
    $(eval $(DDOS_POS_ARGS):;@:)
  endif
endif

ATTACKER   ?= 1
TARGET     ?= 8

.PHONY: all build install deps venv run ddos traffic ai \
        smoke test clean clean-logs distclean help

.DEFAULT_GOAL := all

# -- Build --------------------------------------------------------------------
all: build  ## Build the C++ data plane (default)
build: $(NODE_BIN)

# Header dependencies are explicit so editing packet.h / routing.h / topology.h
# triggers a rebuild — Make can't infer #include graphs without help.
$(NODE_BIN): $(NODE_SRC) $(NODE_HDRS) | $(BIN_DIR)
	$(CXX) $(CXXFLAGS) $(NODE_SRC) -o $@ $(LDFLAGS)

$(BIN_DIR):
	mkdir -p $@

# -- Python environment ------------------------------------------------------
# Two-step pattern: create the venv as one rule, then a stamp file records
# that requirements.txt was installed. Downstream targets depend on the stamp
# so pip only re-runs when requirements.txt actually changes.
$(VENV_PY):
	$(PYTHON) -m venv $(VENV)
	$(VENV_PY) -m pip install --upgrade pip

$(INSTALL_STAMP): $(VENV_PY) requirements.txt
	$(VENV_PIP) install -r requirements.txt
	@touch $@

venv: $(VENV_PY)  ## Create the Python virtual environment
install: $(INSTALL_STAMP)  ## Install Python deps into the venv
deps: install  ## Alias for `install`

# -- Run ----------------------------------------------------------------------
run: $(NODE_BIN) $(INSTALL_STAMP)  ## Launch the control plane (Ctrl+C to stop)
	$(VENV_PY) $(CTL_DIR)/main.py

ddos: $(INSTALL_STAMP)  ## Run DDoS flood: `make ddos <attacker> <target>`
	$(VENV_PY) $(SCRIPT_DIR)/ddos.py --attacker $(ATTACKER) --target $(TARGET)

traffic: $(INSTALL_STAMP)  ## Generate benign background traffic between edge nodes
	$(VENV_PY) $(SCRIPT_DIR)/benign_traffic.py

ai: $(INSTALL_STAMP)  ## Run AI orchestrator against logs/anomaly_snapshot.json
	$(VENV_PY) $(SCRIPT_DIR)/ai_orchestrator.py

# -- Tests --------------------------------------------------------------------
smoke: $(NODE_BIN) $(INSTALL_STAMP)  ## End-to-end smoke test
	bash $(SCRIPT_DIR)/smoke_step3.sh

test: $(INSTALL_STAMP)  ## Run routing unit test
	$(VENV_PY) $(SCRIPT_DIR)/test_routing.py

# -- Clean --------------------------------------------------------------------
# `rm -rf bin/*` mirrors CLAUDE.md exactly — keeps the bin/ dir, drops contents.
clean:  ## Remove compiled binaries
	rm -rf $(BIN_DIR)/*

clean-logs:  ## Remove dashboard + per-node logs
	rm -rf $(LOG_DIR)/* $(RUNTIME_LOG_DIR)/*

distclean: clean clean-logs  ## Remove binaries, logs, AND the venv
	rm -rf $(VENV)

# -- Help ---------------------------------------------------------------------
# Self-documenting: scrape `## comment` annotations from .PHONY targets above.
help:  ## Show this help
	@awk 'BEGIN {FS = ":.*##"; printf "NetShield Makefile targets:\n\n"} \
	      /^[a-zA-Z_-]+:.*##/ {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}' \
	      $(MAKEFILE_LIST)
