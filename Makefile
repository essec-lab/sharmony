# /////////////////////////////////////////////////////////////////////////////////////
# //
# // Copyright (c) 2025-2026 Universität der Bundeswehr München / FI CODE - ESSEC Lab.
# // Licensed under the Apache License, Version 2.0, see LICENSE for details.
# // SPDX-License-Identifier: Apache-2.0
# //
# // Unified Verilator C++ testbench flow.
# // All tests are written in C++ (tb/src/tests/*.cpp). 
# //
# /////////////////////////////////////////////////////////////////////////////////////

# --- paths
PROJ_ROOT    := $(abspath .)
HW_DIR       := $(PROJ_ROOT)/hw/sharmony

# Auto-detect top file (first *_top.sv found)
TOP_FILE_ABS := $(shell find $(HW_DIR) -type f -name "*_top.sv" | head -n 1)
TOP_FILE     := $(patsubst $(PROJ_ROOT)/%,%,$(TOP_FILE_ABS))
TOP_MODULE   := $(basename $(notdir $(TOP_FILE_ABS)))

# Derive package file by replacing '_top' with '_pkg'
HW_PKG       := $(HW_DIR)/$(subst _top,_pkg,$(notdir $(TOP_FILE_ABS)))

# Collect all hardware source files (.sv and .v), excluding the package
HW_SRCS := $(filter-out $(HW_PKG),$(shell find $(HW_DIR) -type f \( -name "*.sv" -o -name "*.v" -o -name "*.vh" \)))

# --- external tools (simulation + synthesis)
# These default to the bare tool name on $PATH. Override on the command line or
# via the environment if your install is elsewhere, e.g.
#   make build        VERILATOR=/opt/verilator/bin/verilator
#   make synth-yosys  YOSYS_BIN=/opt/oss-cad-suite/bin/yosys
#   make synth-vivado VIVADO_BIN=/tools/Xilinx/2025.2/Vivado/bin/vivado
VERILATOR    ?= verilator
VERILATOR_COVERAGE ?= verilator_coverage
YOSYS_BIN    ?= yosys
VIVADO_BIN   ?= vivado
NANGATE_LIB  ?= $(PROJ_ROOT)/synth/lib/NangateOpenCellLibrary_typical.lib
SYNTH_WORK   ?= $(PROJ_ROOT)/synth/work
SYNTH_TOP    ?= essec_sharmony_top

# NangateOpenCell NAND2_X1 cell area (um^2). 1 gate equivalent (GE) = this area.
NAND2_AREA   ?= 0.798

# Sources for the standalone yosys/ASIC flow. The GENERIC adder path is forced
# at synth time (see synth-yosys), so the Xilinx-specific add32_c4/add32_c8
# carry wrappers are intentionally excluded.
SYNTH_SRCS := \
    $(HW_DIR)/essec_sharmony_pkg.sv \
    $(HW_DIR)/essec_sharmony_add4_c4.sv \
    $(HW_DIR)/essec_sharmony_add32_32.sv \
    $(HW_DIR)/essec_sharmony_rom.sv \
    $(HW_DIR)/essec_sharmony_pad.sv \
    $(HW_DIR)/essec_sharmony_core.sv \
    $(HW_DIR)/essec_sharmony_top.sv

# --- C++ flow paths
CXX_DIR      := $(PROJ_ROOT)/tb/src
WRAPPER      := $(CXX_DIR)/sharmony_verilator_wrapper.sv
BUILD_DIR    := $(PROJ_ROOT)/tb/work
OBJ_DIR      := $(BUILD_DIR)/obj_dir
BIN          := $(OBJ_DIR)/Vsharmony_verilator_wrapper

# C++ sources: framework + every test file under tests/
CXX_FRAMEWORK := \
    $(CXX_DIR)/main.cpp \
    $(CXX_DIR)/SharmonyDriver.cpp \
    $(CXX_DIR)/TestRegistry.cpp \
    $(CXX_DIR)/RspParser.cpp

CXX_HELPERS := $(wildcard $(CXX_DIR)/tests/common/*.cpp)
CXX_TESTS   := $(wildcard $(CXX_DIR)/tests/*.cpp)
CXX_SRCS    := $(CXX_FRAMEWORK) $(CXX_HELPERS) $(CXX_TESTS)

# Test names = basename of each tests/*.cpp minus "_test".
# Some small waveform/utility entry points are registered inside interface_test.cpp
# and therefore do not have their own *_test.cpp file. Keep them here so
# make run-<name> / make vcd-<name> can still invoke the registered C++ test.
TEST_NAMES := $(sort $(patsubst %_test,%,$(notdir $(basename $(CXX_TESTS)))))
AUX_TEST_NAMES := \
    input_handshake output_handshake duet \
    tracewave tracewave_hash tracewave_samecycle tracewave_b2b \
    zeroize_scrub oversend_duet midstate_cache \
    case2b case2b_duet_fig sha3cache

TEST_NAMES := $(sort $(TEST_NAMES) $(AUX_TEST_NAMES))
RUN_TEST_NAMES := $(TEST_NAMES)

# Categorize for pretty listing.
# Within each algorithm family, prefer the NIST-style test order:
# shortmsg, longmsg, then monte. Keep any additional tests for the same
# algorithm stem after these, using the default sorted order from TEST_NAMES.
KAT_TEST_ORDER := shortmsg longmsg monte
SHA2_ALGS      := sha224 sha256 sha384 sha512 sha512_224 sha512_256
SHA3_ALGS      := sha3_224 sha3_256 sha3_384 sha3_512
SHAKE_ALGS     := shake128 shake256

ORDER_KAT_TESTS = $(strip $(foreach alg,$(1), \
    $(foreach kind,$(KAT_TEST_ORDER),$(filter $(alg)_$(kind),$(TEST_NAMES))) \
    $(filter-out \
        $(foreach kind,$(KAT_TEST_ORDER),$(alg)_$(kind)) \
        $(foreach subalg,$(filter $(alg)_%,$(1)),$(subalg)_%), \
        $(filter $(alg)_%,$(TEST_NAMES))) \
))

SHA2_TESTS  := $(call ORDER_KAT_TESTS,$(SHA2_ALGS))
SHA3_TESTS  := $(call ORDER_KAT_TESTS,$(SHA3_ALGS))
# cSHAKE tests have no shortmsg/longmsg/monte suffix, so list them explicitly
# under the SHAKE family (after the shake128/shake256 entries).
SHAKE_TESTS := $(call ORDER_KAT_TESTS,$(SHAKE_ALGS)) $(filter cshake128 cshake256,$(TEST_NAMES))
CLASSIFIED  := $(SHA2_TESTS) $(SHA3_TESTS) $(SHAKE_TESTS)
# Exclude the AUX (figure-only / waveform-utility) entry points from the
# listing; they stay in RUN_TEST_NAMES so run-/vcd- can still dispatch them.
OTHER_TESTS := $(filter-out $(CLASSIFIED) $(AUX_TEST_NAMES),$(TEST_NAMES))

# Preferred display order for high-level regression tests.
# Keep any additional/unknown tests after these, using the default sorted order
# inherited from TEST_NAMES.
OTHER_TESTS_ORDERED := \
    $(filter $(OTHER_TESTS),shortmsg longmsg interface error performance nightly) \
    $(filter-out shortmsg longmsg interface error performance nightly,$(OTHER_TESTS))

# --- Verilator
LINT_FLAGS   := --lint-only -Wall -Wno-UNOPTFLAT -Wno-UNOPTTHREADS

# REG_IO is selected by the localparam in sharmony_pkg.sv (no build flags needed).
VL_FLAGS     := --cc --exe --build -j 0 --sv --trace \
                --top-module sharmony_verilator_wrapper \
                --Mdir $(OBJ_DIR) \
                -I$(HW_DIR) \
                -CFLAGS "-std=c++17 -O2 -I$(CXX_DIR)" \
                -Wall -Wno-UNOPTFLAT -Wno-UNOPTTHREADS

# `make ... force` -> tolerate warnings
ifeq ($(filter force,$(MAKECMDGOALS)),force)
  VL_FLAGS += -Wno-fatal
endif

# --- Code-coverage flow (Verilator line + toggle coverage) -------------------
COV_OBJ_DIR := $(BUILD_DIR)/obj_dir_cov
COV_BIN     := $(COV_OBJ_DIR)/Vsharmony_verilator_wrapper
COV_DIR     := $(BUILD_DIR)/coverage
# Separate model in its own obj dir; coverage instrumentation defines
# VM_COVERAGE which activates the write hook in SharmonyDriver's destructor.
COV_VL_FLAGS := --cc --exe --build -j 0 --sv --trace \
                --coverage-line --coverage-toggle \
                --top-module sharmony_verilator_wrapper \
                --Mdir $(COV_OBJ_DIR) \
                -I$(HW_DIR) \
                -CFLAGS "-std=c++17 -O2 -I$(CXX_DIR)" \
                -Wall -Wno-UNOPTFLAT -Wno-UNOPTTHREADS
# Monte-free test list: aggregates cover all modes + control/pad paths; the XOF
# entries add squeeze/variable-output and cSHAKE. (Monte is excluded on purpose.)
COV_TESTS := shortmsg longmsg interface error zeroize midstate \
             sha224_shortmsg sha512_224_shortmsg \
             sha3_224_shortmsg sha3_512_shortmsg \
             shake128_variableout shake256_variableout cshake128 cshake256 duet

###############################################################################
# Default help
###############################################################################
.PHONY: help default all
.DEFAULT_GOAL := default

default: help list-tests

help:
	@echo ""
	@echo "========================== SHARMONY TESTBENCH =========================="
	@echo "Usage: make <target>"
	@echo ""
	@echo "Build & list:"
	@echo "  build                       Build the simulation binary"
	@echo "  list-tests                  Show all available tests"
	@echo "  lint                        Run Verilator lint-only on HW sources"
	@echo "  clean                       Remove build directory"
	@echo "  force                       Continue past Verilator warnings"
	@echo ""
	@echo "Run a test:"
	@echo "  run-<TESTNAME>              Build and run the named test"
	@echo "  vcd-<TESTNAME>              Open Surfer on its VCD"
	@echo ""
	@echo "Synthesis (output in synth/work):"
	@echo "  synth-vivado                FPGA synth (Vivado, Artix-7 xc7a200tfbg484-3)"
	@echo "  synth-yosys                 ASIC synth (yosys+slang -> Nangate45, reports GE)"
	@echo "                              REG_IO=0|1 forces that config (default: pkg value)"
	@echo ""
	@echo "Coverage (output in tb/work/coverage):"
	@echo "  coverage                    Verilator line+toggle coverage over a monte-free suite"
	@echo ""
	@echo "Options:"
	@echo "  VCD=1                       Generate a VCD waveform"
	@echo "  RSP=<path>                  Override the .rsp file for KAT tests"
	@echo "  MAX_VECTORS=<n>             Limit processed vectors (0 = all)"
	@echo "  VERBOSE=<n>                 Verbosity 0..2"
	@echo "  FREQ_MHZ=<MHz>              Clock frequency for performance reports"
	@echo "                              (default = 132 MHz, post-synth Fmax)"
	@echo "  SURFER=<cmd>                Surfer command (default = surfer)"
	@echo ""
	@echo "Examples:"
	@echo "  make run-sha224_shortmsg"
	@echo "  make run-sha512_shortmsg RSP=/abs/path/SHA512ShortMsg.rsp VCD=1"
	@echo "  make run-sha3_512_longmsg MAX_VECTORS=10 VERBOSE=1"
	@echo "  make vcd-sha256_shortmsg"
	@echo ""

all: build

###############################################################################
# Listing
###############################################################################
.PHONY: list-tests
list-tests:
	@echo "========================== Available tests ============================="
	@if [ -z "$(TEST_NAMES)" ]; then \
	  echo "No tests found in $(CXX_DIR)/tests"; \
	else \
	  awk -v sha2="$(SHA2_TESTS)" -v sha3="$(SHA3_TESTS)" -v shake="$(SHAKE_TESTS)" \
	  'BEGIN { \
	    n2 = split(sha2, a, " "); \
	    n3 = split(sha3, b, " "); \
	    ns = split(shake, c, " "); \
	    n = n2; if (n3 > n) n = n3; if (ns > n) n = ns; \
	    printf "%-24s %-24s %s\n", " SHA-2", " SHA-3", " SHAKE"; \
	    printf "%-24s %-24s %s\n", " -----", " -----", " -----"; \
	    for (i = 1; i <= n; i++) printf " %-24s %-24s %s\n", a[i], b[i], c[i]; \
	  }'; \
	  if [ -n "$(OTHER_TESTS)" ]; then \
	    echo ""; echo " Other tests:"; \
	    for t in $(OTHER_TESTS_ORDERED); do \
	      case "$$t" in \
	        shortmsg) desc="Tests short message hashing and padding paths" ;; \
	        longmsg) desc="Tests long multi-block message processing" ;; \
	        interface) desc="Tests streaming and control interface operation" ;; \
	        midstate) desc="Tests midstate save/load and internal state caching" ;; \
	        error) desc="Verifies invalid input and error handling paths" ;; \
	        performance) desc="Measures throughput, latency, and cycle counts" ;; \
	        nightly) desc="Runs the complete regression test suite" ;; \
			zeroize) desc="Verifies zeroization behavior corner cases" ;; \
	        *) desc="" ;; \
	      esac; \
	      if [ -n "$$desc" ]; then \
	        printf " %-11s - %s\n" "$$t" "$$desc"; \
	      else \
	        printf " %s\n" "$$t"; \
	      fi; \
	    done; \
	  fi; \
	fi
	@echo "------------------------------------------------------------------------"
	@echo " Run with: make run-<TESTNAME>"
	@echo "========================================================================"

###############################################################################
# Build
###############################################################################
.PHONY: build check-verilator
build: $(BIN)

# Fail early with an actionable message if Verilator is not installed.
check-verilator:
	@command -v "$(VERILATOR)" >/dev/null 2>&1 || { \
	  echo "ERROR: verilator not found on \$$PATH (looked for '$(VERILATOR)')."; \
	  echo "       Install Verilator, or override with: make <target> VERILATOR=/path/to/verilator"; \
	  exit 1; }

$(BIN): $(WRAPPER) $(CXX_SRCS) $(HW_PKG) $(HW_SRCS) | $(OBJ_DIR) check-verilator
	$(VERILATOR) $(VL_FLAGS) $(HW_PKG) $(HW_SRCS) $(WRAPPER) $(CXX_SRCS)

$(OBJ_DIR):
	@mkdir -p $(OBJ_DIR)

$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)

###############################################################################
# Code coverage (Verilator line + toggle)
###############################################################################
.PHONY: coverage coverage-build
coverage-build: $(COV_BIN)

$(COV_BIN): $(WRAPPER) $(CXX_SRCS) $(HW_PKG) $(HW_SRCS) | check-verilator
	@mkdir -p $(COV_OBJ_DIR)
	$(VERILATOR) $(COV_VL_FLAGS) $(HW_PKG) $(HW_SRCS) $(WRAPPER) $(CXX_SRCS)

coverage: coverage-build
	@rm -rf $(COV_DIR); mkdir -p $(COV_DIR)
	@echo "===================== SHARMONY code coverage ============================="
	@echo "model  : $(COV_BIN)  (line + toggle)"
	@echo "tests  : $(COV_TESTS)"
	@echo "-------------------------------------------------------------------------"
	@for t in $(COV_TESTS); do \
	  printf "  run %-24s " "$$t"; \
	  VERILATOR_COV_FILE=$(COV_DIR)/cov_$$t.dat $(COV_BIN) --test $$t --freq-mhz $(FREQ_MHZ) \
	    > $(COV_DIR)/$$t.log 2>&1 && echo "ok" || echo "FAIL (see $(COV_DIR)/$$t.log)"; \
	done
	@echo "-------------------------------------------------------------------------"
	@echo ">> merging + annotating ..."
	@$(VERILATOR_COVERAGE) --annotate $(COV_DIR)/annotated --annotate-min 1 \
	    $(COV_DIR)/cov_*.dat > $(COV_DIR)/summary.txt 2>&1 || true
	@$(VERILATOR_COVERAGE) --write-info $(COV_DIR)/coverage.info \
	    $(COV_DIR)/cov_*.dat >> $(COV_DIR)/summary.txt 2>&1 || true
	@echo "-------------------------------------------------------------------------"
	@grep -E "Total coverage|points|%" $(COV_DIR)/summary.txt 2>/dev/null | head -5 || true
	@echo ""
	@echo "Annotated source : $(COV_DIR)/annotated/  (uncovered points marked %000000)"
	@echo "lcov info        : $(COV_DIR)/coverage.info  (genhtml for HTML)"
	@echo "Uncovered lines in the core:"
	@grep -nE "^%0" $(COV_DIR)/annotated/essec_sharmony_core.sv 2>/dev/null | head -20 \
	    || echo "  (none / core fully covered by this suite)"
	@echo "========================================================================="

###############################################################################
# Per-test runner
###############################################################################
# Optional knobs
RSP         ?=
MAX_VECTORS ?=
VERBOSE     ?=
VCD         ?=
MODE        ?=
FREQ_MHZ    ?= 132

# Construct the C++ argv tail from optional knobs.
EXTRA_ARGS := \
  $(if $(RSP),--rsp $(RSP)) \
  $(if $(MAX_VECTORS),--max-vectors $(MAX_VECTORS)) \
  $(if $(VERBOSE),--verbose $(VERBOSE)) \
  $(if $(MODE),--mode $(MODE)) \
  --freq-mhz $(FREQ_MHZ)

.PHONY: run-%
run-%: $(BIN) | $(BUILD_DIR)
	@if [ -z "$(filter $*,$(RUN_TEST_NAMES))" ]; then \
	  echo "ERROR: no registered test '$*'"; \
	  echo "Run 'make list-tests' to see available tests."; exit 2; \
	fi
	@mkdir -p "$(BUILD_DIR)/logs/$*" "$(BUILD_DIR)/vcd"
	@echo ">>> Running $*"
	@$(BIN) --test $* $(EXTRA_ARGS) \
	    $(if $(filter 1,$(VCD)),--vcd $(BUILD_DIR)/vcd/$*.vcd) \
	    2>&1 | tee $(BUILD_DIR)/logs/$*/log
	@echo ">>> Log: $(BUILD_DIR)/logs/$*/log"


###############################################################################
# Waveform viewer (Surfer)
###############################################################################
SURFER           ?= surfer

# Software rendering for Surfer (needed under WSLg); set to 0 for hardware GPU.
SURFER_SW_RENDER ?= 1
SURFER_ENV = $(if $(filter 1,$(SURFER_SW_RENDER)),WGPU_BACKEND=gl LIBGL_ALWAYS_SOFTWARE=1)

.PHONY: check-surfer
check-surfer:
	@if ! command -v $(SURFER) >/dev/null 2>&1; then \
	  echo "ERROR: Surfer not found: $(SURFER)"; \
	  echo "Install Surfer, or override with:"; \
	  echo "  make <target> SURFER=/path/to/surfer"; \
	  exit 1; \
	fi

.PHONY: vcd-%
vcd-%: check-surfer | $(BUILD_DIR)
	@TESTNAME='$(patsubst vcd-%,%,$@)'; \
	VCD_DIR='$(BUILD_DIR)/vcd'; \
	VCD_FILE="$$VCD_DIR/$$TESTNAME.vcd"; \
	REL_PATH=$$(realpath --relative-to="$(CURDIR)" "$$VCD_FILE" 2>/dev/null || echo "$$VCD_FILE"); \
	if [ -n "$(MAX_VECTORS)$(MODE)$(RSP)" ] && [ -f "$$VCD_FILE" ]; then \
	  echo ">>> MAX_VECTORS/MODE/RSP given; regenerating $$REL_PATH..."; \
	  rm -f "$$VCD_FILE"; \
	fi; \
	if [ ! -f "$$VCD_FILE" ]; then \
	  echo ">>> VCD for '$$TESTNAME' not found at $$REL_PATH"; \
	  echo ">>> Generating waveform by running the test (VCD=1)..."; \
	  $(MAKE) -s run-$$TESTNAME VCD=1 || exit $$?; \
	fi; \
	echo ">>> Opening $$REL_PATH in Surfer..."; \
	$(SURFER_ENV) $(SURFER) "$$VCD_FILE" >/dev/null 2>&1 &

###############################################################################
# Lint
###############################################################################
.PHONY: lint
lint: check-verilator
	@if [ -z "$(TOP_FILE)" ]; then \
	  echo "No *_top.sv file found under $(HW_DIR). Please specify TOP_MODULE manually."; \
	  exit 1; \
	fi
	@echo "============= Verilator Lint Check on Hardware Sources ============="
	@echo "Top file:    $(TOP_FILE)"
	@echo "Top module:  $(TOP_MODULE)"
	@echo "--------------------------------------------------------------------"
	@$(VERILATOR) $(LINT_FLAGS) -I$(HW_DIR) --top-module $(TOP_MODULE) $(HW_PKG) $(HW_SRCS)
	@echo ""
	@echo "Linting completed."
	@echo "===================================================================="

###############################################################################
# Synthesis
#   synth-vivado : Xilinx FPGA flow (Vivado, Artix-7 xc7a200tfbg484-3)
#   synth-yosys  : open-source ASIC flow (yosys + slang -> Nangate45 -> GE)
# Both write reports/checkpoints into $(SYNTH_WORK).
###############################################################################
.PHONY: synth-vivado synth-yosys

synth-vivado:
	@command -v "$(VIVADO_BIN)" >/dev/null 2>&1 || { \
	  echo "ERROR: vivado not found on \$$PATH (looked for '$(VIVADO_BIN)')."; \
	  echo "       Override with: make synth-vivado VIVADO_BIN=/path/to/vivado"; \
	  exit 1; }
	@case "$(REG_IO)" in ""|0|1) ;; *) \
	  echo "ERROR: REG_IO must be 0 or 1 (got '$(REG_IO)')."; exit 1 ;; esac
	@mkdir -p $(SYNTH_WORK)
	@echo "===================== SHARMONY Vivado / FPGA synthesis ===================="
	@echo "vivado   : $(VIVADO_BIN)"
	@echo "out dir  : $(SYNTH_WORK)"
	@if [ -n "$(REG_IO)" ]; then echo "config   : REG_IO=$(REG_IO) (override)"; \
	 else echo "config   : REG_IO = current value in $(notdir $(HW_PKG))"; fi
	@echo "---------------------------------------------------------------------------"
	@cp $(HW_PKG) $(HW_PKG).synthbak; \
	 trap 'mv -f $(HW_PKG).synthbak $(HW_PKG)' EXIT INT TERM; \
	 if [ -n "$(REG_IO)" ]; then \
	   sed -i -E "s/(localparam bit REG_IO_DEFAULT  *=  *)1'b[01];/\11'b$(REG_IO);/" $(HW_PKG); \
	 fi; \
	 rio=$$(sed -nE "s/.*localparam bit REG_IO_DEFAULT  *=  *1'b([01]);.*/\1/p" $(HW_PKG)); \
	 echo ">> Vivado synthesis (REG_IO=$$rio) ..."; \
	 cd $(SYNTH_WORK) && $(VIVADO_BIN) -mode batch -source $(PROJ_ROOT)/synth/sharmony_top/synth.tcl
	@echo "---------------------------------------------------------------------------"
	@awk -f $(PROJ_ROOT)/synth/vivado_tables.awk $(SYNTH_WORK)/report.dat
	@echo ""
	@echo "Reports  : $(SYNTH_WORK) (utilization.rpt, timing_summary.rpt, report.dat)"
	@echo "Tip      : run 'make synth-vivado REG_IO=0' / 'REG_IO=1' to force a config."
	@echo "==========================================================================="

synth-yosys:
	@command -v "$(YOSYS_BIN)" >/dev/null 2>&1 || { \
	  echo "ERROR: yosys not found on \$$PATH (looked for '$(YOSYS_BIN)')."; \
	  echo "       Override with: make synth-yosys YOSYS_BIN=/path/to/yosys"; \
	  echo "       (must be built with the slang plugin, e.g. OSS CAD Suite)."; \
	  exit 1; }
	@test -f "$(NANGATE_LIB)" || { \
	  echo "ERROR: Nangate liberty not found at '$(NANGATE_LIB)'."; \
	  echo "       The library is not bundled (non-Apache license). Download"; \
	  echo "       NangateOpenCellLibrary_typical.lib (e.g. from OpenROAD-flow-scripts,"; \
	  echo "       flow/platforms/nangate45/lib/) and place it at that path, or set"; \
	  echo "       NANGATE_LIB=/path/to/NangateOpenCellLibrary_typical.lib"; \
	  exit 1; }
	@case "$(REG_IO)" in ""|0|1) ;; *) \
	  echo "ERROR: REG_IO must be 0 or 1 (got '$(REG_IO)')."; exit 1 ;; esac
	@mkdir -p $(SYNTH_WORK)
	@echo "===================== SHARMONY yosys / ASIC synthesis ====================="
	@echo "yosys    : $(YOSYS_BIN)"
	@echo "liberty  : $(NANGATE_LIB)"
	@echo "out dir  : $(SYNTH_WORK)"
	@echo "config   : ADDER_IMPL=GENERIC, ROM_USE_BRAM=0, hierarchy preserved"
	@echo "           (set in $(notdir $(HW_PKG)) for this run, then restored)"
	@if [ -n "$(REG_IO)" ]; then echo "           REG_IO=$(REG_IO) (override)"; \
	 else echo "           REG_IO = current value in $(notdir $(HW_PKG))"; fi
	@echo "---------------------------------------------------------------------------"
	@cp $(HW_PKG) $(HW_PKG).synthbak; \
	 trap 'mv -f $(HW_PKG).synthbak $(HW_PKG)' EXIT INT TERM; \
	 sed -i -e 's/\(localparam int ADDER_IMPL_DEFAULT  *=  *\)ADDER_[A-Z0-9_]*;/\1ADDER_GENERIC;/' \
	        -e "s/\(localparam bit ROM_USE_BRAM_DEFAULT  *=  *\)1'b1;/\11'b0;/" $(HW_PKG); \
	 if [ -n "$(REG_IO)" ]; then \
	   sed -i -E "s/(localparam bit REG_IO_DEFAULT  *=  *)1'b[01];/\11'b$(REG_IO);/" $(HW_PKG); \
	 fi; \
	 rio=$$(sed -nE "s/.*localparam bit REG_IO_DEFAULT  *=  *1'b([01]);.*/\1/p" $(HW_PKG)); \
	 echo ">> synthesizing REG_IO=$$rio ..."; \
	 $(YOSYS_BIN) -ql $(SYNTH_WORK)/yosys_synth.log -p "\
	    plugin -i slang; \
	    read_slang $(SYNTH_SRCS) --top $(SYNTH_TOP) --best-effort-hierarchy; \
	    hierarchy -top $(SYNTH_TOP); \
	    keep_hierarchy; \
	    synth -top $(SYNTH_TOP); \
	    dfflibmap -liberty $(NANGATE_LIB); \
	    abc -liberty $(NANGATE_LIB); \
	    setundef -zero; \
	    opt_clean -purge; \
	    tee -o $(SYNTH_WORK)/yosys_stat.txt stat -liberty $(NANGATE_LIB)" \
	    || exit 1; \
	 echo "$$rio" > $(SYNTH_WORK)/.regio
	@echo "---------------------------------------------------------------------------"
	@awk -v n2=$(NAND2_AREA) -v rio=$$(cat $(SYNTH_WORK)/.regio) \
	    -f $(PROJ_ROOT)/synth/ge_table.awk $(SYNTH_WORK)/yosys_stat.txt
	@echo ""
	@echo "Reports  : $(SYNTH_WORK)/yosys_stat.txt , yosys_synth.log"
	@echo "Tip      : run 'make synth-yosys REG_IO=0' / 'REG_IO=1' to force a config."
	@echo "==========================================================================="

###############################################################################
# Utility
###############################################################################
.PHONY: clean fix-crlf force
clean:
	@rm -rf $(OBJ_DIR) $(BUILD_DIR) $(SYNTH_WORK)
	@rm -f $(HW_PKG).synthbak
	@find $(PROJ_ROOT)/synth -type f \( -name 'vivado*.jou' -o -name 'vivado*.log' \
	      -o -name '*.backup.jou' -o -name '*.backup.log' \) -delete 2>/dev/null || true
	@find $(PROJ_ROOT) -type d -name '.Xil' -exec rm -rf {} + 2>/dev/null || true

fix-crlf:
	@which dos2unix >/dev/null 2>&1 && dos2unix $(WRAPPER) $(CXX_SRCS) $(HW_PKG) $(HW_SRCS) || true
	@sed -i 's/\r$$//' $(WRAPPER) $(CXX_SRCS) $(HW_PKG) $(HW_SRCS)

force:
	@:
	
