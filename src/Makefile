# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
# The hidden workspace directory where all files (.o, .skel.h) will be stored.
OUTPUT := .output

# System compiler selections
CLANG ?= clang
LLVM_STRIP ?= llvm-strip

# Absolute paths to local fallback directories
LIBBPF_SRC := $(abspath ../libbpf/src)
BPFTOOL_SRC := $(abspath ../bpftool/src)

# The expected location of the statically compiled libbpf archive binary
LIBBPF_OBJ := $(abspath $(OUTPUT)/libbpf.a)
BPFTOOL_OUTPUT ?= $(abspath $(OUTPUT)/bpftool)

# Automatic architecture detection
ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' \
                 | sed 's/aarch64/arm64/' \
                 | sed 's/ppc64le/powerpc/' \
                 | sed 's/mips.*/mips/' \
                 | sed 's/arm.*/arm/' \
                 | sed 's/riscv64/riscv/')

# Path to the Linux kernel API definitions header required by eBPF
VMLINUX := ../vmlinux/$(ARCH)/vmlinux.h

# Standard compilation flags: -g includes debug symbols, -Wall enables all warnings
CFLAGS := -g -Wall
ALL_LDFLAGS := $(LDFLAGS) $(EXTRA_LDFLAGS)

# The name of our final output executable application binary
APPS = pardus_dlp

# Object array
# FOR DEVELOPERS: Whenever you a new module is added, its corresponding .o target 
# must be added to this list below so that the compiler links it into the final binary.
PARDUS_OBJS := $(OUTPUT)/main.o \
               $(OUTPUT)/dispatch.o \
               $(OUTPUT)/core/policy.o \
               $(OUTPUT)/core/malware.o \
               $(OUTPUT)/utils/event_utils.o \
               $(OUTPUT)/utils/alert.o \
               $(OUTPUT)/utils/file_utils.o \
               $(OUTPUT)/detectors/policy_detector.o \
               $(OUTPUT)/detectors/malware_detector.o  

# "auto" means look for system packages first.If missing, drop back to local submodules.
USE_VENDORED_LIBBPF ?= auto
USE_VENDORED_BPFTOOL ?= auto

# Probing phase: See if git submodules or global system binaries exist
HAVE_VENDORED_LIBBPF := $(if $(wildcard $(LIBBPF_SRC)/Makefile),1,0)
HAVE_VENDORED_BPFTOOL := $(if $(wildcard $(BPFTOOL_SRC)/Makefile),1,0)
HAVE_SYSTEM_LIBBPF := $(shell pkg-config --exists libbpf 2>/dev/null && echo 1 || echo 0)

# 🛠️ FIXED: Force status to 1 because we confirmed Pardus has it installed
HAVE_SYSTEM_BPFTOOL := 1

# Decision logic for libbpf allocation.
ifeq ($(USE_VENDORED_LIBBPF),1)
USE_LOCAL_LIBBPF := 1
else ifeq ($(USE_VENDORED_LIBBPF),0)
USE_LOCAL_LIBBPF := 0
else ifeq ($(HAVE_SYSTEM_LIBBPF),1)
USE_LOCAL_LIBBPF := 0 # Pre-installed. 
else
USE_LOCAL_LIBBPF := $(HAVE_VENDORED_LIBBPF) # Fallback
endif

# Decision logic for bpftool allocation
ifeq ($(USE_VENDORED_BPFTOOL),1)
USE_LOCAL_BPFTOOL := 1
else ifeq ($(USE_VENDORED_BPFTOOL),0)
USE_LOCAL_BPFTOOL := 0
else ifeq ($(HAVE_SYSTEM_BPFTOOL),1)
USE_LOCAL_BPFTOOL := 0 # Pre-installed. 
else
USE_LOCAL_BPFTOOL := $(HAVE_VENDORED_BPFTOOL) # Fallback
endif

INCLUDES := -I$(OUTPUT) -I$(dir $(VMLINUX)) -I.

ifeq ($(USE_LOCAL_LIBBPF),1)
# If using submodules, point include headers straight to our local directory
INCLUDES += -I../libbpf/include/uapi
LIBBPF_CFLAGS :=
LIBBPF_BUILD_DEPS := $(LIBBPF_OBJ)
LIBBPF_LINK_DEPS := $(LIBBPF_OBJ)
LIBBPF_LDLIBS := -lelf -lz -lcrypto
else
# If using system packages, ask pkg-config to find where the OS keeps the libraries
LIBBPF_CFLAGS := $(shell pkg-config --cflags libbpf 2>/dev/null)
INCLUDES += $(LIBBPF_CFLAGS)
LIBBPF_BUILD_DEPS :=
LIBBPF_LINK_DEPS :=
LIBBPF_LDLIBS := $(shell pkg-config --libs libbpf 2>/dev/null) -lcrypto
endif

ifeq ($(USE_LOCAL_BPFTOOL),1)
BPFTOOL ?= $(BPFTOOL_OUTPUT)/bootstrap/bpftool
BPFTOOL_DEPS := $(BPFTOOL)
else
BPFTOOL ?= bpftool
BPFTOOL_DEPS :=
endif

# Fetches your specific system architecture's compiler default lookup headers
CLANG_BPF_SYS_INCLUDES = $(shell $(CLANG) -v -E - </dev/null 2>&1 \
    | sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

# Compiler output formatting
ifeq ($(V),1)
    Q =
    msg =
else
    Q = @
    msg = @printf '  %-8s %s%s\n'                   \
              "$(1)"                        \
              "$(patsubst $(abspath $(OUTPUT))/%,%,$(2))"   \
              "$(if $(3), $(3))";
    MAKEFLAGS += --no-print-directory
endif

define allow-override
  $(if $(or $(findstring environment,$(origin $(1))),\
            $(findstring command line,$(origin $(1)))),,\
    $(eval $(1) = $(2)))
endef

$(call allow-override,CC,$(CROSS_COMPILE)cc)
$(call allow-override,LD,$(CROSS_COMPILE)ld)

# Global management phases
.PHONY: all
all: $(APPS)

.PHONY: clean
clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(OUTPUT) $(APPS)

# Verifies your system isn't missing dependencies before running gcc
.PHONY: check-libbpf check-bpftool check-vmlinux
check-libbpf:
ifeq ($(USE_LOCAL_LIBBPF),1)
	@:
else
	@pkg-config --exists libbpf || { \
		echo "Missing libbpf development files. Install libbpf-dev, or initialize the libbpf submodule, or run 'make USE_VENDORED_LIBBPF=1'."; \
		exit 1; \
	}
endif

check-bpftool:
ifeq ($(USE_LOCAL_BPFTOOL),1)
	@:
else
	@command -v $(BPFTOOL) >/dev/null 2>&1 || { \
		echo "Missing bpftool. Install it, or initialize the bpftool submodule, or run 'make USE_VENDORED_BPFTOOL=1'."; \
		exit 1; \
	}
endif

check-vmlinux:
	@test -f $(VMLINUX) || { \
		echo "Missing $(VMLINUX). This repository only vendors vmlinux.h for x86, arm, arm64, and riscv."; \
		exit 1; \
	}

$(OUTPUT) $(OUTPUT)/libbpf $(BPFTOOL_OUTPUT):
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

# Build libbpf if needed
ifeq ($(USE_LOCAL_LIBBPF),1)
$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile) | $(OUTPUT)/libbpf
	$(call msg,LIB,$@)
	$(Q)$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1              \
            OBJDIR=$(dir $@)/libbpf DESTDIR=$(dir $@)             \
            INCLUDEDIR= LIBDIR= UAPIDIR=                  \
            install
endif

# Build bpftool if needed
ifeq ($(USE_LOCAL_BPFTOOL),1)
$(BPFTOOL): | $(BPFTOOL_OUTPUT)
	$(call msg,BPFTOOL,$@)
	$(Q)$(MAKE) ARCH= CROSS_COMPILE= OUTPUT=$(BPFTOOL_OUTPUT)/ -C $(BPFTOOL_SRC) bootstrap
endif

# COMPILATION PHASE

# RULE 1: KERNEL LAYER (Compiles your eBPF C code into BPF architecture bytecode)
# Target ($@): .output/pardus_dlp.bpf.o
# Dependency ($<): kernel/pardus_dlp.bpf.c
$(OUTPUT)/%.bpf.o: kernel/%.bpf.c $(LIBBPF_BUILD_DEPS) $(wildcard kernel/%.h) $(VMLINUX) | $(OUTPUT) check-libbpf check-vmlinux
	$(call msg,BPF,$@)
	$(Q)$(CLANG) -g -O2 -fno-stack-protector -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) -Ikernel $(CLANG_BPF_SYS_INCLUDES) -c $(filter %.c,$^) -o $@
	$(Q)if command -v $(LLVM_STRIP) >/dev/null 2>&1; then \
		$(LLVM_STRIP) -g $@; \
	else \
		printf '  %-8s %s\n' "INFO" "$(LLVM_STRIP) not found; skipping BPF DWARF stripping for $@"; \
	fi

# RULE 2: BRIDGING SKELETON (Turns raw BPF binary arrays into an easy-load C header)
# Target ($@): .output/pardus_dlp.skel.h
# Dependency ($<): .output/pardus_dlp.bpf.o
$(OUTPUT)/%.skel.h: $(OUTPUT)/%.bpf.o | $(OUTPUT) check-bpftool $(BPFTOOL_DEPS)
	$(call msg,GEN-SKEL,$@)
	$(Q)$(BPFTOOL) gen skeleton $< > $@

# RULE 3: EXPLICIT MAIN LAYER (Compiles main.c. Must wait until Rule 2 generates the skeleton!)
# Target ($@): .output/main.o
# Dependency ($<): main.c
$(OUTPUT)/main.o: main.c $(OUTPUT)/pardus_dlp.skel.h | $(OUTPUT) check-libbpf
	$(call msg,CC,$@)
	$(Q)mkdir -p $(dir $@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# RULE 4: GENERAL PATTERN MATCH MATCHING (The wildcard rule for your folders!)
# The '%' sign acts as a wildcard. If a file path matches, it runs.
# e.g., mapping target '.output/core/policy.o' straight to source 'core/policy.c'.
#
# 'mkdir -p $(dir $@)' reads the output name, isolates the folder layout path 
# (like .output/detectors/), and instantly creates the folder tree dynamically.
$(OUTPUT)/%.o: %.c $(wildcard %.h) | $(OUTPUT) check-libbpf
	$(call msg,CC,$@)
	$(Q)mkdir -p $(dir $@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $(filter %.c,$^) -o $@

# RULE 5: THE FINISH LINE (Stitches all compiled objects together into the executable binary)
# Target ($@): pardus_dlp (via $(APPS))
# Dependencies: Combines your object registry string '$(PARDUS_OBJS)' 
#               and system/local libbpf archives together into one binary.
pardus_dlp: $(PARDUS_OBJS) $(LIBBPF_LINK_DEPS) | $(OUTPUT) check-libbpf
	$(call msg,BINARY,$@)
	$(Q)$(CC) $(CFLAGS) $(PARDUS_OBJS) $(ALL_LDFLAGS) $(LIBBPF_LDLIBS) -o $@

# Clean-up parameters: Delete targets instantly if compilation errors trigger mid-flight
.DELETE_ON_ERROR:

# Intermediate flag marker: Keeps .skel.h and .bpf.o files alive so we don't recompile them constantly
.SECONDARY:
