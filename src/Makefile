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

# Standard compilation flags: -g includes debug symbols, -Wall enables warnings, -O2 enables optimization
CFLAGS := -g -Wall -O2
ALL_LDFLAGS := $(LDFLAGS) $(EXTRA_LDFLAGS)

# The name of our final output executable application binary
APPS = pardus_dlp

# Object array
PARDUS_OBJS := $(OUTPUT)/main.o \
               $(OUTPUT)/dispatch.o \
               $(OUTPUT)/core/policy.o \
               $(OUTPUT)/core/malware.o \
               $(OUTPUT)/utils/alert.o \
               $(OUTPUT)/utils/file_utils.o \
               $(OUTPUT)/detectors/policy_detector.o \
               $(OUTPUT)/detectors/malware_detector.o  

# "auto" means look for system packages first. If missing, drop back to local submodules.
USE_VENDORED_LIBBPF ?= auto
USE_VENDORED_BPFTOOL ?= auto

# ==============================================================================
# ROBUST PROBING PHASE (Machine Agnostic)
# ==============================================================================
# See if git submodules or global system binaries exist
HAVE_VENDORED_LIBBPF := $(if $(wildcard $(LIBBPF_SRC)/Makefile),1,0)
HAVE_VENDORED_BPFTOOL := $(if $(wildcard $(BPFTOOL_SRC)/Makefile),1,0)
HAVE_SYSTEM_LIBBPF := $(shell pkg-config --exists libbpf 2>/dev/null && echo 1 || echo 0)
HAVE_SYSTEM_BPFTOOL := $(shell command -v bpftool >/dev/null 2>&1 && echo 1 || echo 0)

# ------------------------------------------------------------------------------
# STRICT DECISION TREE: LIBBPF
# ------------------------------------------------------------------------------
ifeq ($(strip $(USE_VENDORED_LIBBPF)),1)
    USE_LOCAL_LIBBPF := 1
else ifeq ($(strip $(USE_VENDORED_LIBBPF)),0)
    USE_LOCAL_LIBBPF := 0
else
    # Auto Mode: System first, fallback to local
    ifeq ($(HAVE_SYSTEM_LIBBPF),1)
        USE_LOCAL_LIBBPF := 0
    else
        USE_LOCAL_LIBBPF := 1
    endif
endif

# ------------------------------------------------------------------------------
# STRICT DECISION TREE: BPFTOOL
# ------------------------------------------------------------------------------
ifeq ($(strip $(USE_VENDORED_BPFTOOL)),1)
    USE_LOCAL_BPFTOOL := 1
else ifeq ($(strip $(USE_VENDORED_BPFTOOL)),0)
    USE_LOCAL_BPFTOOL := 0
else
    # Auto Mode: System first, fallback to local
    ifeq ($(HAVE_SYSTEM_BPFTOOL),1)
        USE_LOCAL_BPFTOOL := 0
    else
        USE_LOCAL_BPFTOOL := 1
    endif
endif
# ==============================================================================

INCLUDES := -I$(OUTPUT) -I$(dir $(VMLINUX)) -I.

ifeq ($(USE_LOCAL_LIBBPF),1)
    INCLUDES += -I../libbpf/include/uapi
    LIBBPF_CFLAGS :=
    LIBBPF_BUILD_DEPS := $(LIBBPF_OBJ)
    LIBBPF_LINK_DEPS := $(LIBBPF_OBJ)
    LIBBPF_LDLIBS := -lelf -lz -lcrypto
else
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

CLANG_BPF_SYS_INCLUDES = $(shell $(CLANG) -v -E - </dev/null 2>&1 \
    | sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

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

# ==============================================================================
# BUILD TARGETS
# ==============================================================================
.PHONY: all
all: $(APPS)

.PHONY: clean
clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(OUTPUT) $(APPS)

# Self-Diagnosing Dependency Guards
.PHONY: check-libbpf check-bpftool check-vmlinux

check-libbpf:
ifeq ($(USE_LOCAL_LIBBPF),1)
	@if [ "$(HAVE_VENDORED_LIBBPF)" = "0" ]; then \
		echo "❌ Error: libbpf submodule is missing or empty. Run: git submodule update --init --recursive"; \
		exit 1; \
	fi
else
	@pkg-config --exists libbpf || { \
		echo "❌ Error: System libbpf-dev missing. Install it via package manager or run 'make USE_VENDORED_LIBBPF=1'."; \
		exit 1; \
	}
endif

check-bpftool:
ifeq ($(USE_LOCAL_BPFTOOL),1)
	@if [ "$(HAVE_VENDORED_BPFTOOL)" = "0" ]; then \
		echo "❌ Error: bpftool submodule is missing or empty. Run: git submodule update --init --recursive"; \
		exit 1; \
	fi
else
	@command -v $(BPFTOOL) >/dev/null 2>&1 || { \
		echo "❌ Error: System bpftool missing. Install it via package manager or run 'make USE_VENDORED_BPFTOOL=1'."; \
		exit 1; \
	}
endif

check-vmlinux:
	@test -f $(VMLINUX) || { \
		echo "❌ Error: Missing $(VMLINUX). Ensure your architecture is supported."; \
		exit 1; \
	}

$(OUTPUT) $(OUTPUT)/libbpf $(BPFTOOL_OUTPUT):
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

# Build libbpf locally if needed
ifeq ($(USE_LOCAL_LIBBPF),1)
$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile) | $(OUTPUT)/libbpf
	$(call msg,LIB,$@)
	$(Q)$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1              \
            OBJDIR=$(dir $@)/libbpf DESTDIR=$(dir $@)             \
            INCLUDEDIR= LIBDIR= UAPIDIR=                  \
            install
endif

# Build bpftool locally if needed
ifeq ($(USE_LOCAL_BPFTOOL),1)
$(BPFTOOL): | $(BPFTOOL_OUTPUT)
	$(call msg,BPFTOOL,$@)
	$(Q)$(MAKE) ARCH= CROSS_COMPILE= OUTPUT=$(BPFTOOL_OUTPUT)/ -C $(BPFTOOL_SRC) bootstrap
endif

# Rule 1: Kernel Layer
$(OUTPUT)/%.bpf.o: kernel/%.bpf.c $(LIBBPF_BUILD_DEPS) $(wildcard kernel/%.h) $(VMLINUX) | $(OUTPUT) check-libbpf check-vmlinux
	$(call msg,BPF,$@)
	$(Q)$(CLANG) -g -O2 -fno-stack-protector -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) -Ikernel $(CLANG_BPF_SYS_INCLUDES) -c $(filter %.c,$^) -o $@
	$(Q)if command -v $(LLVM_STRIP) >/dev/null 2>&1; then \
        $(LLVM_STRIP) -g $@; \
    else \
        printf '  %-8s %s\n' "INFO" "$(LLVM_STRIP) not found; skipping BPF DWARF stripping for $@"; \
    fi

# Rule 2: Skeleton Bridge
$(OUTPUT)/%.skel.h: $(OUTPUT)/%.bpf.o | $(OUTPUT) check-bpftool $(BPFTOOL_DEPS)
	$(call msg,GEN-SKEL,$@)
	$(Q)$(BPFTOOL) gen skeleton $< > $@

# Rule 3: Main Engine
$(OUTPUT)/main.o: main.c $(OUTPUT)/pardus_dlp.skel.h | $(OUTPUT) check-libbpf
	$(call msg,CC,$@)
	$(Q)mkdir -p $(dir $@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Rule 4: Subsystems
$(OUTPUT)/%.o: %.c $(wildcard %.h) | $(OUTPUT) check-libbpf
	$(call msg,CC,$@)
	$(Q)mkdir -p $(dir $@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $(filter %.c,$^) -o $@

# Rule 5: Final Link
pardus_dlp: $(PARDUS_OBJS) $(LIBBPF_LINK_DEPS) | $(OUTPUT) check-libbpf
	$(call msg,BINARY,$@)
	$(Q)$(CC) $(CFLAGS) $(PARDUS_OBJS) $(ALL_LDFLAGS) $(LIBBPF_LDLIBS) -o $@

.DELETE_ON_ERROR:
.SECONDARY: