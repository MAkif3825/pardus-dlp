# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
OUTPUT := .output
CLANG ?= clang
LLVM_STRIP ?= llvm-strip
LIBBPF_SRC := $(abspath ../libbpf/src)
BPFTOOL_SRC := $(abspath ../bpftool/src)
LIBBPF_OBJ := $(abspath $(OUTPUT)/libbpf.a)
BPFTOOL_OUTPUT ?= $(abspath $(OUTPUT)/bpftool)
ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' \
				 | sed 's/aarch64/arm64/' \
				 | sed 's/ppc64le/powerpc/' \
				 | sed 's/mips.*/mips/' \
				 | sed 's/arm.*/arm/' \
				 | sed 's/riscv64/riscv/')
VMLINUX := ../vmlinux/$(ARCH)/vmlinux.h
CFLAGS := -g -Wall
ALL_LDFLAGS := $(LDFLAGS) $(EXTRA_LDFLAGS)

APPS = pardus_dlp

# Dosyalarımız zaten burada olduğu için hedef yolları doğrudan .output altına eşliyoruz
PARDUS_OBJS := $(OUTPUT)/main.o \
               $(OUTPUT)/dispatch.o \
               $(OUTPUT)/event_utils.o \
               $(OUTPUT)/alert.o \
               $(OUTPUT)/policy.o \
               $(OUTPUT)/detectors/policy_detector.o

USE_VENDORED_LIBBPF ?= auto
USE_VENDORED_BPFTOOL ?= auto

HAVE_VENDORED_LIBBPF := $(if $(wildcard $(LIBBPF_SRC)/Makefile),1,0)
HAVE_VENDORED_BPFTOOL := $(if $(wildcard $(BPFTOOL_SRC)/Makefile),1,0)
HAVE_SYSTEM_LIBBPF := $(shell pkg-config --exists libbpf 2>/dev/null && echo 1 || echo 0)
HAVE_SYSTEM_BPFTOOL := $(shell command -v bpftool >/dev/null 2>&1 && echo 1 || echo 0)

ifeq ($(USE_VENDORED_LIBBPF),1)
USE_LOCAL_LIBBPF := 1
else ifeq ($(USE_VENDORED_LIBBPF),0)
USE_LOCAL_LIBBPF := 0
else ifeq ($(HAVE_SYSTEM_LIBBPF),1)
USE_LOCAL_LIBBPF := 0
else
USE_LOCAL_LIBBPF := $(HAVE_VENDORED_LIBBPF)
endif

ifeq ($(USE_VENDORED_BPFTOOL),1)
USE_LOCAL_BPFTOOL := 1
else ifeq ($(USE_VENDORED_BPFTOOL),0)
USE_LOCAL_BPFTOOL := 0
else ifeq ($(HAVE_SYSTEM_BPFTOOL),1)
USE_LOCAL_BPFTOOL := 0
else
USE_LOCAL_BPFTOOL := $(HAVE_VENDORED_BPFTOOL)
endif

INCLUDES := -I$(OUTPUT) -I$(dir $(VMLINUX))

ifeq ($(USE_LOCAL_LIBBPF),1)
INCLUDES += -I../libbpf/include/uapi
LIBBPF_CFLAGS :=
LIBBPF_BUILD_DEPS := $(LIBBPF_OBJ)
LIBBPF_LINK_DEPS := $(LIBBPF_OBJ)
LIBBPF_LDLIBS := -lelf -lz
else
LIBBPF_CFLAGS := $(shell pkg-config --cflags libbpf 2>/dev/null)
INCLUDES += $(LIBBPF_CFLAGS)
LIBBPF_BUILD_DEPS :=
LIBBPF_LINK_DEPS :=
LIBBPF_LDLIBS := $(shell pkg-config --libs libbpf 2>/dev/null)
endif

ifeq ($(USE_LOCAL_BPFTOOL),1)
BPFTOOL ?= $(BPFTOOL_OUTPUT)/bootstrap/bpftool
BPFTOOL_DEPS := $(BPFTOOL)
else
BPFTOOL ?= bpftool
BPFTOOL_DEPS :=
endif

# Get Clang's default includes on this system. We'll explicitly add these dirs
# to the includes list when compiling with `-target bpf` because otherwise some
# architecture-specific dirs will be "missing" on some architectures/distros -
# headers such as asm/types.h, asm/byteorder.h, asm/socket.h, asm/sockios.h,
# sys/cdefs.h etc. might be missing.
#
# Use '-idirafter': Don't interfere with include mechanics except where the
# build would have failed anyways.
CLANG_BPF_SYS_INCLUDES = $(shell $(CLANG) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

ifeq ($(V),1)
	Q =
	msg =
else
	Q = @
	msg = @printf '  %-8s %s%s\n'					\
		      "$(1)"						\
		      "$(patsubst $(abspath $(OUTPUT))/%,%,$(2))"	\
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

.PHONY: all
all: $(APPS)

.PHONY: clean
clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(OUTPUT) $(APPS)

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

# Build libbpf
ifeq ($(USE_LOCAL_LIBBPF),1)
$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile) | $(OUTPUT)/libbpf
	$(call msg,LIB,$@)
	$(Q)$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1		      \
		    OBJDIR=$(dir $@)/libbpf DESTDIR=$(dir $@)		      \
		    INCLUDEDIR= LIBDIR= UAPIDIR=			      \
		    install
endif

# Build bpftool
ifeq ($(USE_LOCAL_BPFTOOL),1)
$(BPFTOOL): | $(BPFTOOL_OUTPUT)
	$(call msg,BPFTOOL,$@)
	$(Q)$(MAKE) ARCH= CROSS_COMPILE= OUTPUT=$(BPFTOOL_OUTPUT)/ -C $(BPFTOOL_SRC) bootstrap
endif

# Build BPF code
$(OUTPUT)/%.bpf.o: %.bpf.c $(LIBBPF_BUILD_DEPS) $(wildcard %.h) $(VMLINUX) | $(OUTPUT) check-libbpf check-vmlinux
	$(call msg,BPF,$@)
	$(Q)$(CLANG) -g -O2 -fno-stack-protector -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) -c $(filter %.c,$^) -o $@
	$(Q)if command -v $(LLVM_STRIP) >/dev/null 2>&1; then \
		$(LLVM_STRIP) -g $@; \
	else \
		printf '  %-8s %s\n' "INFO" "$(LLVM_STRIP) not found; skipping BPF DWARF stripping for $@"; \
	fi

# Generate BPF skeletons
$(OUTPUT)/%.skel.h: $(OUTPUT)/%.bpf.o | $(OUTPUT) check-bpftool $(BPFTOOL_DEPS)
	$(call msg,GEN-SKEL,$@)
	$(Q)$(BPFTOOL) gen skeleton $< > $@

# Skeletons dependency mapping
$(OUTPUT)/main.o: main.c $(OUTPUT)/pardus_dlp.skel.h | $(OUTPUT) check-libbpf
	$(call msg,CC,$@)
	$(Q)mkdir -p $(dir $@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# C compilation logic matching files in current location
$(OUTPUT)/%.o: %.c $(wildcard %.h) | $(OUTPUT) check-libbpf
	$(call msg,CC,$@)
	$(Q)mkdir -p $(dir $@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $(filter %.c,$^) -o $@

# Final dynamic linker action combining binary assets
pardus_dlp: $(PARDUS_OBJS) $(LIBBPF_LINK_DEPS) | $(OUTPUT) check-libbpf
	$(call msg,BINARY,$@)
	$(Q)$(CC) $(CFLAGS) $(PARDUS_OBJS) $(ALL_LDFLAGS) $(LIBBPF_LDLIBS) -o $@

# delete failed targets
.DELETE_ON_ERROR:

# keep intermediate (.skel.h, .bpf.o, etc) targets
.SECONDARY:
