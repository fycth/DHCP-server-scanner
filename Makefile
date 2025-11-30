# DHCP Server Scanner Makefile
# Cross-platform: Linux, macOS, FreeBSD, OpenBSD, NetBSD

CC ?= cc
CFLAGS = -Wall -Wextra

# Debug flags
CFLAGS_DEBUG = -g -O0 -DDEBUG

# Release flags
CFLAGS_RELEASE = -O2 -DNDEBUG

# Directories
SRCDIR = src
BINDIR = bin
TESTDIR = tests

# Detect platform
UNAME_S := $(shell uname -s)

# Platform-specific source file
ifeq ($(UNAME_S),Linux)
    PLATFORM_SRC = $(SRCDIR)/platform_linux.c
endif
ifeq ($(UNAME_S),Darwin)
    PLATFORM_SRC = $(SRCDIR)/platform_bsd.c
endif
ifeq ($(UNAME_S),FreeBSD)
    PLATFORM_SRC = $(SRCDIR)/platform_bsd.c
endif
ifeq ($(UNAME_S),OpenBSD)
    PLATFORM_SRC = $(SRCDIR)/platform_bsd.c
endif
ifeq ($(UNAME_S),NetBSD)
    PLATFORM_SRC = $(SRCDIR)/platform_bsd.c
endif
ifeq ($(UNAME_S),DragonFly)
    PLATFORM_SRC = $(SRCDIR)/platform_bsd.c
endif

# Source files
SOURCES = $(SRCDIR)/dhcpd-detector.c $(PLATFORM_SRC)

# Header files
HEADERS = $(SRCDIR)/dhcpd-detector.h $(SRCDIR)/sum.h \
          $(SRCDIR)/arp.h $(SRCDIR)/pseudo.h $(SRCDIR)/platform.h

# Targets
TARGET_DEBUG = $(BINDIR)/dhcpd-detector-debug
TARGET_RELEASE = $(BINDIR)/dhcpd-detector-release
TARGET_TEST = $(BINDIR)/test_runner

.PHONY: all debug release clean info test

all: debug release

debug: $(TARGET_DEBUG)

release: $(TARGET_RELEASE)

$(TARGET_DEBUG): $(SOURCES) $(HEADERS) | $(BINDIR)
	$(CC) $(CFLAGS) $(CFLAGS_DEBUG) -o $@ $(SOURCES)

$(TARGET_RELEASE): $(SOURCES) $(HEADERS) | $(BINDIR)
	$(CC) $(CFLAGS) $(CFLAGS_RELEASE) -o $@ $(SOURCES)

$(BINDIR):
	mkdir -p $(BINDIR)

clean:
	rm -rf $(BINDIR)

# Unit tests (no external dependencies)
test: $(TARGET_TEST)
	@echo "Running tests..."
	@./$(TARGET_TEST)

$(TARGET_TEST): $(TESTDIR)/test_main.c $(SRCDIR)/dhcpd-detector.h $(SRCDIR)/sum.h | $(BINDIR)
	$(CC) $(CFLAGS) $(CFLAGS_DEBUG) -o $@ $(TESTDIR)/test_main.c

# Show detected platform
info:
	@echo "Platform: $(UNAME_S)"
	@echo "Platform source: $(PLATFORM_SRC)"
