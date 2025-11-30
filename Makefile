# DHCP Server Scanner Makefile
# Cross-platform: Linux and macOS

CC = gcc
CFLAGS = -Wall -Wextra

# Debug flags
CFLAGS_DEBUG = -g -O0 -DDEBUG

# Release flags
CFLAGS_RELEASE = -O2 -DNDEBUG

# Directories
SRCDIR = src
BINDIR = bin

# Detect platform
UNAME_S := $(shell uname -s)

# Platform-specific source file
ifeq ($(UNAME_S),Linux)
    PLATFORM_SRC = $(SRCDIR)/platform_linux.c
endif
ifeq ($(UNAME_S),Darwin)
    PLATFORM_SRC = $(SRCDIR)/platform_darwin.c
endif

# Source files
SOURCES = $(SRCDIR)/dhcpd-detector.c $(PLATFORM_SRC)

# Header files
HEADERS = $(SRCDIR)/dhcpd-detector.h $(SRCDIR)/sum.h \
          $(SRCDIR)/arp.h $(SRCDIR)/pseudo.h $(SRCDIR)/platform.h

# Targets
TARGET_DEBUG = $(BINDIR)/dhcpd-detector-debug
TARGET_RELEASE = $(BINDIR)/dhcpd-detector-release

.PHONY: all debug release clean info

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

# Show detected platform
info:
	@echo "Platform: $(UNAME_S)"
	@echo "Platform source: $(PLATFORM_SRC)"
