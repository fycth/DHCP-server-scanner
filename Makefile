# DHCP Server Scanner Makefile

CC = gcc
CFLAGS = -Wall -Wextra

# Debug flags
CFLAGS_DEBUG = -g -O0 -DDEBUG

# Release flags
CFLAGS_RELEASE = -O2 -DNDEBUG

# Directories
SRCDIR = src
BINDIR = bin

# Source files
SOURCES = $(SRCDIR)/dhcpd-detector.c $(SRCDIR)/gopt.c

# Header files
HEADERS = $(SRCDIR)/dhcpd-detector.h $(SRCDIR)/gopt.h $(SRCDIR)/sum.h $(SRCDIR)/arp.h $(SRCDIR)/pseudo.h

# Targets
TARGET_DEBUG = $(BINDIR)/dhcpd-detector-debug
TARGET_RELEASE = $(BINDIR)/dhcpd-detector-release

.PHONY: all debug release clean

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
