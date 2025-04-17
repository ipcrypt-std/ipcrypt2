# Makefile for building libipcrypt.a
# This Makefile is designed to work with both GNU Make and BSD Make

# Compiler settings
CC ?= cc
AR ?= ar
RANLIB ?= ranlib
CFLAGS ?= -O2 -Wall -Wextra
CFLAGS += -I./src/include

# Installation settings
PREFIX ?= /usr/local
LIBDIR = $(PREFIX)/lib
INCLUDEDIR = $(PREFIX)/include
INSTALL ?= install
INSTALL_DATA ?= $(INSTALL) -m 644
INSTALL_DIR ?= $(INSTALL) -d -m 755
RM ?= rm -f

# Source files
SRC_DIR = src
SRCS = $(SRC_DIR)/ipcrypt2.c
OBJS = $(SRCS:.c=.o)

# Library name
LIBNAME = libipcrypt.a

# Default target
all: $(LIBNAME)

# Build the static library
$(LIBNAME): $(OBJS)
	$(AR) rcs $@ $(OBJS)
	$(RANLIB) $@

# Compile source files
.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

# Install the library and header files
install: $(LIBNAME)
	$(INSTALL_DIR) $(DESTDIR)$(LIBDIR)
	$(INSTALL_DIR) $(DESTDIR)$(INCLUDEDIR)
	$(INSTALL_DATA) $(LIBNAME) $(DESTDIR)$(LIBDIR)/
	$(INSTALL_DATA) $(SRC_DIR)/include/ipcrypt2.h $(DESTDIR)$(INCLUDEDIR)/

# Uninstall the library and header files
uninstall:
	$(RM) $(DESTDIR)$(LIBDIR)/$(LIBNAME)
	$(RM) $(DESTDIR)$(INCLUDEDIR)/ipcrypt2.h

# Clean up
clean:
	$(RM) $(OBJS) $(LIBNAME)

# Test target
test check:
	@if command -v zig >/dev/null 2>&1; then \
		zig build test; \
	else \
		echo "zig not found - skipping tests"; \
		exit 0; \
	fi

# Phony targets
.PHONY: all clean install uninstall test check
