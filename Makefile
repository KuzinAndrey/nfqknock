# Makefile for knockd (NFQUEUE-based port knocker)

# Compiler
CC = gcc

# Compiler flags
CFLAGS_COMMON = -Wall -Wextra -Werror -pedantic -std=gnu99 -D_GNU_SOURCE
CFLAGS_DEBUG = $(CFLAGS_COMMON) -O0 -g -DDEBUG
CFLAGS_RELEASE = $(CFLAGS_COMMON) -O2 -DNDEBUG

# Linker flags
LFLAGS_DEBUG =
LFLAGS_RELEASE = -s

# Choose build type: debug or release
BUILD ?= release
ifeq ($(BUILD), debug)
    CFLAGS = $(CFLAGS_DEBUG)
    LFLAGS = $(LFLAGS_DEBUG)
else
    CFLAGS = $(CFLAGS_RELEASE)
    LFLAGS = $(LFLAGS_RELEASE)
endif

# Libraries
LIBS = -lnfnetlink -lnetfilter_queue -lcrypto

# Source and object
SRC = nfqknockd.c
OBJ = $(SRC:.c=.o)
TARGET = nfqknockd

# Installation paths
PREFIX ?= /usr
BINDIR = $(PREFIX)/bin
MANDIR = $(PREFIX)/share/man

# Default target
.PHONY: all clean install uninstall

all: $(TARGET)

# Rule to build object with dependency tracking
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@ -MMD -MP

# Link target
$(TARGET): $(OBJ)
	$(CC) $(LFLAGS) $(OBJ) -o $(TARGET) $(LIBS)

# Include dep files
-include $(OBJ:.o=.d)

# Clean
clean:
	rm -f $(OBJ) $(TARGET) $(OBJ:.o=.d) *~

# Install
install: $(TARGET)
	install -d $(DESTDIR)$(BINDIR)
#	install -d $(DESTDIR)$(MANDIR)/man8
	install -m 755 $(TARGET) $(DESTDIR)$(BINDIR)/$(TARGET)
	install -m 755 nfqknockd_ssh_wrapper $(DESTDIR)$(BINDIR)/nfqknockd_ssh_wrapper
#	# Optional: install man page if exists
#	# install -m 644 $(TARGET).8 $(DESTDIR)$(MANDIR)/man8/

# Uninstall
uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(TARGET)
#	rm -f $(DESTDIR)$(MANDIR)/man8/$(TARGET).8

# Phony targets
.PHONY: all clean install uninstall

# Optional: run with sudo
.PHONY: install-sudo
install-sudo:
	$(MAKE) install DESTDIR=/ PREFIX=/usr

# Print help
.PHONY: help
help:
	@echo "Usage: make [target]"
	@echo
	@echo "Targets:"
	@echo "  all            - Build $(TARGET) (default)"
	@echo "  clean          - Remove build artifacts"
	@echo "  install        - Install to $(PREFIX) (use DESTDIR= for packaging)"
	@echo "  install-sudo   - Install to /usr with sudo"
	@echo "  uninstall      - Remove installed files"
	@echo
	@echo "Options:"
	@echo "  BUILD=debug    - Enable debug build (default: release)"
	@echo "  PREFIX=/path   - Set install prefix (default: /usr)"
	@echo
	@echo "Example:"
	@echo "  make"
	@echo "  make BUILD=debug"
	@echo "  make install PREFIX=/usr"
