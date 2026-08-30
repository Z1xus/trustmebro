# C11, Linux and macOS.
CC      ?= cc
CFLAGS  ?= -std=c11 -Os -Wall -Wextra \
           -fno-asynchronous-unwind-tables -fno-unwind-tables \
           -ffunction-sections -fdata-sections
PREFIX  ?= $(HOME)/.local

# Dead-code stripping differs between GNU ld and macOS ld64.
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
  LDFLAGS ?= -Wl,-dead_strip
else
  LDFLAGS ?= -Wl,--gc-sections -s
  CFLAGS  += -fno-ident
endif

SRC = main.c cli.c shim.c config.c util.c
HDR = tmb.h
BIN = trustmebro

$(BIN): $(SRC) $(HDR)
	$(CC) $(CFLAGS) -o $@ $(SRC) $(LDFLAGS)
ifeq ($(UNAME_S),Darwin)
	strip $(BIN)
endif

.PHONY: install uninstall sync clean size
install: $(BIN)
	mkdir -p $(PREFIX)/bin
	cp -f $(BIN) $(PREFIX)/bin/$(BIN)
	chmod 755 $(PREFIX)/bin/$(BIN)
	ln -sf $(BIN) $(PREFIX)/bin/tmb
	$(PREFIX)/bin/$(BIN) sync || true

uninstall:
	@if [ -x "$(PREFIX)/bin/$(BIN)" ]; then $(PREFIX)/bin/$(BIN) uninstall; fi
	rm -f $(PREFIX)/bin/$(BIN) $(PREFIX)/bin/tmb
	rm -rf $$(./$(BIN) path 2>/dev/null) 2>/dev/null || true

sync: $(BIN)
	./$(BIN) sync

size: $(BIN)
	@size $(BIN) 2>/dev/null || true
	@ls -l $(BIN)

clean:
	rm -f $(BIN) *.o
