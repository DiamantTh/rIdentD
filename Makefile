-include config.mk

PREFIX ?= /usr/local
EXEC_PREFIX ?= $(PREFIX)
BINDIR ?= $(EXEC_PREFIX)/bin
SBINDIR ?= $(EXEC_PREFIX)/sbin
SYSCONFDIR ?= $(PREFIX)/etc
CONFDIR ?= $(SYSCONFDIR)/rIdentD
CARGO ?= cargo
CARGOFLAGS ?=
RUSTFLAGS ?=
BUILD_ENV ?= RIDENTD_CONFIG_DIR=$(CONFDIR)

.PHONY: all build release test clean install uninstall

all: build

build:
	RUSTFLAGS="$(RUSTFLAGS)" $(BUILD_ENV) $(CARGO) build $(CARGOFLAGS)

release:
	RUSTFLAGS="$(RUSTFLAGS)" $(BUILD_ENV) $(CARGO) build --release $(CARGOFLAGS)

test:
	RUSTFLAGS="$(RUSTFLAGS)" $(BUILD_ENV) $(CARGO) test $(CARGOFLAGS)

clean:
	$(CARGO) clean

install: release
	install -d $(DESTDIR)$(SBINDIR)
	install -d $(DESTDIR)$(CONFDIR)
	install -m 0755 target/release/rIdentD $(DESTDIR)$(SBINDIR)/ridentd
	install -m 0755 target/release/ridentd-natd $(DESTDIR)$(SBINDIR)/ridentd-natd

uninstall:
	rm -f $(DESTDIR)$(SBINDIR)/ridentd $(DESTDIR)$(SBINDIR)/ridentd-natd
