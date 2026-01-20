PREFIX ?= /usr/local
CONFDIR ?= $(PREFIX)/etc/rIdentD
BINDIR ?= $(PREFIX)/bin
CARGO ?= cargo
BUILD_ENV ?= RIDENTD_CONFIG_DIR=$(CONFDIR)

.PHONY: all build release test clean install uninstall

all: build

build:
	$(BUILD_ENV) $(CARGO) build

release:
	$(BUILD_ENV) $(CARGO) build --release

test:
	$(BUILD_ENV) $(CARGO) test

clean:
	$(CARGO) clean

install: release
	install -d $(DESTDIR)$(BINDIR)
	install -d $(DESTDIR)$(CONFDIR)
	install -m 0755 target/release/rIdentD $(DESTDIR)$(BINDIR)/ridentd
	install -m 0755 target/release/ridentd-natd $(DESTDIR)$(BINDIR)/ridentd-natd

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/ridentd $(DESTDIR)$(BINDIR)/ridentd-natd
