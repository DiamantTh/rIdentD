
# rIdentD

Rust rewrite of oidentd (RFC 1413 Ident daemon) with IPv4/IPv6, NAT support, forwarding, and per-user capability rules. Behavior targets oidentd 3.x compatibility while using a modern Rust implementation.

- For German version, see [README.de.md](README.de.md).

## Features
- RFC 1413 wire compatibility (`lport , fport` -> reply `lport,fport:USERID:<os>:<reply>
` or `ERROR:<code>`)
- IPv4/IPv6 listeners, inetd/foreground/daemon modes
- Legacy config parsing (`oidentd.conf` grammar) including capabilities (`reply`, `hide`, `random*`, `numeric`, `forward`, `spoof*`, `allow`/`deny`/`force`)
- User configs from home (XDG or legacy, plus drop-in `~/.rIdentD.conf.d/*.conf`), honoring ownership checks
- NAT: separate `ridentd-natd` binary with conntrack parsing and static masquerade map; forwarding and masquerade-first behavior
- Kernel UID lookup abstraction (Linux procfs/netlink-style; BSD getcred path)
- Logging via stderr when TTY or `--nosyslog`; `--quiet`/`--debug` flags

## Building
Classic `./configure` + `make` frontend (wraps Cargo):

```sh
./configure --prefix=/usr --enable-llvm   # optional flags, see ./configure --help
make                                      # or: make release
make install                              # installs to $(SBINDIR), configs under $(CONFDIR)
```

Environment overrides: `CARGO`, `CARGOFLAGS`, `RUSTFLAGS`, `PREFIX`, `EXEC_PREFIX`, `SBINDIR`, `SYSCONFDIR`, `CONFDIR` (or use `./configure`).

## Running
- Main daemon: `ridentd [options]` (listens on port 113 by default). Use `--inetd` for stdio mode.
- NAT daemon: `ridentd-natd [options]` (for conntrack-based NAT/forwarding). Use on gateways/DMZ; main daemon can stay internal.

Common flags (aiming to match oidentd): `-a`, `-c`, `-C`, `-d`, `-e`, `-f`, `-m`, `-M`, `-P`, `-g`, `-i`, `-I`, `-l`, `-o`, `-p`, `-q`, `-S`, `-t`, `-u`, `-v`, `-r`, `-R`, `-h`. See `--help` for details.

## Configuration
System config directory defaults to `/etc/rIdentD` (configurable via build `RIDENTD_CONFIG_DIR` or `RIDENTD_PREFIX`). Files:
- `oidentd.conf`: legacy grammar with `default {}` and `user "<name>" {}` blocks, range matchers (`to/from/fport/lport`), capabilities (`reply`, `hide`, `random`, `random_numeric`, `numeric`, `forward`, `spoof`, `spoof_all`, `spoof_privport`, `allow`, `deny`, `force`).
- `oidentd_masq.conf`: NAT static replies (`host[/mask] user os`).

User configs (first existing, owner-checked):
1. `~/.config/ridentd.conf`
2. `~/.config/oidentd.conf`
3. `~/.ridentd.conf`
4. `~/.rIdentD.conf`
5. `~/.rIdentD.conf.d/*.conf` (all `*.conf` files, sorted and concatenated)
6. `~/.oidentd.conf`

System config grants/revokes capabilities; user config can only choose within allowed set. `force` overrides user choices.

## Behavior highlights
- Port validation (1..65535), safe formatting, reply length capped (~512 chars)
- Per-request timeout and connection limit
- Random replies use a simple, non-crypto PRNG; choices logged
- Spoof rules enforced (`spoof`, `spoof_all`, `spoof_privport`)
- NAT forward/proxy options mirror oidentd semantics

## Architecture
- `main.rs`: CLI, startup, daemon/inetd handling
- `net/`: listener, epoll/kqueue (`mio`) accept loop with worker pool, request parsing
- `config/`: legacy parsing, paths
- `ident.rs`: response selection and formatting
- `kernel/`: platform UID lookup
- `nat.rs`: masquerade map and conntrack parsing
- `util.rs`: logging helpers, PRNG, config loading, user home ownership checks

## Status & compatibility
Target: behavior compatible with oidentd 3.x. Known gaps/notes are tracked in `docs/NEXT_STEPS.md`.

## License
Same spirit as upstream oidentd (MIT-like). See repository license once added.
