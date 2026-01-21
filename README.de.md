
# rIdentD

Rust-Neuimplementierung von oidentd (RFC 1413) mit IPv4/IPv6, NAT-Unterstützung, Forwarding und benutzerabhängigen Capability-Regeln. Ziel ist Kompatibilität zu oidentd 3.x bei moderner Rust-Implementierung.

- English version: see [README.md](README.md).

## Merkmale
- RFC-1413-kompatibles Protokoll (`lport , fport` -> `USERID`-/`ERROR`-Antwort)
- IPv4/IPv6, inetd-/Vordergrund-/Daemon-Modus
- Legacy-Config-Grammatik (`oidentd.conf`) inkl. Capabilities (`reply`, `hide`, `random*`, `numeric`, `forward`, `spoof*`, `allow`/`deny`/`force`)
- Nutzer-Konfigs aus dem Home (XDG oder Legacy, plus Drop-in `~/.rIdentD.conf.d/*.conf`), mit Besitz-Prüfung
- NAT: separates `ridentd-natd` mit Conntrack-Auswertung und statischer Masq-Map; Forwarding und Masquerade-First
- Kernel-UID-Lookup-Abstraktion (Linux procfs/netlink-Stil; BSD getcred)
- Logging über stderr bei TTY/`--nosyslog`; Flags `--quiet`/`--debug`

## Bauen
Klassisches `./configure` + `make` (wrappt Cargo):

```sh
./configure --prefix=/usr --enable-llvm
make            # oder make release
make install    # installiert nach $(SBINDIR), Configs nach $(CONFDIR)
```

Parameter via `./configure --help` oder Umgebungsvariablen (`CARGO`, `CARGOFLAGS`, `RUSTFLAGS`, `PREFIX`, `EXEC_PREFIX`, `SBINDIR`, `SYSCONFDIR`, `CONFDIR`).

## Betrieb
- Haupt-Daemon: `ridentd [Optionen]`, Default-Port 113. `--inetd` für Stdio-Modus.
- NAT-Daemon: `ridentd-natd [Optionen]`, gedacht für Gateways/DMZ, wenn externe Port-113-Anfragen weitergereicht werden.

Häufige Flags (angelehnt an oidentd): `-a`, `-c`, `-C`, `-d`, `-e`, `-f`, `-m`, `-M`, `-P`, `-g`, `-i`, `-I`, `-l`, `-o`, `-p`, `-q`, `-S`, `-t`, `-u`, `-v`, `-r`, `-R`, `-h`. Details per `--help`.

## Konfiguration
System-Config: Standard `/etc/rIdentD` (per Build `RIDENTD_CONFIG_DIR` oder `RIDENTD_PREFIX` anpassbar).
- `oidentd.conf`: Blöcke `default {}` / `user "<name>" {}` mit Matchern (`to/from/fport/lport`) und Capabilities (`reply`, `hide`, `random`, `random_numeric`, `numeric`, `forward`, `spoof`, `spoof_all`, `spoof_privport`, `allow`, `deny`, `force`).
- `oidentd_masq.conf`: statische NAT-Antworten (`host[/mask] user os`).

User-Configs (erste gefundene, Besitzer geprüft):
1. `~/.config/ridentd.conf`
2. `~/.config/oidentd.conf`
3. `~/.ridentd.conf`
4. `~/.rIdentD.conf`
5. `~/.rIdentD.conf.d/*.conf` (alle `*.conf`, sortiert zusammengeführt)
6. `~/.oidentd.conf`

System-Config legt Capabilities fest; User darf nur innerhalb der erlaubten Möglichkeiten wählen. `force` überschreibt Nutzerwünsche.

## Verhalten
- Port-Validierung (1..65535), begrenzte Antwortlängen (~512 Zeichen), kein Panic auf fehlerhafte Eingaben
- Timeout pro Anfrage und Connection-Limit
- Nicht-kryptografischer PRNG für Zufalls-Antworten; Auswahl wird geloggt
- Spoof-Regeln werden erzwungen (`spoof`, `spoof_all`, `spoof_privport`)
- NAT-Forward/Proxy-Optionen analog zu oidentd

## Architektur
- `main.rs`: CLI, Start, Daemon/inetd
- `net/`: Listener mit `mio` (epoll/kqueue) und Worker-Pool, Request-Parsing
- `config/`: Legacy-Parsing, Pfade
- `ident.rs`: Antwortauswahl und Formatierung
- `kernel/`: Plattform-UID-Lookup
- `nat.rs`: Masq-Map und Conntrack
- `util.rs`: Logging-Helfer, PRNG, Config-Laden, Besitzer-Checks

## Status
Ziel: kompatibel zu oidentd 3.x. Offene Punkte in `docs/NEXT_STEPS.md`.

## Lizenz
Anlehnung an oidentd (MIT-ähnlich). Siehe Lizenzdatei, sobald vorhanden.
