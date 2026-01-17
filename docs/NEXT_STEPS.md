# rIdentD next steps

- Implement UID lookup trait and Linux/BSD backends (netlink tcpdiag + /proc fallback).
- Wire UID lookup and capability evaluation into request handling.
- Add legacy config parsing tests (ranges, allow/deny/force) and reply selection tests.
- Implement NAT masq parsing + forwarding behavior and integrate with request flow.
- Add CLI flag coverage and logging behavior (syslog vs stderr, quiet/debug).
