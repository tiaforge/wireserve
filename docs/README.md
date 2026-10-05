# wireserve documentation

## How it works

```
  admin CLI ──▶ coordinator ◀── agents poll every ~20s over HTTPS
                (axum + SQLite)     │
                                    ├─ configure WireGuard peers
                                    ├─ open only declared ports on wireserve0
                                    └─ write <service>.wg into /etc/hosts
                                       (each service has its own address)
```

The coordinator holds no private keys and is never itself a WireGuard peer.
Each node generates its own keypair locally and sends only the public half.
Nodes talk to each other directly; the coordinator only tells them who
exists.

## Pages

- [Running the coordinator](coordinator.md)
- [Adding nodes](nodes.md)
- [Publishing services](services.md)
- [Phones and laptops](devices.md)
- [Real names and HTTPS](names-and-https.md)
- [Who can reach what](access-control.md)
- [Identity providers](identity-providers.md)
- [Relaying between nodes](relaying.md)
- [Ports, firewalls and host setup](firewall.md)
- [Security](security.md)
- [Command reference](commands.md)
- [Building from source](building.md)
- [Releasing](releasing.md)
