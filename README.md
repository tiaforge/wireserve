# wireserve

A self-hosted WireGuard mesh for publishing services between your own
machines. You run one coordinator, and every machine that joins can reach
the others directly and publish services under names like `plex.wg`. No
traffic goes through the coordinator, and it never sees a private key.

## Features

- **A WireGuard mesh with nothing to configure by hand.** Each machine gets
  a stable address and its peer list is kept up to date. It connects
  directly to the others, through NAT where it can.
- **Publish services by name.** `wireserve plex 80:32400` makes `plex.wg`
  reach port 32400 on this machine. Each service has its own address, and
  only the ports you publish are open.
- **Phones and laptops without extra software.** They use the standard
  WireGuard app with a generated config or a QR code.
- **Works behind NAT.** When two machines can't reach each other, another
  machine relays their traffic without being able to read it.
- **Real names and HTTPS, optional.** Services can get names under your own
  domain and Let's Encrypt certificates, issued on the machine that runs
  them.
- **Access control.** Choose who reaches what with groups, tags and your
  identity provider's users, and require a sign-in for web services.
- **Exit node.** A phone can send all its internet traffic through a
  machine at home.
- **Devices on your LAN.** Publish a router or printer through the machine
  next to it.

## Requirements

- Linux with systemd on every machine that joins (phones excepted), with
  `nftables` installed.
- A host for the coordinator that every machine can reach over HTTPS, with
  a reverse proxy such as Caddy or nginx in front of it.
- A Rust toolchain to build the binaries: `cargo build --release --workspace`.

## Quick start

**1. Install the coordinator** on a host every machine can reach:

```sh
sudo ./wireserve-coordinator install
```

It asks a few questions and starts the service. Then point your reverse
proxy at `127.0.0.1:47820`; the installer prints a ready-to-use Caddy block.

**2. Add a machine.** On the coordinator:

```sh
wireserve-admin node create homeserver
```

Then, on the new machine, paste the join token when asked:

```sh
sudo wireserve install https://mesh.example.com
```

**3. Publish a service** on that machine, and approve it on the coordinator:

```sh
wireserve plex 80:32400
wireserve-admin service approve plex --node homeserver
```

Every machine in the mesh can now reach `http://plex.wg`.

**4. Add a phone**, and scan the code with the WireGuard app:

```sh
wireserve-admin device create myphone --qr
```

## Everyday use

On a machine:

```sh
wireserve status                 # services and peers
wireserve web 80:5080            # publish web.wg:80 → local port 5080
wireserve web off                # stop publishing it
sudo usermod -aG wireserve $USER # use wireserve without sudo
```

On the coordinator:

```sh
wireserve-admin service list --pending   # services waiting for approval
wireserve-admin node list                # all machines
wireserve-admin node revoke laptop       # cut a lost machine off
```

Run any command with `--help` for its options.

## Documentation

- [Running the coordinator](docs/coordinator.md): installation, reverse
  proxy, containers
- [Adding nodes](docs/nodes.md): joining, upgrading, several meshes on one
  host
- [Publishing services](docs/services.md): ports, approval, devices on a
  node's LAN
- [Phones and laptops](docs/devices.md): configs, exit node, DNS
- [Real names and HTTPS](docs/names-and-https.md): your own domain, DNS
  providers, certificates
- [Who can reach what](docs/access-control.md): groups, grants, tags,
  owners, sign-in
- [Relaying between nodes](docs/relaying.md): when machines can't reach each
  other directly
- [Ports, firewalls and host setup](docs/firewall.md): what each machine
  needs open
- [Security](docs/security.md): what a node can do, lost machines
- [Command reference](docs/commands.md)
- [Building from source](docs/building.md)
