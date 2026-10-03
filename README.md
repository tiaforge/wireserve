<h1><img src="docs/assets/wireserve-lockup.svg" alt="wireserve" width="360"></h1>

**Every service you self-host, on every device you own: by name, encrypted
end to end, on infrastructure you control.**

wireserve turns your machines into a private WireGuard mesh and puts your
services on it by name. Publish Plex on your home server with one command,
and `plex.wg` works on your laptop, your phone and every other machine you
have added. Nothing is opened to the internet, there are no WireGuard
configs to write and no third-party account. You run the coordinator
yourself, and it never sees your traffic or a single private key.

```sh
wireserve plex 80:32400    # plex.wg now reaches Plex from anywhere in your mesh
```

## Why wireserve

- 🔌 **No hand-written WireGuard.** A machine joins with one command and
  a token. wireserve handles addresses, keys and peer lists, and machines
  connect to each other directly, through NAT included.
- 🏷️ **Services, not IP addresses.** One command publishes a service, and
  every machine reaches it by name. Each service gets its own address, and
  only the ports you publish are open. The rest of the machine stays
  closed.
- 🔒 **Real HTTPS on your own domain.** Optionally, `plex.example.com` gets
  a Let's Encrypt certificate, and wireserve manages the DNS records for you
  (Cloudflare, deSEC, Hetzner, Porkbun or any RFC 2136 server). The
  certificate's key is created and kept on the machine that serves it.
  WebSockets work.
- 🪪 **Sign in with your own identity provider.** Put any web service behind
  your Pocket ID, Authentik or Keycloak login, and decide who reaches what
  by group, tag or user: `wireserve-admin grant add oidc:family media`.
- 📱 **Phones with the stock WireGuard app.** Scan a QR code and you're in,
  with no extra app. On untrusted Wi-Fi, a phone can send all its internet
  traffic home through an exit node.
- 🧱 **Gets through even hard NAT.** When two machines can't reach each
  other directly, a third one relays their traffic. The connection stays
  encrypted end to end, so the relay can't read it, and you don't run any
  relay servers.
- 🖨️ **Brings your LAN along.** Publish a router, NAS or printer through the
  machine next to it, without installing anything on the device.
- 🧯 **Works with the firewall you already have.** ufw, firewalld, Docker
  hosts and your own nftables rules keep working. wireserve opens exactly
  the mesh interface and nothing else, and restores that opening when they
  reload.
- 🛡️ **You stay in charge.** Nothing is published until you approve it, a
  node can't carry other nodes' traffic unless you allow it, and a lost
  laptop is cut off with one command.

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
