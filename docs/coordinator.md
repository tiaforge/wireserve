# Running the coordinator

Somewhere reachable by every node, behind a reverse proxy that terminates
TLS. You don't need to invent a secret or pick a mesh IP range up front —
the coordinator generates and persists both for you on first start if you
leave them unset.

**Bare metal**: download the coordinator archive for your architecture
from the [releases page](https://github.com/tiaforge/wireserve/releases)
(it holds `wireserve-coordinator` and `wireserve-admin` side by side; check
it against `SHA256SUMS` there if you like) and run its installer:

```sh
VERSION=1.0.0-beta.3
curl -fL https://github.com/tiaforge/wireserve/releases/download/v$VERSION/wireserve-coordinator-$VERSION-$(uname -m)-linux.tar.gz | tar xz
sudo ./wireserve-coordinator-$VERSION-$(uname -m)-linux/wireserve-coordinator install
```

Built [from source](building.md) instead, it is
`sudo ./target/release/wireserve-coordinator install`; the two binaries
just need to sit in one directory.

It asks five questions in plain language, each with a short explanation and
a sensible default:

1. the web address your machines reach the coordinator at (`https://…`);
2. whether the HTTPS web server (reverse proxy) runs on this machine — and,
   if not, which addresses the two machines talk over;
3. the internal port the web server passes requests to (47820): TCP stays
   closed to the internet, UDP may be forwarded for NAT help;
4. whether new services wait for your approval (yes);
5. which local user gets the admin key saved, so `wireserve-admin` needs no
   flags (whoever ran sudo).

Then it creates the `wireserve-coordinator` user and group, installs both
binaries to `/usr/local/bin`, writes `/etc/wireserve/coordinator.env`,
generates the admin key and mesh ranges, starts the service, and prints what
is left by hand: a ready-to-paste Caddy block, the firewall rules, the
command for your first device — and the `setup` commands below, so you know
they exist. Every question also has a flag (`install --help`), and
without a terminal it never asks — `--public-url` is the only one without a
default:

```sh
sudo ./wireserve-coordinator install --public-url https://mesh.example.com --yes
```

Run it again on a machine where it is installed and it **upgrades** instead:
both binaries and the unit replaced and the service restarted, no questions,
`coordinator.env` untouched. Downloading the new version as above and
running its `install` is the whole update. `install --reconfigure` asks the questions again
with the current settings as defaults, and changes only those keys in
`coordinator.env` — a key you drop is commented out, never deleted.

## Later: a domain, and people

What a working mesh doesn't need, install doesn't ask. Each of these is its
own command, run whenever its time comes — and again to change it, or with
`--off` to undo it. Each starts by saying what it is for, checks what it can
before saving (a DNS token, a login server), changes only its own keys and
restarts the coordinator:

```sh
sudo wireserve-coordinator setup domain    # plex.home.example.com instead of plex.wg, on phones too, with HTTPS
sudo wireserve-coordinator setup login     # access follows people, through your login server
```

- **`setup domain`** ([Real names and HTTPS](names-and-https.md)) is worth
  doing early: a domain *replaces* `.wg`, so it renames every service, and
  anything set up with an old name needs the new one. It lists the renames
  before it saves.
- **`setup login`** needs a login server you run — Pocket ID, Authentik,
  Keycloak: [recipes](identity-providers.md). Devices can then
  [belong to someone](access-control.md#devices-that-belong-to-someone), and
  with `setup domain`'s DNS records people sharing a computer
  [sign in](access-control.md#signing-in-for-shared-devices) to web services
  — one client registration for both, nothing else to run.
  `wireserve-admin owner status` shows whether it works.

Without a terminal they take flags (`setup <what> --help`); secrets come
from the environment (`WIRESERVE_DNS_*`, `WIRESERVE_OIDC_CLIENT_SECRET`),
never the command line.

The coordinator runs as its own `wireserve-coordinator` user. Earlier
versions ran it as `wireserve`, which on a host that also runs an agent is the
group allowed to drive the agent daemon (see [Using it without sudo](nodes.md#using-it-without-sudo)); an
upgrade moves it over, and systemd hands the state directory to the new user.
The old `wireserve` user is left alone — keep its group if an agent runs there.

**By hand**, if you'd rather not run the installer:

```sh
sudo useradd --system --user-group --no-create-home --shell /usr/sbin/nologin wireserve-coordinator
sudo install -m 0755 target/release/wireserve-coordinator target/release/wireserve-admin /usr/local/bin/
sudo cp deploy/systemd/wireserve-coordinator.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now wireserve-coordinator
```

No `/etc/wireserve/coordinator.env` is required for this — the unit's
`StateDirectory=` gives the coordinator `/var/lib/wireserve-coordinator` to work with,
and it generates its own admin token and mesh ranges there on first start.
Save the admin token it generated once, so `wireserve-admin` never needs a
flag or env var again:

```sh
mkdir -p ~/.config/wireserve-admin
sudo grep WIRESERVE_ADMIN_TOKEN /var/lib/wireserve-coordinator/coordinator-secrets.env \
    | cut -d= -f2 > ~/.config/wireserve-admin/admin_token
chmod 600 ~/.config/wireserve-admin/admin_token
```

```sh
wireserve-admin node list   # just works — no --coordinator-url, no --admin-token
```

If you'd rather manage the admin token or mesh ranges yourself, copy
`deploy/env/coordinator.env.example` to `/etc/wireserve/coordinator.env`
and set whichever of `WIRESERVE_ADMIN_TOKEN`, `WIRESERVE_NET_V4_CIDR`,
`WIRESERVE_NET_V6_PREFIX` you want — an explicit value there always wins
over the generated one.

**Point a reverse proxy at `127.0.0.1:47820`.** `deploy/proxy/` has a
ready-to-use `Caddyfile.example` (auto-TLS via Let's Encrypt, about five
lines) and `nginx.conf.example`. This is the one piece the coordinator
deliberately never does itself. The coordinator
listens on loopback only unless you set `WIRESERVE_LISTEN_ADDR`, so a
proxy on a different host needs that set to an address it can reach — and
`WIRESERVE_TRUSTED_PROXY` set to the proxy's address, so the coordinator
believes the client addresses it forwards and nobody else's.

**Containers**, if you'd rather not use systemd directly. The image is
published for amd64 and arm64:

```sh
VERSION=1.0.0-beta.3
podman run -d --name wireserve-coordinator \
    -p 127.0.0.1:47820:47820 \
    -v wireserve-coordinator-data:/var/lib/wireserve \
    ghcr.io/tiaforge/wireserve-coordinator:$VERSION
```

To build the image yourself instead, see [Building from source](building.md).

Same zero-config behavior applies: the admin token and mesh ranges are
generated into the named volume on first start unless you pass
`--env-file /etc/wireserve/coordinator.env` with your own values. There is
also a Quadlet unit in `deploy/` for Podman-under-systemd.

The admin port never leaves the host by design, so admin commands run
inside the container:

```sh
podman exec wireserve-coordinator wireserve-admin node list
```
