# Phones and laptops

A device that only consumes services does not run the agent. This creates
the node and prints a ready-to-import WireGuard config:

```sh
podman exec wireserve-coordinator wireserve-admin device create myphone \
    --out myphone.conf
```

Import it into the official WireGuard app, by file or with `--qr`, which
prints a code to scan straight from the terminal. The file contains a
private key, so it is written mode 600; move it, do not copy it. (So does
the QR code — it will sit in your scrollback.) Such a peer gets a mesh
address and reaches every service by its address (in `wireserve-admin
service list`) and port, but has no `.wg` name resolution.

**Every node, end to end.** The config holds one `[Peer]` per node, and the
phone talks to each one directly — WireGuard between the two, as between
agents. How depends on the node:

- **A node that accepts inbound WireGuard** (a VPS, a home server with a port
  forward) is dialled at its own endpoint. Each agent finds this out itself
  when it starts: the coordinator answers its startup probe a second time,
  from a port the node never sent anything to, and that answer only gets in
  where the node's router or firewall lets unsolicited traffic in.
  `node show <name>` shows the result (`dialable: yes|no`).
- **Every other node** — behind a NAT nothing gets through (a home server
  without a port forward, CGNAT), or one that hasn't said, because it is
  offline or runs an older agent — is reached through a **carrier**: an
  approved node with a public IPv4 address, preferably one that reaches it
  right now. An offline node's relay works once it is back. The phone dials the
  carrier's public address on that node's **relay port**, and the carrier
  sends the packets on to the node without being able to read them — the
  session is the phone's and the node's, the carrier holds no key to it.
  It still sees that the two talk, when and how much.

```sh
wireserve-admin transit approve vps1      # and `wireserve transit on` on vps1
wireserve-admin device create myphone --qr
```

Before writing anything the export checks, from outside, that every relay
port it needs is open, since that is the one thing that may need doing by
hand (see [Ports and firewalls](firewall.md)), and it lists every port the
config relies on each time. A port on the coordinator's own host can't be
checked — the check would never leave the machine — so it is listed as
`NOT CHECKED`: make sure it is open in any firewall in front of that host
(a cloud provider's panel, say). A closed one stops the export:

```
these relay ports must be reachable from the internet first:
  open UDP 41003 inbound on vps1 (203.0.113.7) in any firewall outside the
  host — cloud firewall or router port forward — for minipc; it was not reachable
then run this again (or pass --allow-unverified to write the config regardless)
```

Each node's relay port is `41000` plus a number it keeps for life, the same
on every carrier, so a port opened once stays right. The export prefers a
carrier whose port for that node is already open, then one already serving
phones, so as few as possible ever need opening. `wireserve-admin
relay-ports` lists every one: where it must be open, which node it leads to,
which devices use it, whether it was open when last checked — and which no
device uses any more and may be closed again.

**The config is a snapshot.** A node that joins later isn't in it, nor is
one no carrier reaches at the time of the export (the export says so).
`node list` notes such devices as stale; `device refresh` (below) brings one
up to date. A withdrawn (or revoked, or deleted) service's address is held
back meanwhile: an older config still sends it to the node that had it, so no
other node's service gets it until every device exported before is exported
again or deleted. `node show <device>` lists those addresses under `holds`; a node
that declares a service again takes its own back. Two phones don't reach each other: neither has anything the
other could dial.

**Re-issuing a config** keeps the device's name and mesh address:

```sh
wireserve-admin device refresh myphone --qr
```

Only the keypair changes. Delete the old tunnel on the device before
importing the new one — the address is unchanged, so the stale config still
looks valid, and two tunnels claiming one address is its own kind of
confusing. This is destructive from its first call: the old key stops
working immediately and the device is briefly absent from the mesh while
the new one is redeemed. It refuses outright if the name belongs to a node
that runs the agent.


## Send all of a phone's traffic through an exit

For public Wi-Fi, or to browse from home while away, a device can also get a
**full-tunnel profile**: same key, same address, same end-to-end entries for
every node, but everything else goes to an **exit**, which sends it on to the
internet under its own address. The exit reads that traffic, as any exit
does — only the mesh stays end to end. It opts in first, as for transit,
because the traffic leaves under *its* public IP, and the phone must be able
to dial it directly:

```sh
wireserve exit on                           # on the exit, besides `transit on`
wireserve-admin device create myphone --exit vps1 --dns 9.9.9.9 --qr
```

With exactly one node qualifying, `--exit` needs no name.

That prints two codes; import both. The WireGuard app runs one tunnel at a
time, so switching on `myphone-exit` is the exit switch. With `--out
myphone.conf` the second one is written beside it as `myphone-exit.conf`.
`device refresh` without `--exit` withdraws it.

- **IPv4 only.** The full tunnel captures the device's IPv6 as well, so none
  of it leaks around the tunnel on someone else's network, and the exit
  drops it. Phones fall back to IPv4 on their own, since the only IPv6
  address the tunnel gives them is a private one.
- **The internet, not the exit's LAN.** Private and other non-public
  destinations are refused, so the exit never reaches around the per-service
  approval a device on a LAN needs. To reach one, [serve it](#devices-on-the-nodes-network).
- **`--dns` is required.** Without it, the phone keeps asking the café's
  resolver, at a private address the exit will not forward to.

### A home resolver, which also names the mesh

`--dns` takes an approved service by name, so the full-tunnel profile can use
your own resolver: ad blocking on the go, and **names for every service,
not just HTTP ones**. A resolver that runs on a node reads that node's
`/etc/hosts`, where the agent writes every service's name:

```sh
wireserve dns 53:53/udp 53:53/tcp     # on the node running the resolver
wireserve-admin service approve dns --node homeserver
wireserve-admin device refresh myphone --exit vps1 --dns dns --qr
```

`ssh backup.wg` and `jellyfin.wg:8096` then work from the phone while the
full tunnel is on. A domain set with `WIRESERVE_SERVICE_DOMAIN` works the same
way, and a resolver answering the mesh's names itself is not affected by
[rebinding protection](#if-the-name-resolves-on-one-network-but-not-another).

- **The resolver must pick up changes to `/etc/hosts`.** AdGuard Home
  (`dns.hostsfile_enabled`) does. dnsmasq, and so Pi-hole, read it at start
  and on `SIGHUP` only, so a service added later has no name until they
  reload. A path unit fixes that:

  ```ini
  # /etc/systemd/system/wireserve-hosts.path
  [Path]
  PathChanged=/etc/hosts
  [Install]
  WantedBy=multi-user.target

  # /etc/systemd/system/wireserve-hosts.service
  [Service]
  Type=oneshot
  ExecStart=/usr/local/bin/pihole reloaddns   # or: /usr/bin/pkill -HUP dnsmasq
  ```

- **A resolver in a container does not see the host's names.** The agent
  replaces `/etc/hosts` atomically, and a single bind-mounted file keeps
  showing the old copy. Run it on the host, or give up the names.
- **Let it answer the mesh, and nothing else.** Queries arrive on the node's
  mesh address from the phones' mesh addresses. Pi-hole's "allow only local
  requests" may refuse them, but "permit all origins" on a node with a public
  interface is an open resolver: bind to the mesh address instead.
- A resolver on a LAN appliance works through a
  [LAN mapping](#devices-on-the-nodes-network) (`wireserve dns
  53:192.168.1.2:53/udp`), but it has no names of the mesh's own.

### The same names without the full tunnel

The mesh profile can name the resolver too, so every service has a name on
the phone whether or not the full tunnel is on:

```sh
wireserve-admin device refresh myphone --dns dns --mesh-dns --qr
# with the exit as well:  ... --exit --dns dns --mesh-dns ...
```

This is a trade-off, which is why it is opt-in. The phone apps cannot send
only the mesh's names to a resolver: a `DNS =` line takes **all** of the
device's DNS while the tunnel is on. So the resolver has to answer
everything, as a Pi-hole or AdGuard Home does, and if it goes down, so does
the phone's DNS until you switch the tunnel off. It must also be on the mesh
(a service, or a node's own address): the mesh profile carries nothing else,
so a public resolver would be asked outside the tunnel and name nothing.
