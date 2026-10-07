# Adding nodes

`wireserve-admin` doesn't have to run on the coordinator host — it's a
plain HTTP client, so it works just as well from your own laptop, as long
as it can reach the admin listener (loopback-only by default; bind it to
a private address, or SSH-tunnel it, to reach it from elsewhere). Give it
the coordinator's public URL once and it remembers it:

```sh
wireserve-admin node create homeserver
```

If you haven't set `--coordinator-url`/`WIRESERVE_COORDINATOR_URL` or
`--admin-token`/`WIRESERVE_ADMIN_TOKEN` (or the coordinator host's own
generated `coordinator-secrets.env`, see [Running the coordinator](coordinator.md)), it asks for each —
masked for the token — and offers to save both to
`~/.config/wireserve-admin/` so you're never asked again. Same for
`--register-url`/`WIRESERVE_REGISTER_URL` (the coordinator's *other*
listener, the one nodes actually register against): set it once and every
`node create`/`node rejoin` prints the exact command to run on the new node:

```
node 'homeserver' created — join token: jtk_...
  redeemable until: ...

To add this node to the mesh:
  sudo wireserve install https://wireserve.example.com
  (needs the wireserve binary already on that machine, and root)
  then paste the join token above when prompted
```

**The token is redeemable for 30 minutes** — long enough to walk over
to the machine, short enough that a token left in a chat log or a password
manager is not a live way into the mesh months later. If the window lapses,
`wireserve-admin node rejoin <name>` mints a fresh one for the same node, name
and address. Override with `--ttl <secs>` per token, or coordinator-wide
with `WIRESERVE_JOIN_TOKEN_TTL_SECS`; `0` disables expiry.

On the node itself, download the `wireserve` archive for your
architecture from the [releases page](https://github.com/tiaforge/wireserve/releases)
and run its `install` (built [from source](building.md) instead, it is
`target/release/wireserve`):

```sh
VERSION=1.0.0-beta.1
curl -fL https://github.com/tiaforge/wireserve/releases/download/v$VERSION/wireserve-$VERSION-$(uname -m)-linux.tar.gz | tar xz
sudo ./wireserve-$VERSION-$(uname -m)-linux/wireserve install https://wireserve.example.com
```

One command: it installs the binary to `/usr/local/bin/wireserve`, installs
and enables the right systemd unit, then joins — prompting for the join token
(masked, not echoed) exactly like `join` does below, so nothing sensitive
ever lands in shell history. It also creates a `wireserve` group (see
[Using it without sudo](#using-it-without-sudo)); it does not add anyone to it. Running an *additional* agent on a host that
already runs one? Add `--instance work` (see [Several agents on one host](#several-agents-on-one-host)); `wireserve-admin node create --instance work` fills that flag into
the printed command for you. `install` needs Linux/systemd — Quadlet/podman
deployments install by hand, per `deploy/quadlet/`.

**Run the agent on the host, not in a container, on any node that forwards**:
a carrier, an exit, or a node serving a device on its LAN. Those need the agent to switch on forwarding for its own interfaces
in `/proc/sys/net`, which Podman and Docker mount read-only. A containerised
agent logs a warning and forwards nothing, and from the other end that looks
like a dead route. A node that only serves its own ports, and never
forwards, runs fine in the container.

The coordinator URL must be `https://` (or `http://` to loopback): the join
token, the node's bearer token and the peer directory all travel over it,
and the directory decides which keys the node trusts. For a coordinator
reached only over a network you trust end to end, pass
`--allow-plaintext-http` to `install`/`join`; the node remembers the
choice.

Or, step by step, if you'd rather not have `install` touch systemd for you:

```sh
wireserve join
systemctl enable --now wireserve-agent
```

Run with no arguments like this, `join` prompts for the coordinator URL and
then the join token (masked, not echoed) — nothing to paste into the
command line at all, which is also the safer option: a token passed as an
argument lands in shell history and is visible to any local user via `ps`
for as long as the process is alive. Passing both explicitly still works
the same as before (`wireserve join <url> <token>`, or
`--join-token-file <path>`/`-` for scripted joins) if you'd rather not be
prompted. `join` generates the keypair locally, redeems the token, and
stores everything mode-600. The daemon brings the mesh up on `wireserve0`,
or the next free name if that one is taken; `wireserve status` shows
which.

## Using it without sudo

`install`, `join` and `daemon` need root. Everything else (`wireserve
<service>`, `status`, `transit`, `exit`, `leave`) only talks to the running
daemon over a Unix socket, and needs no root of its own: whoever can open
the socket can run them. By default that is root alone. If a group named
`wireserve` exists when the daemon starts, the daemon shares the socket with
it, and its members can run those commands as themselves:

```sh
sudo usermod -aG wireserve $USER   # then log out and back in
wireserve status
```

`install` creates the group for you and prints that line; without
`install`, `sudo groupadd --system wireserve` before starting the daemon.
The group is looked up once, when the daemon binds its socket, so a daemon
that was already running needs `sudo systemctl restart wireserve-agent`
to pick it up. Someone who is not allowed in is told so, rather than that
the daemon isn't running. `WIRESERVE_SOCKET_GROUP` in
`/etc/wireserve/agent.env` names a different group, and an empty value keeps
the socket root-only even though the group exists.

Treat membership as "operator of this node", the way you would the `docker`
group. A member can publish and withdraw services, opt the node in or out
of transit and exit duty, and `leave` the mesh. What a member cannot do is
get past the coordinator: a new service, a transit carrier or an exit still
needs an admin's approval there, and members cannot read the node's keys
or bearer token, which stay in a root-only state file. Only add people you
would trust to run that node.

A containerised agent does not see the host's groups, so its socket stays
root-only (`podman exec`/`docker exec` runs as root anyway).

## Upgrading a node

Download the new version on the node and run its `install`, without a
URL:

```sh
VERSION=1.0.0-beta.1
curl -fL https://github.com/tiaforge/wireserve/releases/download/v$VERSION/wireserve-$VERSION-$(uname -m)-linux.tar.gz | tar xz
sudo ./wireserve-$VERSION-$(uname -m)-linux/wireserve install
```

A binary built from source upgrades the same way: copy it over and run
its `install`.

On a node that has already joined, `install` given no URL or token is an
upgrade, not a join: it installs the binary, rewrites the systemd unit files
(the default unit, and the `@` template if one is on disk), reloads systemd,
and restarts every running `wireserve-agent*` unit, so no agent keeps running
the old binary. The node keeps its identity and its declared services; the
mesh drops out for the few seconds the daemon takes to restart, and its
firewall is rebuilt deny-first as on any start. Pass a URL or a token and it
joins again. Upgrade the coordinator first, the same way:
its new archive's `sudo ./wireserve-coordinator install` on its host. It matters: an agent
learns from the coordinator who may reach its services, and opens none of
them until a coordinator that says so answers.


## Several agents on one host

One host can be a node in several meshes (or hold several identities in
one) by running one agent *instance* per mesh. The plain unit runs the
default instance; name the others:

```sh
sudo wireserve install https://wireserve.example.com --instance work
wireserve --instance work git 3000     # no sudo needed once you are in the group
wireserve --instance work status
```

Or, by hand:

```sh
sudo wireserve --instance work join          # prompts, as above
sudo systemctl enable --now wireserve-agent@work   # deploy/systemd/wireserve-agent@.service
```

(`WIRESERVE_INSTANCE=work` works in place of the flag.) Each instance is a
separate node with its own:

| | default instance | instance `work` |
|---|---|---|
| state and keys | `/var/lib/wireserve/` | `/var/lib/wireserve/instances/work/` |
| socket | `/run/wireserve/agent.sock` | `/run/wireserve-work/agent.sock` |
| interface | first free `wireserve<N>` | next free `wireserve<N>` |
| listen port | first free from 51820 | next free from 51820 |
| nftables | `inet wireserve.<if>`, `inet wireserve-interop.<if>` | same, for its interface |
| hosts file | `# BEGIN WIRESERVE` block | `# BEGIN WIRESERVE work` block |

Each instance's socket is shared with the `wireserve` group separately, by
that instance's own daemon, so one group covers all of them.

Instances leave each other alone: each keeps, rewrites and removes only
its own table, hosts block and host-firewall rules. Another instance's
rules are left in place while it runs; if it dies without cleaning up,
whichever instance runs next removes them. An instance can't be run twice,
and `join` refuses while that instance's daemon is up. Interface names and
listen ports stored by an instance stay reserved for it even while it's
stopped.

Give the meshes' coordinators non-overlapping address ranges; the daemon
refuses to start if its own mesh address is already on another interface.

Running `deploy/e2e/run-multi-instance-test.sh` (after
`cargo build --workspace`) exercises all of this end to end in a throwaway
unprivileged namespace — no root and no containers needed.

The agent adds one route per peer address on its interface and nothing
else — no routes to peers' endpoints, so hosts without a default route
work too. Versions before this let the WireGuard library pin a route to
every peer endpoint via the default gateway; those stay until the link
goes down or the host reboots, and are harmless while the gateway doesn't
change (`ip route` lists them as `<endpoint-ip> via <gateway>`).
