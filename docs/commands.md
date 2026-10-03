# Command reference

On a node, talking to the local daemon over a Unix socket. `install`, `join`
and `daemon` need root; the others need only access to the socket, which
members of the `wireserve` group have (see [Using it without sudo](nodes.md#using-it-without-sudo)):

| Command | What it does |
| --- | --- |
| `wireserve install [url] [--instance name]` | installs the binary + systemd unit, then joins — one command, needs root. On a node that already joined, with no URL or token: upgrades and restarts the agents instead |
| `wireserve join [url] [token]` | one-time bootstrap, generates the keypair — prompts for either if omitted |
| `wireserve <name> <[public:][address:]target[/tcp\|/udp]>... [--group <g>]` | publish a service on its own address — on this node, or on an address it reaches; a new one in group `g` |
| `wireserve <name> off` | withdraw one |
| `wireserve transit on\|off` | opt in/out of relaying for two other nodes that can't reach each other directly (also needs `transit approve`) |
| `wireserve exit on\|off` | opt in/out of sending the internet traffic of devices exported with `--exit` through this node (also needs `transit on` and approval) |
| `wireserve status [--json]` | services (name, address, ports, owner, state, whether this node may reach it), peers (with each one's route — direct or via a carrier) and anything not published, from the last poll |
| `wireserve leave` | tear down interface, firewall, hosts block |

On the coordinator host, as root:

| Command | What it does |
| --- | --- |
| `wireserve-coordinator install` | asks a few questions, then installs both binaries, the `wireserve-coordinator` user and the unit, and starts it. On a host where it is installed: upgrades and restarts instead |
| `wireserve-coordinator install --reconfigure` | asks again, with the current settings as defaults |

Against the admin port (loopback-only by default; run from the coordinator
host, or point `--coordinator-url`/`WIRESERVE_COORDINATOR_URL` at it from
anywhere that can reach it):

| Command | What it does |
| --- | --- |
| `wireserve-admin node create <name>` | create a node, print a join token |
| `wireserve-admin device create <name> [--exit [node]] [--dns <svc\|ip>] [--mesh-dns] [--allow-unverified] [--out <file>] [--qr]` | create a device (an agent-less static peer, such as a phone) and write its `.conf`: every node end to end, directly or through a carrier's relay port; `--exit` adds a full-tunnel profile, `--mesh-dns` names the resolver in the mesh profile too |
| `wireserve-admin device refresh <name> [same flags]` | re-issue a device's `.conf` under a new key, same name and address; the old key stops working at once |
| `wireserve-admin node list` | the full directory, with each agent's `dialable=` and each device's `stale=` and `holds=` |
| `wireserve-admin transit ports` | every public relay port phones use: where it must be open, which node and devices, whether it was open, which may be closed |
| `wireserve-admin node revoke <name>` | cut a node off, keep its name reserved |
| `wireserve-admin node rejoin <name>` | fresh join token, same name and address; the old key stops working at once |
| `wireserve-admin node delete <name>` | remove the record, free the name |
| `wireserve-admin node clear-endpoint <name>` | drop a stale advertised endpoint |
| `wireserve-admin service list [--pending]` | declared services and their approval state |
| `wireserve-admin service approve <svc> --node <node>` | let a declaration reach the mesh |
| `wireserve-admin group create\|delete\|list` | service groups; a service in none is in `default` |
| `wireserve-admin group add\|remove <group> <svc>` | put a service in a group, or take it out |
| `wireserve-admin grant add\|remove <source> <group>`, `grant list` | let `everyone`, `tag:<tag>` or `oidc:<group>` reach a group |
| `wireserve-admin tag add\|remove <node> <tag>` | tag a node, for grants to name |
| `wireserve-admin tag list [<tag>]` | every tag in use and the nodes carrying it (`node list` shows `tags=` per node too) |
| `wireserve-admin service access <svc>` / `node access <node>` | who reaches a service and why, or what a node reaches |
| `wireserve-admin owner link <node> [--qr]` | a single-use link for whoever the device belongs to |
| `wireserve-admin owner clear <node>` | the device belongs to nobody again |
| `wireserve-admin service deny <svc> --node <node>` | refuse one, or withdraw an approval |
| `wireserve-admin transit approve <name>` | let a node that opted in relay for others, and be an exit |
| `wireserve-admin transit deny <name>` | withdraw that |
