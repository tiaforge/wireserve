# Relaying between nodes

Two nodes each behind their own hard (symmetric) NAT — no shared LAN,
nothing port-forwarded to either — can end up with no direct path at all:
a symmetric NAT maps a different external port per destination, so
whatever wireserve's own NAT-traversal already learned for one peer is
useless for reaching a different one. When that happens, a third node
that already reaches both **relays** their connection: the two run their
own WireGuard session with each other, end to end, and the carrier only
forwards its encrypted UDP. It never holds the session's keys, so it can
neither read what passes through nor send anything as either end. No
separate relay server, no new protocol, and the coordinator never sees
the traffic.

This runs on a second WireGuard interface on every node, the **carry
interface** (`wireserve0-t` next to `wireserve0`), with the same key, no
address of its own and a port the kernel picks once and the node keeps.
Nothing needs opening for it: relayed sessions arrive through the mesh,
and wireserve's own firewall and its handling of ufw and firewalld cover
it the way they cover the mesh interface.

**When the relay takes over.** Agents keep each other alive every 10
seconds, so a direct path that dies goes quiet. After 30 seconds without a
single packet from the peer, checked every 5 seconds, the node asks for a
relay at once, and the relay is usually up within the next poll, about a
minute after the path died. The node goes on trying the direct path
underneath, and the first direct handshake ends the relay again.

**A node carries traffic only with two approvals, and has neither by
default.** Its own operator opts in, so a node with a data cap, say, is
never used; and the mesh admin approves it as a carrier:

```sh
wireserve transit on   # on the node: willing to carry traffic for others
wireserve transit off  # stop — takes effect on the next poll, no rejoin

wireserve-admin transit approve homeserver   # on the admin side: trusted to
wireserve-admin transit deny homeserver      # withdraw it again
```

A carrier cannot read or forge a relayed session, but it still sees who
talks to whom, when and how much, and it can drop the traffic. What a node
says about itself (that it is willing, which peers it reaches) cannot be
verified, so without approval a single compromised node could offer to
carry every pair in the mesh and learn all of that. Until it is approved,
`wireserve status` on that node says `Transit: on, waiting for an admin to
approve this node as a carrier`. Revoking or rejoining a node withdraws
its approval, and `node list` shows who currently has one in its TRANSIT
column: `on` when the node has switched it on too, `approved` when it has
not, `unapproved` for a node that offers without approval.

`wireserve status` shows the outcome, both for a peer this node can't
reach directly and for what this node is relaying on others' behalf:

```
PEER    ADDRESS   ENDPOINT  HANDSHAKE  ROUTE
laptop  10.1.0.5  -         never      relayed by homeserver

Transit: on
  relaying (end to end, unreadable here): laptop <-> desktop
```

`direct` is the ordinary case; `relayed by <name>` means this node is one
end of a pair relayed by a carrier. Only a single hop is ever used — the
carrier must already, currently reach both ends itself — and the two ends
keep trying their direct candidates the whole time, moving off the relay
as soon as one answers. Relaying needs all three nodes on this version;
with an older one among them the pair simply stays unreachable, never
falling back to forwarding in the clear.

Each node has a **relay port**, `41000` plus a number the coordinator
assigns it for life (`WIRESERVE_RELAY_PORT_BASE` moves the range). A
carrier receives a node's relayed packets on that port of its mesh
address, inside the tunnel, so for relaying between agents nothing is
ever opened on the internet.
