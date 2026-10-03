# Security

Every node holds a bearer token, and `wireserve-admin` approves the rest. What
that lets a node do, and what it does not:

| A node, once joined | |
| --- | --- |
| Sees | The whole directory: every node's name, mesh addresses, public endpoint and LAN address, and every approved service's name and ports (a service's LAN target address is left out). Do not join a machine that should not learn where the others are. |
| Reports, unchecked | Its own endpoint, LAN and reflexive addresses. The coordinator checks their form, not their truth, so a node can make its peers send WireGuard handshake packets to addresses it names — one small fixed packet per attempt, including to addresses on the peer's own LAN. It gains no access by it. |
| Declares services | Nothing is published without an admin's approval (the default), and only 16 may be waiting or denied at a time. A name is first come, first served; another node's name, the coordinator's own and `WIRESERVE_RESERVED_SERVICE_NAMES` cannot be taken. |
| Owns an approved service on 443 | A real certificate for the name, every request made to it and the cookies in them — including the sign-in provider's session cookie, which is why binding sessions to the device matters (see [Signing in](access-control.md#signing-in-for-shared-devices)). Approve such a service the way you would hand someone a login page. |
| Cannot | Carry other nodes' traffic (transit and exit each need an admin's approval and the node's own opt-in), change groups, grants, tags or owners, publish a DNS record the zone already holds, or be told who owns a device that has never called it. |

Two more things to know about a machine that runs an agent:

- **The `wireserve` group is not a convenience group.** Its members can
  publish a service pointed at any address the node reaches (which an admin's
  approval then publishes to the mesh), withdraw one, `leave`, and switch transit
  and exit on. Treat membership as administering the node's network; give it to
  the people who could `sudo` anyway.
- **Identity is the device's.** Whoever can send packets from a node — another
  local user, a container — acts with its grants and, if it is claimed, its
  owner's identity headers. On a machine several people use, tag the machine
  for what all of them may use, and leave the rest to each service's own login.

And on the coordinator: there is one database connection behind one lock, so
what a node does inside its allowance (`WIRESERVE_POLL_RATE_*`, the pending
limit, the challenge limit) still queues behind everyone else's. Rate-limit by
address at the reverse proxy too, and put `WIRESERVE_TRUSTED_PROXY` on it so the
address the limiter and the log see is the client's. A terminator closes
connections that say nothing, and caps each address at 128 and the node at
4096, but a client dripping a request body slowly holds one of its own 128 for
as long as the backend allows.

## When a machine is lost or compromised

```sh
podman exec wireserve-coordinator wireserve-admin node revoke homeserver
```

The node's token stops working immediately, and every other node drops it
as a peer on its own next poll, so removal across the mesh is bounded by
the poll interval rather than instant. `rejoin` issues a fresh join token
for the same name and address when the machine itself is still trusted
but its key may not be: the old key and token stop working at once, and
the node drops out of every other node's peer list until it registers
again under a new key. `node delete` frees the name entirely, and refuses
until the node is revoked.
