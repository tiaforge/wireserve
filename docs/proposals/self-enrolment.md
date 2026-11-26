# Proposal: nodes that join by signing in

Status: **proposal** — kept so the idea and its threat model are not lost; not
scheduled in [PLAN.md](../PLAN.md).

Today a node joins with a join token, and only an admin makes join tokens
(`wireserve-admin node create`, `node rejoin`). This proposes a second way in,
opt-in per rule: an admin allows an `oidc:` group to enrol, and anyone in it
adds their own machine by signing in at the login server the coordinator
already uses — `wireserve install https://wireserve.example.com --sign-in`,
with no admin in the loop.

## What it changes

Being on the mesh stops meaning *an admin handed this machine a token* and
starts meaning *someone the login server says is in group X approved this
machine*. The login server goes from deciding what people reach to deciding
whose machines are on the mesh at all: it is then only as strong as its
accounts (MFA, password policy) and as the way people get into the group — some
providers can be set up to let users add themselves to groups, which would make
enrolment open to every account.

That matters because of what any joined node gets ([Security](../security.md)):
it sees the whole directory, it counts as `everyone` (and a fresh mesh grants
`everyone → default`), it may declare services, and it reports addresses its
peers send handshakes to. Unless the design says otherwise, "every member may
enrol" means "every member's machine gets everything `everyone` gets".

### The claim-link rule

[Device owners](../access-control.md#devices-that-belong-to-someone) can only
be claimed through a link an admin makes, because "a node handing its own
around could collect other people's groups". A device-code style "open this
URL and sign in" flow brings exactly that back: someone starts an enrolment on
their own machine, sends the link or code to a colleague ("can you approve
this?"), the colleague signs in, and the attacker's machine is on the mesh,
owned by the colleague, with the colleague's groups. This is the known weakness
of device-code flows, and the design has to answer it.

## Design

1. **Off unless a rule says so.** For example
   `wireserve-admin enroll allow oidc:wireserve [--tag servers] [--max-per-user 5] [--approve]`.
   The group is one at the login server — not the local `wireserve` Unix group
   on each node, which administers that node's network
   ([Security](../security.md)); the docs should say so and the examples should
   use another name.
2. **A self-enrolled node belongs to whoever enrolled it.** It reaches what
   their groups reach — what they could reach by signing in anyway — plus the
   rule's tags. Whether `everyone` covers self-enrolled nodes is the admin's
   choice, and the default is no: without this, the feature widens access.
3. **Its life follows the person's**, in three states (below). An outage never
   removes anything; only a clear answer from the login server does.
4. **The flow resists phishing.**
   - Desktops: a loopback redirect (RFC 8252) — the agent opens the browser on
     the same machine, so the sign-in is tied to it.
   - Headless machines: the person types the code the agent prints into a page
     on the coordinator, rather than following a link with the code in it.
   - The confirmation page ("add `laptop` to the mesh as yours?") shows the
     key's fingerprint, the hostname, and the address the enrolment came from
     beside the browser's own, with a plain warning when they differ.
   - A code works once, for about ten minutes.
5. **Starting an enrolment costs nothing.** The start endpoint needs no
   credential, so it allocates no node row and no address until someone
   confirms; pending enrolments are capped and rate-limited like `/register`,
   and `--max-per-user` keeps one person from draining the address pool.
6. **Names are checked as service names are**: reserved names, the
   coordinator's own and names already taken are refused.
7. **`--approve`** makes the sign-in prove who is asking and then hold the node
   for `wireserve-admin node approve`, as declared services wait for
   approval today — for meshes that want both.
8. **Every enrolment is logged**: who, which node, from where.

Most of it exists: the OIDC client with PKCE, sealed refresh tokens, the
periodic group refresh, and the claim confirmation page. What is new is the
enrolment flow and the lifecycle in point 3.

## When the login server stops answering, or says no

A node's place on the mesh rests on its WireGuard key and bearer token, which
do not expire on their own. The OIDC token only proves the owner's groups, and
those decide what the node may **reach**. Who may reach **into** the node — its
SSH, say — is decided by the grants on the services it declares, which name the
caller's groups and tags, not the owner's. So losing the owner's groups must
never mean losing the machine: a headless server whose SSH listens only on the
mesh stays reachable from the owner's laptop, which is signed in on its own.

| State | Cause | What the node reaches | Reachable by others | Recovery |
| --- | --- | --- | --- | --- |
| stale | login server unreachable, or the token key does not open the sealed token | its groups for an hour, then tags and (if the rule allows) `everyone` only | yes | on its own, at the first refresh that works |
| needs sign-in | the login server refuses the refresh token (`invalid_grant`) | tags and (if the rule allows) `everyone` only | yes | the same person signs in again, from any browser |
| revoked | a refresh that works shows the person left the enrolment group; or *needs sign-in* for longer than the rule allows | nothing — dropped as a peer | no | an admin, or a new enrolment |

**Stale** is what owners already get today (`owners::STALE_AFTER` in
`crates/wireserve-coordinator/src/db/owners.rs`): every refresh tries again,
and the first one that works brings the groups back with nothing to do by hand.
One addition: retry stale owners with a backoff (30 seconds, growing to
`WIRESERVE_OIDC_REFRESH_SECS`) instead of only on the normal cycle, so a node
is back within a minute or so of the login server returning, not up to fifteen.

**Needs sign-in** is separate from revoked because a refusal does not always
mean the person was removed: Keycloak and others also answer `invalid_grant`
when a token reaches a maximum lifetime, for someone still in good standing.
Revoking there would make them enrol again from scratch, and could leave a
remote machine out of reach for nothing. Today a refused token simply makes a
device nobody's; for a self-enrolled node it becomes this state instead.

### Signing in again without the machine

The coordinator is the OIDC client and holds the token, so the node itself
takes no part in signing in again:

- **A "your devices" page on the coordinator**: sign in from any browser,
  see "`homeserver` needs you to sign in again", and bind it back. Only the
  same subject (`sub`) that owned the node may — so this cannot hand anyone's
  groups to someone else's node, and the claim-link rule holds.
- **The admin's way already exists**: `wireserve-admin owner link homeserver`.
- **It is visible before it matters**: `wireserve status` on the owner's other
  devices and `wireserve-admin owner status` list nodes that need a sign-in.

### Not hitting it at all

- The coordinator refreshes every `WIRESERVE_OIDC_REFRESH_SECS` (15 minutes by
  default), which keeps any idle timeout from running out; only a maximum
  lifetime can end the token. Keycloak's *Offline Session Max Limited* is off by
  default, so `offline_access` tokens there do not expire unless someone turns
  it on. [Identity providers](../identity-providers.md) should say this per
  provider.
- **Tag the servers that matter** (`--tag servers` on the rule, or `tag add`
  afterwards). A grant to a tag depends on nobody's token, so no identity
  problem changes what the machine reaches; its owner then records who enrolled
  it and decides when it is revoked.

## Open questions

- Does a self-enrolled node keep `everyone` while *needs sign-in*, when the rule
  gave it `everyone`? The table says yes; a stricter rule option could say no.
- How long may a node stay *needs sign-in* before it is revoked — a rule
  setting with a default (30 days?), or never without an admin?
- Should *revoked* keep the node's row and address for a while, so an admin can
  bring it back with `node rejoin` rather than a fresh enrolment?
- Windows: the loopback redirect needs a browser in the interactive session,
  while `install` runs elevated; the typed code may be the only way there.
