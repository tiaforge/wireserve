# Who can reach what

Every service is in one or more **service groups**, and a **grant** lets a
source reach every service in a group. A source is `everyone` (every node),
`tag:<tag>` (nodes you tagged: servers, shared devices) or `oidc:<group>`
(people in that group at your identity provider, who prove it by signing
in). A service in no group is in the built-in `default` group, and a fresh
mesh grants `default` to `everyone` — which is why, until you set anything
up, every service is reachable from every node, as it always was.

```sh
wireserve-admin group create infra
wireserve-admin group add infra grafana        # out of default, into infra
wireserve-admin tag add ci-runner ops
wireserve-admin tag list                       # each tag in use and its nodes
wireserve-admin grant add tag:ops infra        # the ci-runner reaches grafana
wireserve-admin service access grafana                 # who reaches it, and why
wireserve-admin node access ci-runner        # what a node reaches
wireserve-admin group list
wireserve-admin grant list
```

Only you change groups, grants and tags. A node declaring a service may name
an existing group once, so a new service never appears in `default` even with
approval off:

```sh
wireserve vault 8200 --group infra
```

That applies to a service that has no group yet, and only when it is
approved; after that its groups are yours, and a declaration naming another
one changes nothing and says so in `wireserve status`. A declaration naming a
group that does not exist is not published at all. Groups belong to the
service **name**: they survive the service being withdrawn and declared again,
and a name can be put in a group before anything declares it. `group delete`
is refused while a group holds services, has grants, or a declaration is
waiting to join it — its services would fall back into `default`.

Each service's own node enforces it, for every protocol: its firewall lets
only the granted nodes' addresses in, and cuts a connection whose grant was
taken away at its next packet. Changes reach it within a poll and a
terminator check-in (seconds). Removing the `everyone → default` grant
turns the whole mesh deny-by-default; `access` says when it is gone.

Every node still sees every published service, so a name you aren't granted
is something to ask for, not a mystery. The ACCESS column of `wireserve
status` says what this node gets at each one: `yes` (every port), `sign-in`
(only its HTTPS, and only for someone who signs in with a granted group) or
`no`. It is the answer the service's own node enforces, worked out by the
coordinator on each poll. `-` means the coordinator is too old to say.

## Devices that belong to someone

Without anything set up, access goes by the *device*: what its tags allow, or
what every device gets. With a login server you run (Pocket ID, Authentik,
Keycloak, … — the same one the sign-in uses), access can follow the
*person* instead: a device belongs to someone, and reaches what their groups
are granted — no browser sign-in on the service, for SSH or a database as
much as for a web page. Anna's laptop and phone both get what Anna is
allowed, and when she leaves `family` at the login server, both lose it.

On the coordinator:

```sh
sudo wireserve-coordinator setup login
```

It shows the redirect URL to register — `<public url>/oidc/callback` —
asks for the issuer, client ID and secret, and checks the login server's
discovery document before saving: the issuer is stored exactly as the
server spells it, and the scopes are narrowed to the ones it lists.
[Identity providers](identity-providers.md) has step-by-step recipes for
Pocket ID, Authentik and Keycloak. It writes:

```sh
WIRESERVE_OIDC_ISSUER=https://id.example.com
WIRESERVE_OIDC_CLIENT_ID=wireserve
WIRESERVE_OIDC_CLIENT_SECRET=…
# only when not the default
WIRESERVE_OIDC_SCOPES="openid email profile groups offline_access"
WIRESERVE_OIDC_GROUPS_CLAIM=groups
# never asked; 60..86400
WIRESERVE_OIDC_REFRESH_SECS=900
```

The same login server is [the sign-in](#signing-in-for-shared-devices), once
there is a domain with DNS records: one client registration for both.

`wireserve-admin owner status` then says whether the login server answers,
which `oidc:` groups grants name, whose devices are whose and who is signed
in — and what to do next where something is missing.

`node create` and `device create` then also print a **claim link** (with
`--qr`, as a code for the phone's camera), and `owner link <node>` makes a
fresh one:

```sh
wireserve-admin owner link laptop --qr
wireserve-admin grant add oidc:family media
wireserve-admin node access laptop      # whose it is, and what that gives it
wireserve-admin owner clear laptop
```

Opening the link sends the person to sign in, then asks "make `laptop`
yours?", naming its tags and its current owner; yes makes it theirs. A link
works once, for ten minutes, and **only you make them** — a node handing its
own around could collect other people's groups, so none can. Signing in is
optional: a device nobody claimed reaches what `everyone` and its tags reach,
as before.

An owner's e-mail is kept only when the provider marks it verified, and every
refresh takes it afresh from the provider's ID token. It reaches backends as
the owner's e-mail header, and one that knows people by e-mail would otherwise
take whoever typed your address into their profile for you.

The coordinator keeps each owner's refresh token, sealed with a key it
generated into `coordinator-secrets.env` (`WIRESERVE_OIDC_TOKEN_KEY`), and
fetches their groups again every `WIRESERVE_OIDC_REFRESH_SECS`: someone
removed from a group loses what it gave them within that. If the provider
refuses the token, the device belongs to nobody again; if the provider cannot
be reached, the groups keep counting for an hour, then not until it answers.
Revoking or rejoining a node clears its owner — the new identity may be
another device. A terminator lets a claimed device's backends know who it is
in the same `X-Auth-*` headers a sign-in fills (the user is the provider's
`sub`).

## Signing in, for shared devices

A grant to a tag or everyone is about the *device*. A laptop the whole family
uses is one device, though: for HTTP services the terminator can tell its
people apart by a sign-in, at the same login server
[device owners](#devices-that-belong-to-someone) use. The coordinator signs
people in itself — there is nothing else to run — and it is on whenever
there is a login server (`setup login`) and
[a domain with DNS records](names-and-https.md) (`setup domain`).

Grant a group at your identity provider:

```sh
wireserve-admin grant add oidc:family media
```

A request to a service in `media`, served with TLS by its node, then goes:

1. from a device a grant names — its own node, a tagged one, one whose owner
   is in `family`: straight through, nobody asked to sign in;
2. from any other device, with a session for this service: the terminator
   checks it on its own — a token the coordinator signed, made out to this
   service's name, not past its time — and one of the granted groups in it
   lets the request through, with who it is in `X-Auth-User`, `-Email` and
   `-Groups`; any other group gets 403;
3. from any other device without one: a browser is sent to the coordinator's
   `/sign-in`, which sends it on to the login server. Back from there, the
   coordinator lets only someone in one of the service's granted groups go
   on — anyone else gets a page saying the service is not for them, and the
   service learns nothing about them — with a ticket for that service alone,
   which the service's node redeems for the session, and only in the browser
   that set off the sign-in: a ticket opened anywhere else signs nobody in.
   A second service asks
   the login server nothing: the coordinator remembers the browser.
   Anything but a GET gets 401 instead, which a redirect would lose the body
   of.

So the sign-in is never a per-service switch: a restricted service offers it
exactly when a grant names an `oidc:` group, and a service in `default` never
asks. While it does, the service's terminated 443 is open to every node — the
terminator decides — and its other ports stay with the grants, so nobody
walks round the sign-in by dialling another one.

**A session is one service's.** Its cookie (`__Host-wireserve-session`)
belongs to that service's name alone: the browser never sends it to another
service under the same domain, a token made out to one service is refused at
every other, and the coordinator redeems and renews it only for the node that
serves it. Whoever runs a service sees its visitors' sessions — they see
everything else those visitors send it too — and can use them there, and
nowhere else. The cookie never reaches a backend.

**Groups stay current.** A session token is good until the person's groups
are due again — `WIRESERVE_OIDC_REFRESH_SECS`, as for device owners. Then
the service's node renews it through the coordinator, which asks the login
server with the person's refresh token, and the browser gets the new one
with its next answer; the person notices nothing. Someone removed from a
group loses what it gave them within that time. If the login server refuses
the refresh token — the person was disabled, or signed out everywhere there
— the session is over and the next page asks them to sign in. If it cannot be
reached, the groups keep counting for an hour.

**Signing out**: `https://<service>/.wireserve/sign-out` ends the session —
every service it was used at asks again at its next renewal — and the
coordinator forgets the browser too. `wireserve-admin owner sign-out
anna@example.com` signs a person out of every browser at once (their devices
stay theirs). A session nobody uses for 30 days is forgotten.

Worth knowing:

- **Only HTTP can tell people apart.** Two people on one laptop send the same
  packets; for SSH, SMB or a database the grant is the device's, and the
  service does its own login. Tag the shared device for what everyone on it
  may use.
- **Native apps can't do a browser sign-in.** The Jellyfin, Immich and Home
  Assistant apps, or anything speaking CalDAV/CardDAV, fail behind it — grant
  their devices instead, or let the device belong to its person.
- **No carrier speaks for anyone.** A relayed session — between two agents,
  or a phone and a node — is end to end; the carrier forwards packets it can
  neither read nor forge, so a grant to a relayed peer trusts that peer and
  nobody else. An exit reads what it sends on to the internet, and nothing
  of the mesh.
- **Close the owner's LAN yourself.** The mesh admits only the grants; a
  backend listening on every interface is still reachable from its own
  network. Bind it to the node's mesh address.
- **Identity headers and the session cookie never reach a backend from a
  client.** Every terminator removes the identity headers and the sign-in's
  session cookie from every request, on every service. So do the headers a proxy or an
  identity-aware front end sets and a backend may believe: every
  `X-Forwarded-*`, `X-Original-*`, `X-Auth-Request-*` and `X-WebAuth-*`,
  `Remote-User` and its kin, `X-Real-IP`, `True-Client-IP` and the like. A
  backend that trusts a header of its own naming adds it to
  `WIRESERVE_STRIP_HEADERS` on the coordinator.
- **A reverse proxy of your own can name its client.** A node listed in
  `WIRESERVE_FORWARDING_NODES` on the coordinator — a Caddy on a public host
  proxying into the mesh — keeps the last entry of its `X-Forwarded-For`
  (the client its proxy saw; the terminator appends the node's own address)
  and an `X-Forwarded-Host` that is one plain host name; every other
  caller's are still removed. Nothing about *who* is calling is ever kept,
  and such a node's owner is never named: it speaks for someone else.
- **Another site's page cannot act here as your device.** A terminator lets
  a device in by its grants and names its owner, and a browser sends whatever
  any page open on it asks for through the tunnel — no cookie, so no SameSite
  rule holds it back. So a POST, PUT or DELETE, or a WebSocket, that a page on
  another site started is refused with 403; another service under the same
  domain counts as another site, since a node's own 443 service is one of
  them. Following a link, reads (which the browser keeps from the other page)
  and programs that aren't browsers are unaffected. Through a forwarding node, the public name it was
  asked for counts as the service's own. A service that must take such requests — itself a
  sign-in client answered by form POST, say — goes in
  `WIRESERVE_CROSS_SITE_SERVICES` on the coordinator.
- **A node learns who owns a device only when that device calls it.** The
  identity headers name the owner of a calling device; the coordinator tells
  a node an owner's subject, e-mail and groups only for a device the node
  reports having seen. The first request from a device not seen in the last
  day may reach the backend unnamed, for a second or two.
- **A deleted node's address**, once given to a new node, keeps the old one's
  grants until the serving node's next poll.
