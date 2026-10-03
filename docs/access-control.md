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
Keycloak, … — the same one your sign-in uses), access can follow the
*person* instead: a device belongs to someone, and reaches what their groups
are granted — no browser sign-in on the service, for SSH or a database as
much as for a web page. Anna's laptop and phone both get what Anna is
allowed, and when she leaves `family` at the login server, both lose it.

On the coordinator:

```sh
sudo wireserve-coordinator setup owners
```

It shows the redirect URL to register — `<public url>/claim/callback` —
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

`wireserve-admin owner status` then says whether the login server answers,
which `oidc:` groups grants name, and whose devices are whose — and what to
do next where something is missing.

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
people apart by a sign-in. It is built into every node's terminator and
speaks `forward_auth`, so any provider for that works; the defaults are
[authward](https://git.tia.sh/tia/authward)'s.

Run the provider as a mesh service on 443 — its login pages are then
`https://auth.int.example.com` — and name it, and the node running it, on
the coordinator:

```sh
wireserve auth 443:8080                       # on the node running authward
sudo wireserve-coordinator setup sign-in      # on the coordinator
```

`setup sign-in` needs [a domain with DNS records](names-and-https.md) first.
It asks which provider you run and fills in its names for things:

| Provider | Verify path | Session cookie | Identity headers | Groups split on |
| --- | --- | --- | --- | --- |
| authward (the defaults) | `/verify` | `authward_session` | `X-Auth-User`, `-Email`, `-Groups` | `,` |
| Authentik, embedded outpost | `/outpost.goauthentik.io/auth/caddy` | `authentik_proxy_` + 8 hex digits of the proxy provider's client ID's SHA-256 — asked for the ID, worked out | `X-Authentik-Username`, `-Email`, `-Groups` | `\|` |
| Authelia | `/api/authz/forward-auth` | `authelia_session` | `Remote-User`, `-Email`, `-Groups` | `,` |

"other" asks for each. It writes, leaving authward's defaults out:

```sh
WIRESERVE_AUTH_SERVICE=auth
WIRESERVE_AUTH_NODE=gate                  # the node that runs it
WIRESERVE_AUTH_VERIFY_PATH=/verify
WIRESERVE_AUTH_SESSION_COOKIE=authward_session
WIRESERVE_AUTH_USER_HEADER=X-Auth-User
WIRESERVE_AUTH_EMAIL_HEADER=X-Auth-Email
WIRESERVE_AUTH_GROUPS_HEADER=X-Auth-Groups
WIRESERVE_AUTH_GROUPS_SEPARATOR=,         # or |
```

Only the configured separator splits: with `,`, a group called `x|admins` is
one group, never `admins`. A node older than the setting splits on `,`, which
leaves Authentik's `a|b` one group no grant names — nobody gets in by it.

Then grant a group at your identity provider:

```sh
wireserve-admin grant add oidc:family media
```

A request to a service in `media`, served with TLS by its node, then goes:

1. from a device a grant names — its own node, a tagged one: straight through,
   the sign-in never asked;
2. from any other device: headers only, to `https://auth.<domain>/verify`,
   over verified TLS on the provider's own address, with `X-Forwarded-Method`,
   `X-Forwarded-Uri`, the service's own name in `X-Forwarded-Host` (a
   request naming any other host is refused with 421 before it gets that
   far) and the calling device's mesh address as the one `X-Forwarded-For`
   value, which a provider can bind a session to: the provider's cookie is
   scoped to the whole domain, so without that anyone hosting a service could
   replay a visitor's session elsewhere. Not signed in: a 401 with `X-Login-Url` sends the
   browser to sign in. Signed in: the provider says who, and the terminator
   decides — one of the granted groups in `X-Auth-Groups` lets it through with
   the provider's identity headers, anything else gets 403. The provider only
   authenticates; which groups get in is the grants' business.

A provider that says its answer holds (`Cache-Control: max-age=…` and a `Vary`
naming the cookie, as authward does) is not asked again for the same cookie
until it expires, and with `stale-if-error` a signed-in browser keeps working
through a short outage of the provider. Nothing is kept for a provider that
says nothing.

So the sign-in is never a per-service switch: a restricted service offers it
exactly when a grant names an `oidc:` group, and a service in `default` never
asks. While it does, the service's terminated 443 is open to every node — the
terminator decides — and its other ports stay with the grants, so nobody
walks round the sign-in by dialling another one.

The provider is trusted **only on `WIRESERVE_AUTH_NODE`**: every request
behind the sign-in goes to it, cookies included, and it says who is signed
in, so the same service name declared by any other node is ignored, and
nobody gets in by signing in until the named node serves it again. Without
`WIRESERVE_AUTH_NODE` the sign-in is off, with a warning at startup. The
provider's own service stays open to every node and cannot be put in a group:
every terminator and every browser signing in has to reach it.

**Bind sessions to the device, or approving a service means trusting its owner
with everyone's sessions.** The provider's cookie is scoped to the whole
domain, so the browser sends it to every service, and whoever runs a service
under the domain can read it there and replay it at another. wireserve can only
tell the provider which device is asking: every terminator sends the calling
device's mesh address as the one `X-Forwarded-For` value on the check (and the
provider's own terminator hands it on unchanged), and a provider that binds a
session to the address it was created from then refuses the replay. authward
does, with `bind_session_to_client_ip` (on by default). authentik does too
(the *User Login* stage's session binding, to the network, or the exact IP).
Authelia and oauth2-proxy use the client address for their own access rules,
but their documentation describes no session binding: behind them the
exposure stays, and the answer is to be careful which nodes you approve
services for. Sessions created before a provider starts binding stay unbound
until they expire, and a browser on a node that hosts services looks like that
node, not like a different device.

Worth knowing:

- **Only HTTP can tell people apart.** Two people on one laptop send the same
  packets; for SSH, SMB or a database the grant is the device's, and the
  service does its own login. Tag the shared device for what everyone on it
  may use.
- **Native apps can't do a browser sign-in.** The Jellyfin, Immich and Home
  Assistant apps, or anything speaking CalDAV/CardDAV, fail behind it — grant
  their devices instead, or use authward's API tokens and `bypass_paths`.
- **No carrier speaks for anyone.** A relayed session — between two agents,
  or a phone and a node — is end to end; the carrier forwards packets it can
  neither read nor forge, so a grant to a relayed peer trusts that peer and
  nobody else. An exit reads what it sends on to the internet, and nothing
  of the mesh.
- **Close the owner's LAN yourself.** The mesh admits only the grants; a
  backend listening on every interface is still reachable from its own
  network. Bind it to the node's mesh address.
- **Identity headers and the session cookie never reach a backend from a
  client.** Every terminator removes the identity headers from every request,
  on every service, and the provider's session cookie from every request but
  the provider's own — the cookie is scoped to the whole domain, so the
  browser sends it to every service. So do the headers a proxy or an
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
  and programs that aren't browsers are unaffected, and so is the sign-in
  provider's own service. Through a forwarding node, the public name it was
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
