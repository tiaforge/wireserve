# Identity providers

Two things in wireserve use a login server you run, and both are optional:

- **Device owners** — a device belongs to a person, and reaches what their
  groups are granted ([how it works](access-control.md#devices-that-belong-to-someone)).
  The coordinator is an OpenID Connect client of your login server.
  `sudo wireserve-coordinator setup owners` sets it up.
- **The sign-in** — people sharing one computer sign in to web services
  ([how it works](access-control.md#signing-in-for-shared-devices)).
  A forward_auth provider, run as one of your services, asks your login
  server. `sudo wireserve-coordinator setup sign-in` sets it up.

Use the same login server for both, so a group means the same on each path.
Below, `https://mesh.example.com` is your coordinator's web address
(`WIRESERVE_PUBLIC_URL`) and `int.example.com` your service domain.

What every login server needs for device owners:

| | |
| --- | --- |
| Client type | confidential: it has a client secret |
| Redirect URL | `https://mesh.example.com/claim/callback`, exactly |
| Scopes | `openid`, and `offline_access` — without a refresh token the coordinator cannot keep anyone's groups current, and claiming fails |
| Groups | a claim listing the person's groups, `groups` unless you say otherwise, in the ID token or the userinfo answer |

`setup owners` checks the server's discovery document before saving, stores
the issuer exactly as the server spells it, and asks only for the scopes the
server lists. An owner's e-mail is kept only when the ID token marks it
verified. `wireserve-admin owner status` checks it all again later.

## Pocket ID

**Device owners.** In Pocket ID's admin area, under *OIDC Clients*, add a
client:

1. Name it `wireserve`, and add the callback URL
   `https://mesh.example.com/claim/callback`.
2. Leave it a confidential client (not *public*); copy the client ID and the
   client secret it shows.
3. Optionally, limit it to the user groups whose devices may be claimed.

Groups are Pocket ID's *user groups*, listed in the `groups` claim; Pocket ID
lists `offline_access` and `groups` among its scopes, so nothing else needs
switching on. The issuer is Pocket ID's own address:

```sh
sudo wireserve-coordinator setup owners
# Issuer URL: https://id.example.com
```

**The sign-in.** Pocket ID has no forward_auth of its own; run
[authward](https://git.tia.sh/tia/authward) as an OpenID Connect client of
Pocket ID (a second OIDC client, with authward's own callback URL), publish
it on 443, and pick `authward`:

```sh
wireserve auth 443:8080                                # on the node running authward
sudo wireserve-coordinator setup sign-in               # on the coordinator: authward, auth, <that node>
```

## Authentik

**Device owners.** Under *Applications → Providers*, create an *OAuth2/OpenID
Provider*:

1. Client type *Confidential*; copy the client ID and secret.
2. Redirect URIs: *Strict*, `https://mesh.example.com/claim/callback`.
3. Under *Advanced protocol settings → Scopes*, add the `offline_access`
   mapping (*authentik default OAuth Mapping: OpenID 'offline_access'*) to the
   selected ones.

Then create an *Application* for it, with a slug such as `wireserve`. Groups
come in the `profile` scope, as the `groups` claim — Authentik has no
`groups` scope, so `setup owners` leaves it out. The issuer is the
application's, with its trailing slash:

```sh
sudo wireserve-coordinator setup owners
# Issuer URL: https://authentik.example.com/application/o/wireserve/
```

**The sign-in.** Authentik's embedded outpost speaks forward_auth itself:

1. Publish Authentik on 443 as the sign-in service, from the node running
   it: `wireserve auth 443:9000`. Its pages are then
   `https://auth.int.example.com`.
2. Create a *Proxy Provider* in *Forward auth (domain level)* mode, with
   authentication URL `https://auth.int.example.com` and cookie domain
   `int.example.com`. Note its client ID.
3. Create an *Application* for it, and add the application to the
   *authentik Embedded Outpost*.
4. On the coordinator, pick `authentik`, and give it that client ID — the
   outpost's session cookie is named after it:

   ```sh
   sudo wireserve-coordinator setup sign-in
   # Which sign-in service do you run? authentik
   ```

The preset asks the outpost's Caddy endpoint and splits Authentik's groups
on `|`. Authentik can bind a session to the network it was made from (the
*User Login* stage's session binding), which keeps one service's owner from
replaying a visitor's session at another.

## Keycloak

**Device owners.** In your realm:

1. *Clients → Create client*: OpenID Connect, client ID `wireserve`. Turn
   *Client authentication* on, keep *Standard flow*, and set *Valid redirect
   URIs* to `https://mesh.example.com/claim/callback`. Copy the secret from
   the *Credentials* tab.
2. Keycloak puts no groups in a token by itself. *Client scopes → Create
   client scope* named `groups` (OpenID Connect), then in its *Mappers*, *By
   configuration → Group Membership*: token claim name `groups`, *Full group
   path* off, added to the ID token and userinfo.
3. In the `wireserve` client's *Client scopes*, add `groups` as a default
   scope. `offline_access` is there already as an optional one; people need
   the `offline_access` realm role, which Keycloak's default roles include.

Keycloak refuses a scope it doesn't know, which is why `setup owners` asks
only for the ones the realm lists — create the `groups` scope first. The
issuer is the realm's:

```sh
sudo wireserve-coordinator setup owners
# Issuer URL: https://keycloak.example.com/realms/home
```

**The sign-in.** Keycloak has no forward_auth of its own; run
[authward](https://git.tia.sh/tia/authward) as a second client of the realm,
as for Pocket ID above, and pick `authward`.

## Authelia and others

`setup sign-in` also knows Authelia's forward_auth (`/api/authz/forward-auth`,
the `Remote-*` headers, cookie `authelia_session`). Authelia's documentation
describes no binding of a session to the device it was made on, so whoever
runs a service under your domain could replay a visitor's session at another;
approve services only for nodes you trust.

Any other forward_auth provider works if it answers like Caddy's
`forward_auth` expects: a 2xx naming the user in a header for someone signed
in, and for anyone else either a redirect to its login page or a 401 carrying
the login page in `X-Login-Url`. Pick `other` and give its verify path,
session cookie, identity headers and group separator, as its Caddy
documentation names them.

The Authentik and Authelia presets were checked against their source code
(`src/outpost/proxy` and `internal/handlers` respectively); neither has run
end to end against wireserve yet.
