# Identity providers

A login server you run — Pocket ID, Authentik, Keycloak, … — lets access in
wireserve follow people instead of devices. It does two things, through one
client registration on the coordinator, so a group means the same on both:

- **Device owners** — a device belongs to a person, and reaches what their
  groups are granted ([how it works](access-control.md#devices-that-belong-to-someone)).
- **The sign-in** — people sharing one computer sign in to web services
  ([how it works](access-control.md#signing-in-for-shared-devices)). It needs
  [a domain with DNS records](names-and-https.md) too.

`sudo wireserve-coordinator setup login` sets it up. Below,
`https://mesh.example.com` is your coordinator's web address
(`WIRESERVE_PUBLIC_URL`).

What every login server needs:

| | |
| --- | --- |
| Client type | confidential: it has a client secret |
| Redirect URL | `https://mesh.example.com/oidc/callback`, exactly |
| Scopes | `openid`, and `offline_access` — without a refresh token the coordinator cannot keep anyone's groups current, and signing in fails |
| Groups | a claim listing the person's groups, `groups` unless you say otherwise, in the ID token or the userinfo answer |

`setup login` checks the server's discovery document before saving, stores
the issuer exactly as the server spells it, and asks only for the scopes the
server lists. A person's e-mail is kept only when the ID token marks it
verified. `wireserve-admin owner status` checks it all again later.

Nothing else runs anywhere: the coordinator signs people in itself, and each
service's node checks what it signed.

## Pocket ID

In Pocket ID's admin area, under *OIDC Clients*, add a client:

1. Name it `wireserve`, and add the callback URL
   `https://mesh.example.com/oidc/callback`.
2. Leave it a confidential client (not *public*); copy the client ID and the
   client secret it shows.
3. Optionally, limit it to the user groups who may use the mesh.

Groups are Pocket ID's *user groups*, listed in the `groups` claim; Pocket ID
lists `offline_access` and `groups` among its scopes, so nothing else needs
switching on. The issuer is Pocket ID's own address:

```sh
sudo wireserve-coordinator setup login
# Issuer URL: https://id.example.com
```

## Authentik

Under *Applications → Providers*, create an *OAuth2/OpenID Provider*:

1. Client type *Confidential*; copy the client ID and secret.
2. Redirect URIs: *Strict*, `https://mesh.example.com/oidc/callback`.
3. Under *Advanced protocol settings → Scopes*, add the `offline_access`
   mapping (*authentik default OAuth Mapping: OpenID 'offline_access'*) to the
   selected ones.

Then create an *Application* for it, with a slug such as `wireserve`. Groups
come in the `profile` scope, as the `groups` claim — Authentik has no
`groups` scope, so `setup login` leaves it out. The issuer is the
application's, with its trailing slash:

```sh
sudo wireserve-coordinator setup login
# Issuer URL: https://authentik.example.com/application/o/wireserve/
```

## Keycloak

In your realm:

1. *Clients → Create client*: OpenID Connect, client ID `wireserve`. Turn
   *Client authentication* on, keep *Standard flow*, and set *Valid redirect
   URIs* to `https://mesh.example.com/oidc/callback`. Copy the secret from
   the *Credentials* tab.
2. Keycloak puts no groups in a token by itself. *Client scopes → Create
   client scope* named `groups` (OpenID Connect), then in its *Mappers*, *By
   configuration → Group Membership*: token claim name `groups`, *Full group
   path* off, added to the ID token and userinfo.
3. In the `wireserve` client's *Client scopes*, add `groups` as a default
   scope. `offline_access` is there already as an optional one; people need
   the `offline_access` realm role, which Keycloak's default roles include.

Keycloak refuses a scope it doesn't know, which is why `setup login` asks
only for the ones the realm lists — create the `groups` scope first. The
issuer is the realm's:

```sh
sudo wireserve-coordinator setup login
# Issuer URL: https://keycloak.example.com/realms/home
```

Keycloak keeps every refresh token it hands out for `offline_access` as an
*offline session*, one per signed-in browser and one per owned device;
*Sessions* in the admin console lists them.

## Others

Any OpenID Connect provider works that gives a confidential client a refresh
token for `offline_access` and lists groups in a claim — Authelia, Zitadel,
Kanidm and the hosted ones among them. Register the redirect URL above, and
give `setup login` its issuer. The ones above are the ones checked step by
step; a hosted provider may limit how often its token endpoint is asked,
which the coordinator does once per refresh interval for every owned device
and every browser in use.
