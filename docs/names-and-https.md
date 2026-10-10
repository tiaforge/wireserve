# Real names and HTTPS

`<service>.wg` lives in each agent's `/etc/hosts`, which a phone does not
have. To give services a name that works everywhere, give the coordinator a
domain and a DNS provider it can write records through — on the coordinator,
any time after the install:

```sh
sudo wireserve-coordinator setup domain
```

It asks for both and writes them to `coordinator.env`:

```sh
WIRESERVE_SERVICE_DOMAIN=int.example.com
WIRESERVE_DNS_PROVIDER=cloudflare      # or rfc2136, desec, hetzner, porkbun
WIRESERVE_DNS_API_TOKEN=...            # a token that may edit the zone
```

Every service is then `<name>.int.example.com` instead of `<name>.wg` — the
suffix is **replaced, not added to**, so do it early: `setup domain` lists the
services it renames before it saves. Two working names would mean two base
URLs, and anything with a single configured one (Gitea's `ROOT_URL`, Grafana's
`root_url`, an OIDC `redirect_uri`) emits redirects that bounce between them.
Every name points at the service's own address, from a node and from a phone
alike, so one base URL is right everywhere.

**Publishing on TCP 443 is what asks for HTTPS:**

```sh
wireserve plex 443:32400   # https://plex.int.example.com, served by its own node
wireserve prom 80:9090     # http://prom.int.example.com:80, direct
```

Nothing that is not published on 443 ever gets a certificate.

## The DNS records

The coordinator keeps one record per approved service up to date through the
provider's API — written when the service is approved, moved when its address
changes, removed when it is withdrawn or its node revoked. **It never
overwrites a record it did not write:** before it first writes a name it asks
the provider what the zone already holds there, and a name with an A record
outside the mesh's range, an AAAA or a CNAME is left alone — `wireserve-admin
service list` shows it as an error ("not overwriting it") until the record is
gone. A name whose zone cannot be read waits too. So a node declaring a service
called `mail` cannot take over, or later delete, a record you already have
under the domain — nor get a certificate for it: the ACME challenge for such a
name is refused the same way.

Names are also protected before they get that far. A service may be called
after a node (`hetzner` on the node `hetzner`), but only by that node: nobody
else may newly declare another node's name, nor the coordinator's own host name
when it lies under the service domain, nor any name in
`WIRESERVE_RESERVED_SERVICE_NAMES` (comma-separated). The node is told in
`wireserve status`; a service it already has is never taken away for it.
`sudo wireserve-coordinator setup domain` asks for the domain and the provider, and before saving
writes and removes a throwaway `_wireserve-check` TXT record, so a wrong
token shows up there rather than as names that never appear. The wizard says where each provider's token is created:

| Provider | Token |
| --- | --- |
| Cloudflare | My Profile → API Tokens → Create Token → "Edit zone DNS", limited to the domain |
| deSEC | Token Management → add a token |
| Hetzner | Hetzner Console, the project holding the DNS: Security → API tokens, Read & Write (not the old dns.hetzner.com) |
| Porkbun | Account → API Access; also switch on "API Access" for the domain |

| Provider | Settings |
| --- | --- |
| `rfc2136` | `WIRESERVE_DNS_SERVER` (`host:port`), `WIRESERVE_DNS_TSIG_KEY_NAME`, `WIRESERVE_DNS_TSIG_SECRET` (base64), `WIRESERVE_DNS_TSIG_ALGORITHM` (default `hmac-sha256`) — BIND, Knot, PowerDNS |
| `cloudflare`, `desec`, `hetzner` | `WIRESERVE_DNS_API_TOKEN` |
| `porkbun` | `WIRESERVE_DNS_API_TOKEN` (the API key), `WIRESERVE_DNS_API_SECRET` |

`WIRESERVE_DNS_ZONE` names the zone when it is a parent of the service domain
(`example.com` for `int.example.com`; default: the domain itself). The
wizard finds it without asking: its test record tries the domain, then each
domain above it, and keeps the first the provider accepts. `WIRESERVE_DNS_TTL`
defaults to 300 seconds.

What to know first:

- **The coordinator manages service names under the domain.** A record with
  the same name as a service is replaced. It deletes only records it wrote
  itself, and never touches anything else in the zone.
- **Keep the domain to itself.** Most providers' tokens cover a whole zone,
  so a token for `example.com` could also change its mail records. A zone of
  its own (a subdomain delegated to its own zone, or a spare domain) keeps
  the token that small.
- **The records publish your mesh addresses and service names.** They are
  private addresses and unreachable from outside the mesh, but anyone can
  read them.
- **An address change waits 20 seconds** before it is written, so a name
  that swings and swings back never reaches resolver caches.
  `wireserve-admin service list` shows each record in its DNS column as
  `published`, `pending` or `error`, with the provider's error as a note.

## HTTPS on the service's own node

A service published on TCP 443 is served with HTTPS by **its own node**. The
`wireserve-tls` unit, which `wireserve install` sets up beside the agent,
runs a small terminator as its own unprivileged user. For each of the node's
services on 443 it:

1. gets a certificate for `<name>.<domain>` — the key is made on the node and
   never leaves it; the coordinator publishes the ACME DNS-01 challenge record
   for it, and only for that node's own names;
2. answers on the service's own address, port 443, and passes each request
   to the service's target in plain HTTP on the same node;
3. tells the backend who is calling: `X-Wireserve-Node` names the calling
   node, `X-Forwarded-For` its mesh address, and copies of either sent by the
   client are removed first.

```sh
# on the coordinator, optional
WIRESERVE_ACME_DIRECTORY=https://acme-v02.api.letsencrypt.org/directory  # the default
WIRESERVE_ACME_EMAIL=you@example.com
```

Worth knowing:

- **Every 443 service name becomes public** in the Certificate Transparency
  logs, one certificate per name.
- **WebSockets go through; other upgrades don't.** A WebSocket reaches the
  backend as it answers it, and stays open while its caller is still let in.
  Any other `Upgrade` (`h2c`, say) is ignored and the request served as a
  plain one: past a switch nothing more is checked, so a protocol that
  carries further requests would carry them past the sign-in. A backend's
  `101` that isn't a WebSocket's answer to that very request is refused (502).
- **Only the service's 443 mapping changes.** Its other ports stay ordinary
  mappings, and its target port stays closed to the mesh.
- **Port 443 stays free on the node** for nginx, Caddy or Stalwart. The
  terminator really listens on port 11443, which systemd holds for it
  (`wireserve-tls.socket`), and the agent sends the mesh's 443 on service
  addresses there. If 11443 is taken, pick another with
  `sudo wireserve install --tls-port <port>`; a second instance gets the
  next free port automatically.
- **Let's Encrypt limits** — 5 failed validations per name per hour, 5
  duplicate certificates a week: the terminator keeps its certificates across
  restarts and backs off after a failure, and the install wizard checks the
  DNS credential before anything is issued.
- **Try it on the staging CA first.** Let's Encrypt's staging CA has far
  higher limits and issues certificates no browser trusts, so a first setup
  can go wrong there for free:

  ```sh
  # /etc/wireserve/coordinator.env, then: sudo systemctl restart wireserve-coordinator
  WIRESERVE_ACME_DIRECTORY=https://acme-staging-v02.api.letsencrypt.org/directory
  ```

  Check with `curl -vk https://<name>.<domain>/`: the issuer is `(STAGING)`.
  Then remove the line and restart the coordinator. Certificates are kept
  per CA, so each node replaces its staging certificates with production
  ones within a minute, serving the staging ones until then.


## If the name resolves on one network but not another

This is almost always **DNS rebinding protection**, and it is worth knowing
before it costs you an evening. Resolvers strip private addresses out of
answers from public DNS by default; the usual list is `127/8`, `10/8`,
`172.16/12`, `192.168/16`, `169.254/16`, `fd00::/8` and `fe80::/10`. The
coordinator generates a `10.x.0.0/16` mesh and an `fd..::/64` prefix, so
**both families are on that list** and the records are silently dropped —
no error, just a name that does not resolve.

OpenWrt's dnsmasq enables this by default, as do pfSense, NextDNS and AdGuard.
The usual offender is your own router, and every one of them has a per-domain
exception:

```
rebind-domain-ok=/int.example.com/       # dnsmasq, OpenWrt
private-domain: "int.example.com"        # unbound, pfSense
```

NextDNS and AdGuard take an allowlist entry for the domain. Carrier and plain
public resolvers generally do not filter, which is why the symptom is often
"works on cellular, fails at home".

`100.64.0.0/10` is not on the strip list, but do not reach for it — see the
mesh-range warning further down, since Tailscale allocates that entire `/10`.
