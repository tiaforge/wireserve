# fail2ban integration

These files belong on the **reverse proxy host**, not the coordinator host.

That is the whole point. The coordinator runs unprivileged with an empty
`CapabilityBoundingSet=` and never touches the host firewall (spec §8), and
behind the TLS-terminating proxy that spec §7 mandates the only client
address it can see is the proxy's own. A block applied there would drop
every node at once and stay dropped. The proxy sees the real client and
already holds the privilege to act.

So the coordinator's contribution is a log line, and the proxy's is the
block.

## What the coordinator emits

One `WARN` per failed authentication, on `/register`, `/poll` and the admin
listener:

```
event="auth_failure" client_ip=203.0.113.9 endpoint="/register" reason="unknown_token"
```

`reason` is one of `unknown_token`, `missing_header`, `bad_admin_token`. It
never contains any part of the presented credential.

`client_ip` is the address the coordinator resolved, which is only the real
client when `WIRESERVE_TRUST_PROXY_HEADERS=true` and the proxy sets
`X-Forwarded-For`. **With that setting off, every line reads as the proxy's
own address and this jail would ban the proxy.** Check that first.

## Install

Ship the coordinator's journal to the proxy host (or run both on one host),
then:

```sh
cp wireserve.conf   /etc/fail2ban/filter.d/wireserve.conf
cp wireserve-jail.conf /etc/fail2ban/jail.d/wireserve.conf
systemctl reload fail2ban
fail2ban-client status wireserve
```

Verify the filter matches real output before trusting it — a filter that
matches nothing fails silently, and this project has been bitten by exactly
that (PLAN.md decisions log #51, where tracing's ANSI escapes sat between a
field name and its `=`):

```sh
fail2ban-regex /var/log/wireserve/coordinator.log /etc/fail2ban/filter.d/wireserve.conf
```

If it matches nothing, check whether the log is being written with ANSI
colour. Set `RUST_LOG_STYLE=never` or pipe through `sed -r 's/\x1b\[[0-9;]*m//g'`.
