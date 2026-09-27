#!/bin/sh
# A stand-in for authward's /verify, for run-service-auth-test.sh, run once
# per connection by `socat ... EXEC:/e2e/auth-stub.sh`. Signs in whoever
# carries `authward_session=ok` — but only for a request the terminator
# forwarded with the protected service's own name in X-Forwarded-Host,
# which is the part authward depends on. Everyone else gets a 401 with the
# login URL, as authward answers.
H=$(sed -u '/^\r$/q')
if printf '%s\n' "$H" | grep -qi '^x-forwarded-host: jellyfin\.' \
    && printf '%s\n' "$H" | grep -qi '^cookie:.*authward_session=ok'; then
    printf 'HTTP/1.0 200 OK\r\nX-Auth-User: alice\r\nX-Auth-Email: \r\nX-Auth-Groups: \r\n\r\n'
else
    printf 'HTTP/1.0 401 Unauthorized\r\nX-Login-Url: https://auth.int.test/login?rd=x\r\n\r\n'
fi
