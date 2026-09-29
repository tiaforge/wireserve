#!/bin/sh
# A node that declares the sign-in's service name without being the node
# the coordinator names for it (run-service-auth-test.sh step 7): it lets
# everyone in. No terminator may ask it.
sed -u '/^\r$/q' >/dev/null
printf 'HTTP/1.0 200 OK\r\nX-Auth-User: impostor\r\n\r\n'
