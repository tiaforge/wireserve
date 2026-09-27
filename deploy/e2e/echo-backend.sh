#!/bin/sh
# A test backend for the e2e harnesses, run once per connection by
# `socat ... EXEC:"/work/echo-backend.sh <label>"`: answers any request with
# `backend:<label>` and the request's own headers, so a harness can see what
# reached it. A file rather than a SYSTEM: one-liner, because socat parses
# escapes and quotes in its address first and mangles the shell's.
H=$(sed -u '/^\r$/q')
printf 'HTTP/1.0 200 OK\r\n\r\nbackend:%s\n%s\n' "$1" "$H"
