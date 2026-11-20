#!/bin/sh
# Proves dns-cache itself validates DNSSEC: the upstream here is an unbound
# with validation turned off, so it happily returns bogus data.
#   ./tests/dnssec-check.sh      (needs docker, dig, cargo)
set -eu
cd "$(dirname "$0")/.."
PORT=5398 UP=5454 TMP=$(mktemp -d)
cleanup() { kill "$PID" 2>/dev/null || true; docker rm -f dnssec-upstream >/dev/null 2>&1 || true; rm -rf "$TMP"; }
trap cleanup EXIT

docker run -d --rm --name dnssec-upstream -p 127.0.0.1:$UP:53/udp -p 127.0.0.1:$UP:53/tcp alpine:3.20 sh -c '
  apk add -q unbound && printf "server:\n interface: 0.0.0.0\n access-control: 0.0.0.0/0 allow\n module-config: \"iterator\"\n" > /u.conf && exec unbound -d -c /u.conf' >/dev/null

cat > "$TMP/c.toml" <<CONF
listen = ["127.0.0.1:$PORT", "[::1]:$PORT"]
[[view]]
name = "validating"
match_clients = ["127.0.0.1/32"]
upstreams = [{ ip = "127.0.0.1", port = $UP }]
[[view]]
name = "not-validating"
match_clients = ["::1/128"]
dnssec = false
upstreams = [{ ip = "127.0.0.1", port = $UP }]
CONF

cargo build -q
./target/debug/dns-cache "$TMP/c.toml" > "$TMP/log" 2>&1 & PID=$!
status() { dig @"$1" -p $PORT +time=10 +tries=2 "$2" | sed -n 's/.*status: \([A-Z]*\).*/\1/p'; }
until dig @127.0.0.1 -p $UP +time=1 +tries=1 . NS >/dev/null 2>&1; do sleep 1; done  # unbound up

fail=0
check() { got=$(status "$1" "$2"); [ "$got" = "$3" ] && echo "ok   $4: $2 -> $got" || { echo "FAIL $4: $2 -> $got (want $3)"; fail=1; }; }
check ::1       dnssec-failed.org NOERROR  "upstream passes bogus data"
check 127.0.0.1 dnssec-failed.org SERVFAIL "dns-cache rejects it"
check 127.0.0.1 isc.org           NOERROR  "signed zone still resolves"
check 127.0.0.1 example.org       NOERROR  "signed zone still resolves"
grep -q "DNSSEC validation failed\|DnssecBogus\|bogus" "$TMP/log" && echo "ok   log shows a local validation failure" || { echo "FAIL no local validation error in log"; fail=1; }
[ $fail = 1 ] && sed 's/\x1b\[[0-9;]*m//g' "$TMP/log" | grep -E "WARN|ERROR"
exit $fail
