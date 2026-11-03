#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "$0")/.."
command -v cargo >/dev/null
command -v unshare >/dev/null
command -v ip >/dev/null
command -v tc >/dev/null
test -c /dev/net/tun || { echo "/dev/net/tun absent" >&2; exit 1; }
# Compile as the regular user. Privileges are limited to running the test in a new net namespace.
build_log=$(mktemp)
trap 'rm -f -- "$build_log"' EXIT
cargo test --locked --test linux_tcp_close --no-run --message-format=json > "$build_log"
binary=$(python3 - "$build_log" <<'PY'
import json,sys
for line in open(sys.argv[1]):
    item=json.loads(line)
    if item.get("reason")=="compiler-artifact" and item.get("target",{}).get("name")=="linux_tcp_close" and item.get("executable"):
        print(item["executable"])
PY
)
test -n "$binary"
for impairment in clean netem; do
  echo "Running Linux TCP matrix: $impairment"
  sudo -n unshare --net -- bash -euo pipefail -c '
    ip link set lo up
    export IPSTACK_TEST_NETNS=1
    if [[ "$2" == netem ]]; then export IPSTACK_TEST_NETEM=1; fi
    exec "$1" --ignored --nocapture
  ' bash "$binary" "$impairment"
done
