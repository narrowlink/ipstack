#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "$0")/.."
build_log=$(mktemp)
trap 'rm -f -- "$build_log"' EXIT
cargo test --locked --test linux_tcp_close_extended --no-run --message-format=json > "$build_log"
binary=$(python3 - "$build_log" <<'PY'
import json, sys
for line in open(sys.argv[1]):
    item = json.loads(line)
    if item.get('reason') == 'compiler-artifact' and item.get('target', {}).get('name') == 'linux_tcp_close_extended' and item.get('executable'):
        print(item['executable'])
PY
)
test -n "$binary"
profiles=(clean netem reorder)
if [[ $# -gt 0 ]]; then profiles=("$@"); fi
for profile in "${profiles[@]}"; do
  echo "Running extended Linux TCP matrix: $profile"
  timeout 15m sudo -n unshare --net -- bash -euo pipefail -c '
    ip link set lo up
    export IPSTACK_TEST_NETNS=1 IPSTACK_EXT_PROFILE="$2"
    export IPSTACK_EXT_CASE="$3" RUST_LOG="$4"
    exec "$1" --ignored --nocapture
  ' bash "$binary" "$profile" "${IPSTACK_EXT_CASE:-}" "${RUST_LOG:-}"
done
echo EXTENDED_NETWORK_MATRIX=PASS
