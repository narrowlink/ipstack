#!/usr/bin/env bash
set -euo pipefail

OUT_DIR=bench_results/$(date +%Y%m%d_%H%M%S)
mkdir -p "$OUT_DIR"

printf "Building examples...\r\n" >&2
cargo build --examples --release > "$OUT_DIR/build.log" 2>&1

# iperf3 server will listen on 127.0.0.1:5201
printf "Starting iperf3 server... (logs -> $OUT_DIR/iperf3_server.log)\r\n" >&2
iperf3 -s -p 5201 >"$OUT_DIR/iperf3_server.log" 2>&1 &
IPERF3_SRV_PID=$!

# start the tun example (requires root). We will try to launch it via sudo; if that
# fails (password prompt/backgrounding issues), prompt the user to start it manually
# in another terminal and press ENTER to continue.
EXAMPLE_BIN=target/release/examples/tun
if [ ! -x "$EXAMPLE_BIN" ]; then
  printf "Example binary not found: $EXAMPLE_BIN\r\n" >&2
  kill $IPERF3_SRV_PID || true
  exit 1
fi

printf "Attempting to start the TUN example via sudo (may prompt for password)...\r\n" >&2
if command -v sudo >/dev/null 2>&1; then
  # Ask for sudo credential upfront so backgrounded sudo won't hang
  sudo -v || true
  sudo "$EXAMPLE_BIN" --server-addr 127.0.0.1:5201 < /dev/null >"$OUT_DIR/tun_example.log" 2>&1 &
  TUN_PID=$!
  # Reset terminal in case sudo changed it
  stty sane || true
  sleep 1
  if kill -0 "$TUN_PID" >/dev/null 2>&1; then
    printf "TUN example started (pid $TUN_PID), logs -> $OUT_DIR/tun_example.log\r\n" >&2
  else
    echo "Automatic sudo start failed or process exited. Please run the following command in another terminal as root:" >&2
    echo "  sudo $EXAMPLE_BIN --server-addr 127.0.0.1:5201 >$OUT_DIR/tun_example.log 2>&1 &" >&2
    echo >&2 "Press ENTER after you've started the TUN example manually (or Ctrl-C to abort)"
    read -r _
    TUN_PID=0
  fi
else
  echo "sudo not found; please start the TUN example manually in another terminal as root:" >&2
  echo "  sudo $EXAMPLE_BIN --server-addr 127.0.0.1:5201 >$OUT_DIR/tun_example.log 2>&1 &" >&2
  echo >&2 "Press ENTER after you've started the TUN example manually (or Ctrl-C to abort)"
  read -r _
  TUN_PID=0
fi

# wait a moment for tun and ip stack to initialize
sleep 3

# run iperf3 tests (JSON output saved)
printf "Running client -> server test...\r\n" >&2
iperf3 -c 10.3.0.1 -J > "$OUT_DIR/iperf_client_to_server.json" 2> "$OUT_DIR/iperf_client_to_server.err" || true

printf "Running server -> client (reverse) test...\r\n" >&2
iperf3 -c 10.3.0.1 -R -J > "$OUT_DIR/iperf_server_to_client.json" 2> "$OUT_DIR/iperf_server_to_client.err" || true

# give a moment to flush logs
sleep 3

# stop background processes
sudo kill $TUN_PID || true
kill $IPERF3_SRV_PID || true

printf "Benchmark finished. Results saved to: $OUT_DIR\r\n" >&2

printf "To inspect results:\r\n" >&2
printf "  ls -l $OUT_DIR\r\n" >&2
printf "  jq . < $OUT_DIR/iperf_client_to_server.json\r\n" >&2

printf "If you don't want the script to require root, instead run the tun example manually as root, then run the two iperf3 commands:\r\n" >&2

printf "  # start iperf3 server (local): iperf3 -s -p 5201 &\r\n" >&2
printf "  # run client->server: iperf3 -c 10.3.0.1 -J > client.json\r\n" >&2
printf "  # run reverse: iperf3 -c 10.3.0.1 -R -J > reverse.json\r\n" >&2

# Reset terminal
stty sane || true

printf "\r\n" >&2
