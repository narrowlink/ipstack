# TCP close qualification

This work integrates frontierlabs-admin's half-close changes from PR #112 and preserves SajjadPourali's shutdown wakeup fix from PR #114, following Musyg's report in issue #89.

## Running the tests

Build and run the ordinary tests first. This also generates Cargo.lock in a fresh checkout:

```sh
cargo test
cargo fmt --check
cargo clippy --locked --all-targets --all-features -- -D warnings
bash scripts/qualify-linux-tcp.sh
bash scripts/qualify-linux-tcp-extended.sh
```

The network tests require Linux, TUN, iproute2, Python 3, util-linux, and permission to run `sudo -n unshare --net`. Builds run as the ordinary user. Every network profile runs in a separate network namespace. No host routes or host qdiscs are changed. The integration tests are ignored during ordinary `cargo test` and run explicitly by these scripts.

## Coverage

The original matrix has 32 cases: four application close paths, two payload sizes, with and without losing the first ipstack FIN, under clean and delay/loss profiles.

The extended matrix has 264 cases, 88 per profile: clean, 10 ms delay with 1% random loss, and 10 ms delay with 25% reordering and 50% correlation. Impairments apply in the Linux-to-ipstack direction. Each profile tests IPv4 and IPv6, with 5-byte and 128-KiB payloads in both directions. Payload bytes vary by position so misordering or duplication cannot be hidden by constant data.

| Scenario | Assertion beyond complete payload delivery |
| --- | --- |
| Client-first, server-first, application overlap, and drop | Bounded completion with no unexpected RST |
| Lose one, two, or three ipstack FIN attempts | Every requested loss occurs, a later FIN arrives at the same sequence, and its ACK is observed |
| Lose the kernel's final ACK of ipstack FIN | ipstack retransmits FIN and a subsequent kernel ACK is observed |
| Lose ipstack's final ACK of kernel FIN | Linux retransmits FIN and ipstack answers it |
| Swap two incoming data segments | The swap occurs and the complete varied payload is delivered in order |
| Force crossed FINs | ipstack FIN is retained until Linux sends its own FIN without having seen it; release waits for ipstack's ACK of the kernel FIN |

ACK-loss cases are applied to the close paths where that direction carries the final ACK. Deterministic data swaps use 128-KiB transfers. FIN loss applies to the connection's client port, not to late packets from earlier cases. FIN retransmissions preserve the FIN sequence even when the original FIN carries data. ACK observations include ACKs carried by data or FIN; deterministic ACK loss targets a pure ACK. The crossed-FIN gate also retains retransmissions until release.

Every extended case waits for both FINs and their acknowledgements, including cases without injected loss. The fault oracle also waits for recovery packets after application EOF. `shutdown()` or EOF alone cannot establish that a lost final ACK was recovered. Every case has a 45-second deadline; each extended profile also has a 15-minute process deadline.

A reordered duplicate FIN can reach ipstack after Linux has consumed the final ACK and closed. Linux may then reset ipstack's required ACK of that duplicate. These late resets are counted separately only when both FINs and ACKs have been observed, the reset is incoming and has the exact post-FIN sequence, the kernel FIN was seen more than once, and exactly one final-ACK attempt was made per observed kernel FIN. Other resets fail the case. This retains the distinction from an unsolicited extra window ACK. The TimeWait reset behavior follows [RFC 9293 section 3.10.7.4](https://www.rfc-editor.org/rfc/rfc9293.html#section-3.10.7.4); a dedicated unit test checks duplicate-FIN acknowledgement followed by silent closure on RST.

For a targeted diagnostic case:

```sh
IPSTACK_EXT_CASE='v6/server-first/131072/AckToKernel' \
  bash scripts/qualify-linux-tcp-extended.sh clean
```

A targeted run does not qualify the full matrix. Qualification evidence must contain all 264 unique extended case lines and all 32 original case lines.

## Lifecycle and timer tests

Unit tests additionally cover sequence wraparound, invalid ACKs, partial ACKs, independent shutdown waiters, CloseWait data preservation, TimeWait restart, detached cleanup, and FinWait2 expiry. New boundary tests cover:

- Drop with no entered Tokio runtime: immediate RST, closed state, and worker cancellation.
- Active detached close: wait for data ACKs, local FIN ACK, peer FIN, and TimeWait before destruction.
- Receive progress renewing the FinWait2 inactivity deadline.
- FIN retry counts of zero, one, and three in FinWait1, Closing, and LastAck, with configured floors and an RTO above the ordinary cap. This is 27 configuration/state combinations within one unit test.
- A delayed reader notification after the final ACK, while unread data remains buffered.
- 256 independent streams established simultaneously with data outstanding, released by a barrier to race shutdown against peer FIN, followed by explicit worker-destruction checks on a four-thread runtime. This differs from the older test, which races two tasks but processes sessions sequentially.

## Defect found by the extended matrix

The server-first 128-KiB scenario with repeated FIN loss exposed an extra window-update ACK after ipstack had acknowledged Linux's FIN. Linux had already closed and replied with RST. The application had received all bytes, so an EOF-only test missed this failure.

A delayed reader-drain notification could call the data extraction helper in TimeWait and send that extra ACK. The worker now processes window-update notifications only while the receive direction remains open. After the peer FIN, `poll_read` drains the remaining bytes without advertising another window. A deterministic unit regression fails before this fix, and the Linux packet-level oracle checks for the resulting RST.

## Scope of the result

On Phoenix5-Orion (Ubuntu 24.04.5, Linux 7.0.0-42-generic, Rust 1.95.0), the final run passed all 296 Linux cases, 101 unit tests, 23 doctests, formatting, Clippy with warnings denied, and diff checks. The extended matrix contains 132 IPv4 and 132 IPv6 cases. The loss profile recorded 56 actual packet drops. No unexpected resets occurred; one late closed-peer reset met the strict classification above.

Twenty repetitions of the simultaneous 256-stream test passed, totalling 5,120 streams. Separately, twenty repetitions of the older per-session task-race test passed, totalling another 5,120 sessions. These stress runs use the in-process packet harness; the 296 integration cases exercise Linux kernel TCP through TUN. The evidence bundle retains the failing pre-fix regression, intermediate diagnostics, final logs, exact dependency lockfile, and a matrix auditor.

The qualification concerns these close paths, faults, payload sizes, and configuration boundaries. It is not exhaustive TCP conformance. The implementation uses a configured RTO and exponential backoff; it does not implement a new adaptive RTT estimator. Packet parsing in the test fault injector covers the IPv4 and IPv6 TCP traffic generated here, not arbitrary IPv6 extension-header chains.

The lifetime after drop, the use of `config.timeout`, and FIN retry limits remain API decisions for maintainer review even when their implemented behavior passes the tests.
