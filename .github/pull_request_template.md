<!--
Thank you for contributing to IpStack!
Before opening a Pull Request, please ensure:
1. There is an existing open Issue that has been verified/triaged by a maintainer.
   (Opening an issue and immediately submitting a PR before maintainer verification is not accepted.)
2. Your PR includes a unit or async test (`#[test]` or `#[tokio::test]`) that reproduces the issue and verifies the fix.
Unsolicited or unverified AI-generated PRs will be automatically closed.
-->

## Verified Issue
<!-- Replace with the maintainer-verified issue number, e.g. Fixes #123 -->
Fixes #

## Problem & Motivation
<!-- Describe the concrete bug or use case. Avoid speculative static-analysis claims without a reproducible failure. -->


## Test & Verification Evidence
<!-- Name the test(s) added/updated to reproduce the issue and paste the relevant test output. -->


## Checklist
- [ ] This PR references an existing open issue (`#...`) that has been verified by a maintainer.
- [ ] I have added or updated a test (`#[test]` or `#[tokio::test]`) that reproduces the issue and verifies the fix.
- [ ] I have personally reviewed, tested, and understood every line of code in this PR (no unverified AI-generated patches).
- [ ] `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, and `cargo nextest run --all-features --all-targets` pass locally.
