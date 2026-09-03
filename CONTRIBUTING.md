# Contributing

V6Alias is currently an early hackathon prototype. Open an issue before making
large changes so the address model and standards guardrails remain coherent.

## Local checks

```powershell
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
```

Keep the core library deterministic and independent of DHCP or DNS providers.
Invalid, ambiguous, or unauthorized inputs must fail explicitly rather than
falling back to a privileged profile.
