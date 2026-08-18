# spar

Sync sparring harness for [minip2p-rs](https://github.com/deepso7/minip2p) 0.4.1. No Tokio/async.

```bash
cargo build --release
./target/release/spar listen
./target/release/spar dial <peer-multiaddr>
./target/release/spar suite --deep --transport quic --out reports
./target/release/spar suite --deep --transport tcp --out reports
```

`--transport` must match on listen and dial (default `quic`). Suite writes `reports/run-*/report.md`, `report.json`, and `memory.csv`.
