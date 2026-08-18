# spar

Sync sparring harness for [minip2p-rs](https://github.com/deepso7/minip2p) 0.4.1. No Tokio/async.

```bash
cargo build --release
./target/release/spar listen
./target/release/spar dial <peer-multiaddr>
./target/release/spar suite --out reports
./target/release/spar suite --deep --transport quic --out reports
./target/release/spar suite --deep --transport tcp --out reports
./target/release/spar suite --gossip --out reports
./target/release/spar suite --nat --out reports
./target/release/spar suite --gossip --transport tcp --out reports
./target/release/spar suite --deep --gossip --nat --out reports
```

`--transport` must match on listen and dial (default `quic`). Suite writes `reports/run-*/report.md`, `report.json`, and `memory.csv`.

Default `suite` is a short echo pack. `--deep` adds long echoes, reconnect-churn-200, and a 30s soak. `--gossip` and `--nat` add loopback gossipsub and NAT/circuit packs. Used alone (without `--deep`) they skip the echo pack.
