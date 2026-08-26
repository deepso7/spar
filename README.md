# spar

Sync sparring harness for [minip2p-rs](https://github.com/deepso7/minip2p) 0.4.6. No Tokio/async.

```bash
cargo build --release
./target/release/spar --help
./target/release/spar listen
./target/release/spar dial /ip4/127.0.0.1/udp/PORT/quic-v1/p2p/PEER

# WAN via relay.minip2p.com (bare --relay)
./target/release/spar listen --relay
./target/release/spar dial --relay 12D3KooW... -n 10 -p 4k
./target/release/spar dial --relay 12D3KooW... -n 2000 -i 0 -p 4k

./target/release/spar suite
./target/release/spar suite --deep -t quic
./target/release/spar suite --deep -t tcp
./target/release/spar suite --gossip
./target/release/spar suite --nat
./target/release/spar suite --gossip -t tcp
./target/release/spar suite --deep --gossip --nat
./target/release/spar suite --relay
```

`-t/--transport` is global (default `quic`) and must match on listen and dial. Bare `--relay` uses `relay.minip2p.com` (QUIC or TCP matching `-t`). Dial accepts a direct multiaddr, a full `/p2p-circuit/` addr, or a raw peer id with `--relay`. Payload takes `4k` / `64k`.

Suite writes `reports/run-*/report.md`, `report.json`, and `memory.csv`. Default `suite` is a short echo pack. `--deep` adds long echoes, reconnect-churn-200, and a 30s soak. `--gossip` and `--nat` add loopback gossipsub and NAT/circuit packs. `--relay` smokes a public Circuit Relay v2 hop (`force_relay`, 10 echoes). Used alone (without `--deep`) they skip the echo pack.
