# spar

Sync sparring harness for [minip2p-rs](https://github.com/deepso7/minip2p) 0.4.6. No Tokio/async.

## Install (no cargo)

```bash
curl -fsSL https://raw.githubusercontent.com/deepso7/spar/main/scripts/install.sh | sh
spar listen --relay
```

Puts the binary in `~/.local/bin`. Override with `SPAR_INSTALL_DIR`. Pin a release with `SPAR_VERSION=0.1.2`.

Prebuilts: Linux amd64/arm64, macOS Apple Silicon and Intel. GitHub Actions builds them on `v*` tags.

## Two-peer punch

On the listener:

```bash
spar listen --relay
```

Copy the printed `spar dial 12D3KooW... --relay` line onto the other machine:

```bash
spar dial 12D3KooW... --relay -n 10
spar dial 12D3KooW... --relay --json
```

Dial prints a path/echo card (first path, punch attempts, Easy/Hard, RTT). `--json` is one object on stdout for agents.

## Suite

```bash
spar suite
spar suite --deep -t tcp
spar suite --gossip --nat
spar suite --relay
```

`-t/--transport` is global (default `quic`). Bare `--relay` uses `relay.minip2p.com`. Custom hop is `--relay=ADDR`. Dial a listener peer through the hop with `spar dial <peer> --relay`. Payload takes `4k` / `64k`.

Suite writes `reports/run-*/report.md`, `report.json`, and `memory.csv`.
