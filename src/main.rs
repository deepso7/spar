//! spar — sync sparring harness for minip2p (no Tokio / no async).

mod common;
mod gossip;
mod nat;
mod relay;
mod suite;

use std::path::PathBuf;
use std::process::ExitCode;
use std::str::FromStr;
use std::sync::atomic::AtomicBool;
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::Duration;

use clap::{Parser, Subcommand, ValueEnum};
use minip2p::{PeerAddr, PeerId};
use serde::Serialize;

use common::{
    parse_dial_target, run_dial_collect, run_dial_nat, run_listen_loop, run_listen_relay, DialOpts,
    DialResult, DialTarget, TransportKind,
};
use suite::SuiteArgs;

const PUBLIC_RELAY_QUIC: &str =
    "/dns4/relay.minip2p.com/udp/19876/quic-v1/p2p/12D3KooWNAHhp6rp11SvCDA84zua3hhEYTLNjgKmEDmt1BddtLdf";
const PUBLIC_RELAY_TCP: &str =
    "/dns4/relay.minip2p.com/tcp/19876/p2p/12D3KooWNAHhp6rp11SvCDA84zua3hhEYTLNjgKmEDmt1BddtLdf";

#[derive(Parser, Debug)]
#[command(
    name = "spar",
    version,
    about = "Sync sparring harness for minip2p (no Tokio/async)",
    after_help = "\
Examples:
  spar listen --relay
  spar dial --relay 12D3KooW... -n 10 -p 4k
  spar dial --relay 12D3KooW... --json
  spar suite --relay

Bare --relay uses relay.minip2p.com (QUIC or TCP matching -t).
Custom hop: --relay=/dns4/host/...
--json prints one JSON object on stdout; progress stays on stderr."
)]
struct Cli {
    /// Wire transport. Listener and dialer must match.
    #[arg(
        short = 't',
        long,
        value_enum,
        default_value_t = CliTransport::Quic,
        global = true
    )]
    transport: CliTransport,

    /// Machine-readable JSON on stdout (progress stays on stderr).
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
#[value(rename_all = "lower")]
enum CliTransport {
    #[default]
    Quic,
    Tcp,
}

impl From<CliTransport> for TransportKind {
    fn from(value: CliTransport) -> Self {
        match value {
            CliTransport::Quic => Self::Quic,
            CliTransport::Tcp => Self::Tcp,
        }
    }
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Accept echo streams. --relay reserves on a hop and prints a dial command.
    Listen {
        /// Bind host:port. Relay mode remaps 127.0.0.1:0 to 0.0.0.0:0.
        #[arg(short, long, default_value = "127.0.0.1:0")]
        bind: String,
        /// Circuit Relay v2 hop. Bare --relay uses relay.minip2p.com.
        #[arg(
            short,
            long,
            num_args = 0..=1,
            default_missing_value = "public",
            require_equals = true,
            value_name = "ADDR"
        )]
        relay: Option<String>,
    },
    /// Echo a peer: direct multiaddr, full circuit, or peer id with --relay.
    Dial {
        /// Peer multiaddr, /p2p-circuit/ addr, or raw peer id (needs --relay).
        target: String,
        /// Circuit Relay v2 hop. Bare --relay uses relay.minip2p.com.
        #[arg(
            short,
            long,
            num_args = 0..=1,
            default_missing_value = "public",
            require_equals = true,
            value_name = "ADDR"
        )]
        relay: Option<String>,
        /// Echo frames to send.
        #[arg(short = 'n', long, default_value_t = 10)]
        count: u64,
        /// Milliseconds between sends. 0 pipelines as fast as the stack allows.
        #[arg(short = 'i', long, default_value_t = 200)]
        interval: u64,
        /// Extra bytes per frame (0, 4096, 4k, 64k).
        #[arg(
            short = 'p',
            long,
            default_value = "0",
            value_parser = parse_bytes,
            value_name = "BYTES"
        )]
        payload: usize,
        /// Builtin ping rounds (0 = skip).
        #[arg(long, default_value_t = 0)]
        ping: u64,
    },
    /// Loopback soak. Writes reports/run-<stamp>/.
    Suite {
        #[arg(short, long, default_value = "reports")]
        out: PathBuf,
        /// Long echoes, reconnect-churn-200, 30s soak.
        #[arg(long)]
        deep: bool,
        /// Loopback gossipsub pack.
        #[arg(long)]
        gossip: bool,
        /// Loopback NAT/circuit pack.
        #[arg(long)]
        nat: bool,
        /// Public hop smoke (force_relay, 10 echoes). Bare --relay uses relay.minip2p.com.
        #[arg(
            short,
            long,
            num_args = 0..=1,
            default_missing_value = "public",
            require_equals = true,
            value_name = "ADDR"
        )]
        relay: Option<String>,
    },
}

fn public_relay(transport: TransportKind) -> PeerAddr {
    let raw = match transport {
        TransportKind::Quic => PUBLIC_RELAY_QUIC,
        TransportKind::Tcp => PUBLIC_RELAY_TCP,
    };
    PeerAddr::from_str(raw).expect("baked-in public hop")
}

fn resolve_relay(
    raw: Option<String>,
    transport: TransportKind,
) -> Result<Option<PeerAddr>, String> {
    match raw.as_deref() {
        None => Ok(None),
        Some("public") => Ok(Some(public_relay(transport))),
        Some(s) => PeerAddr::from_str(s)
            .map(Some)
            .map_err(|e| format!("bad --relay: {e}")),
    }
}

fn parse_bytes(s: &str) -> Result<usize, String> {
    let s = s.trim().to_ascii_lowercase().replace('_', "");
    let (digits, mul) = if let Some(n) = s.strip_suffix("kib") {
        (n, 1024usize)
    } else if let Some(n) = s.strip_suffix("mib") {
        (n, 1024 * 1024)
    } else if let Some(n) = s.strip_suffix("kb") {
        (n, 1024)
    } else if let Some(n) = s.strip_suffix("mb") {
        (n, 1024 * 1024)
    } else if let Some(n) = s.strip_suffix('k') {
        (n, 1024)
    } else if let Some(n) = s.strip_suffix('m') {
        (n, 1024 * 1024)
    } else {
        (s.as_str(), 1)
    };
    let n: usize = digits
        .trim()
        .parse()
        .map_err(|_| format!("bad byte size {s:?}"))?;
    n.checked_mul(mul)
        .ok_or_else(|| format!("byte size overflow {s:?}"))
}

fn resolve_target(raw: &str, relay: Option<&PeerAddr>) -> Result<DialTarget, String> {
    if raw.contains("/p2p-circuit/") || raw.starts_with('/') {
        return parse_dial_target(raw);
    }
    let peer = PeerId::from_str(raw).map_err(|e| {
        format!("invalid target {raw:?}: {e} (want a multiaddr, circuit addr, or peer id)")
    })?;
    let Some(relay) = relay.cloned() else {
        return Err("bare peer id needs --relay (or pass a full multiaddr)".into());
    };
    Ok(DialTarget::Circuit { relay, peer })
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let transport = TransportKind::from(cli.transport);
    let json = cli.json;
    let result = match cli.command {
        Command::Listen { bind, relay } => cmd_listen(bind, transport, relay, json),
        Command::Dial {
            target,
            relay,
            count,
            interval,
            payload,
            ping,
        } => cmd_dial(
            target, transport, relay, count, interval, payload, ping, json,
        ),
        Command::Suite {
            out,
            deep,
            gossip,
            nat,
            relay,
        } => cmd_suite(out, deep, gossip, nat, transport, relay, json),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            if json {
                let _ = writeln_json_error(&err.to_string());
            } else {
                eprintln!("error: {err}");
            }
            ExitCode::FAILURE
        }
    }
}

fn writeln_json_error(err: &str) -> Result<(), serde_json::Error> {
    #[derive(Serialize)]
    struct E<'a> {
        ok: bool,
        error: &'a str,
    }
    println!("{}", serde_json::to_string(&E { ok: false, error: err })?);
    Ok(())
}

fn cmd_listen(
    bind: String,
    transport: TransportKind,
    relay: Option<String>,
    json: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let relay = resolve_relay(relay, transport)?;
    let stop = Arc::new(AtomicBool::new(false));
    let stop2 = Arc::clone(&stop);
    if let Some(relay) = relay {
        let (tx, rx) = mpsc::channel::<String>();
        let handle = thread::spawn(move || run_listen_relay(&bind, transport, relay, stop2, tx));
        let mut us = String::new();
        let mut circuit = String::new();
        let mut addr = String::new();
        while let Ok(line) = rx.recv_timeout(Duration::from_secs(25)) {
            if let Some(v) = line.strip_prefix("us=") {
                us = v.to_string();
            } else if let Some(v) = line.strip_prefix("circuit=") {
                circuit = v.to_string();
            } else if let Some(v) = line.strip_prefix("addr=") {
                addr = v.to_string();
            }
            if !json {
                println!("[listen] {line}");
            }
            if line.starts_with("circuit=") || line.starts_with("warn=") {
                break;
            }
        }
        if json {
            #[derive(Serialize)]
            struct ListenJson<'a> {
                event: &'a str,
                ok: bool,
                us: &'a str,
                circuit: &'a str,
                addr: &'a str,
                transport: &'a str,
                next: String,
            }
            let report = ListenJson {
                event: "listening",
                ok: !circuit.is_empty(),
                us: &us,
                circuit: &circuit,
                addr: &addr,
                transport: transport.as_str(),
                next: format!("spar dial --relay {us} -n 10"),
            };
            println!("{}", serde_json::to_string(&report)?);
        } else if !us.is_empty() {
            println!();
            println!("  next: spar dial --relay {us} -n 10");
            println!();
        }
        eprintln!(
            "[listen] transport={} echoing (Ctrl-C to stop)",
            transport.as_str()
        );
        handle.join().map_err(|_| "listen thread panicked")??;
        Ok(())
    } else {
        let (tx, rx) = mpsc::channel();
        let handle = thread::spawn(move || run_listen_loop(&bind, transport, stop2, tx));
        if let Ok(peer_addr) = rx.recv() {
            if json {
                #[derive(Serialize)]
                struct ListenJson<'a> {
                    event: &'a str,
                    ok: bool,
                    us: String,
                    addr: String,
                    transport: &'a str,
                }
                println!(
                    "{}",
                    serde_json::to_string(&ListenJson {
                        event: "listening",
                        ok: true,
                        us: peer_addr.peer_id().to_string(),
                        addr: peer_addr.to_string(),
                        transport: transport.as_str(),
                    })?
                );
            } else {
                println!("[listen] us={}", peer_addr.peer_id());
                println!("[listen] addr={peer_addr}");
            }
            eprintln!(
                "[listen] transport={} echoing (Ctrl-C to stop)",
                transport.as_str()
            );
        }
        handle.join().map_err(|_| "listen thread panicked")??;
        Ok(())
    }
}

fn cmd_dial(
    target: String,
    transport: TransportKind,
    relay: Option<String>,
    count: u64,
    interval: u64,
    payload: usize,
    ping: u64,
    json: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let relay = resolve_relay(relay, transport)?;
    let parsed = resolve_target(&target, relay.as_ref())?;
    let r = if relay.is_some() || matches!(parsed, DialTarget::Circuit { .. }) {
        run_dial_nat(
            parsed,
            relay,
            count,
            Duration::from_millis(interval),
            payload,
            transport,
        )
    } else {
        let addr = match &parsed {
            DialTarget::Direct(a) => a.clone(),
            DialTarget::Circuit { relay, .. } => relay.clone(),
        };
        run_dial_collect(DialOpts {
            addr,
            count,
            interval: Duration::from_millis(interval),
            payload,
            builtin_ping: ping,
            quiet: json,
            name: "cli-dial".into(),
            max_echo_duration: None,
            rtt_sample_stride: 1,
            transport,
        })
    };
    if json {
        println!("{}", serde_json::to_string(&dial_json(&r, transport.as_str(), &target))?);
    } else {
        print_dial_cards(&r);
    }
    if r.ok {
        Ok(())
    } else {
        Err(r.error.unwrap_or_else(|| "dial failed".into()).into())
    }
}

#[derive(Serialize)]
struct DialJson<'a> {
    ok: bool,
    event: &'a str,
    name: &'a str,
    target: &'a str,
    us: &'a str,
    transport: &'a str,
    first_path: &'a str,
    final_path: &'a str,
    punch_attempts: u32,
    punch_upgraded: bool,
    fell_back_to_relay: bool,
    difficulty: &'a str,
    direct_connections: &'a str,
    sent: u64,
    received: u64,
    lost: u64,
    avg_rtt_ms: f64,
    p95_rtt_us: u64,
    bytes_sent: u64,
    wall_ms: u64,
    mbps: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<&'a str>,
}

fn difficulty(r: &DialResult) -> (&'static str, &'static str) {
    if r.punch_upgraded || r.final_path.starts_with("Direct") {
        ("easy", "Easy NAT + No NAT devices")
    } else if r.punch_attempts > 0 || r.fell_back_to_relay || r.final_path.starts_with("Relayed") {
        ("hard", "No NAT devices only (relay required)")
    } else {
        ("unknown", "Unknown")
    }
}

fn dial_json<'a>(r: &'a DialResult, transport: &'a str, target: &'a str) -> DialJson<'a> {
    let (diff, direct) = difficulty(r);
    DialJson {
        ok: r.ok,
        event: "dial",
        name: &r.name,
        target,
        us: &r.us,
        transport,
        first_path: &r.first_path,
        final_path: &r.final_path,
        punch_attempts: r.punch_attempts,
        punch_upgraded: r.punch_upgraded,
        fell_back_to_relay: r.fell_back_to_relay,
        difficulty: diff,
        direct_connections: direct,
        sent: r.sent,
        received: r.received,
        lost: r.lost,
        avg_rtt_ms: r.avg_echo_rtt(),
        p95_rtt_us: r.percentile_echo_rtt_us(0.95),
        bytes_sent: r.bytes_sent,
        wall_ms: r.wall_ms,
        mbps: r.mbps(),
        error: r.error.as_deref(),
    }
}

fn print_dial_cards(r: &DialResult) {
    let (diff, direct) = difficulty(r);
    let diff_label = match diff {
        "easy" => "Easy",
        "hard" => "Hard",
        _ => "Unknown",
    };
    let status = match diff {
        "easy" => "Direct path. Punch landed or you were already public.",
        "hard" => "Stayed Relayed. This NAT pair needs the hop.",
        _ => "No punch data. Direct dial or the path never came up.",
    };

    println!();
    println!("  Path");
    println!("  ----");
    if !r.first_path.is_empty() {
        println!("  first:            {}", r.first_path);
        println!("  final:            {}", r.final_path);
        println!("  punch attempts:   {}", r.punch_attempts);
        println!(
            "  upgraded:         {}",
            if r.punch_upgraded { "yes" } else { "no" }
        );
        println!(
            "  fell back:        {}",
            if r.fell_back_to_relay { "yes" } else { "no" }
        );
    } else {
        println!("  (no NAT path; loopback/direct dial)");
    }
    println!("  difficulty:       {diff_label}");
    println!("  direct:           {direct}");
    println!();
    println!("  Echo");
    println!("  ----");
    println!(
        "  frames:           {}/{}  lost {}",
        r.received, r.sent, r.lost
    );
    println!(
        "  rtt:              {:.1} ms avg   p95 {} us",
        r.avg_echo_rtt(),
        r.percentile_echo_rtt_us(0.95)
    );
    println!(
        "  throughput:       {:.2} Mbps   {} bytes in {} ms",
        r.mbps(),
        r.bytes_sent,
        r.wall_ms
    );
    println!("  ok:               {}", r.ok);
    if let Some(err) = &r.error {
        println!("  error:            {err}");
    }
    println!();
    println!("  {status}");
    println!();
}

fn cmd_suite(
    out: PathBuf,
    deep: bool,
    gossip: bool,
    nat: bool,
    transport: TransportKind,
    relay: Option<String>,
    json: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let relay = resolve_relay(relay, transport)?;
    if json {
        eprintln!("[suite] --json writes the usual reports/; stdout is the run dir when done");
    }
    suite::run_suite(SuiteArgs {
        out_dir: out,
        deep,
        gossip,
        nat,
        transport,
        relay,
    })
}

#[cfg(test)]
mod cli_parse {
    use super::*;

    #[test]
    fn relay_flag_does_not_eat_peer_id() {
        let cli = Cli::try_parse_from([
            "spar",
            "dial",
            "--relay",
            "12D3KooWN2XgqhhWMfxAZPNoDLjtYsKFvpjGWuZMEdZ3RMTTHaa4",
            "-n",
            "10",
        ])
        .expect("parse");
        match cli.command {
            Command::Dial {
                target, relay, count, ..
            } => {
                assert_eq!(
                    target,
                    "12D3KooWN2XgqhhWMfxAZPNoDLjtYsKFvpjGWuZMEdZ3RMTTHaa4"
                );
                assert_eq!(relay.as_deref(), Some("public"));
                assert_eq!(count, 10);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn relay_equals_sets_custom_hop() {
        let cli = Cli::try_parse_from([
            "spar",
            "dial",
            "--relay=/dns4/hop.example/udp/1/quic-v1",
            "12D3KooWN2XgqhhWMfxAZPNoDLjtYsKFvpjGWuZMEdZ3RMTTHaa4",
        ])
        .expect("parse");
        match cli.command {
            Command::Dial { target, relay, .. } => {
                assert_eq!(
                    target,
                    "12D3KooWN2XgqhhWMfxAZPNoDLjtYsKFvpjGWuZMEdZ3RMTTHaa4"
                );
                assert_eq!(relay.as_deref(), Some("/dns4/hop.example/udp/1/quic-v1"));
            }
            other => panic!("{other:?}"),
        }
    }
}
