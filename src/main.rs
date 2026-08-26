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

use common::{
    parse_dial_target, run_dial_collect, run_dial_nat, run_listen_loop, run_listen_relay, DialOpts,
    DialTarget, TransportKind,
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
  spar listen
  spar dial /ip4/127.0.0.1/udp/PORT/quic-v1/p2p/PEER
  spar listen --relay
  spar dial --relay 12D3KooW... -n 10 -p 4k
  spar suite --nat --gossip
  spar suite --relay

Bare --relay uses relay.minip2p.com (QUIC or TCP matching -t).
Dial accepts a direct multiaddr, a full /p2p-circuit/ addr, or a raw peer id with --relay."
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
    /// Accept echo streams. --relay reserves on a hop and prints circuit=.
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
    let result = match cli.command {
        Command::Listen { bind, relay } => cmd_listen(bind, transport, relay),
        Command::Dial {
            target,
            relay,
            count,
            interval,
            payload,
            ping,
        } => cmd_dial(target, transport, relay, count, interval, payload, ping),
        Command::Suite {
            out,
            deep,
            gossip,
            nat,
            relay,
        } => cmd_suite(out, deep, gossip, nat, transport, relay),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}

fn cmd_listen(
    bind: String,
    transport: TransportKind,
    relay: Option<String>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let relay = resolve_relay(relay, transport)?;
    let stop = Arc::new(AtomicBool::new(false));
    let stop2 = Arc::clone(&stop);
    if let Some(relay) = relay {
        let (tx, rx) = mpsc::channel::<String>();
        let handle = thread::spawn(move || run_listen_relay(&bind, transport, relay, stop2, tx));
        while let Ok(line) = rx.recv_timeout(Duration::from_secs(25)) {
            println!("[listen] {line}");
            if line.starts_with("circuit=") || line.starts_with("warn=") {
                break;
            }
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
        if let Ok(addr) = rx.recv() {
            println!("[listen] us={}", addr.peer_id());
            println!("[listen] addr={addr}");
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
            quiet: false,
            name: "cli-dial".into(),
            max_echo_duration: None,
            rtt_sample_stride: 1,
            transport,
        })
    };
    println!(
        "[dial] summary name={} ok={} sent={} received={} lost={} avg_rtt_us={:.1} avg_rtt_ms={:.3} p95_us={} bytes_sent={} wall_ms={}",
        r.name,
        r.ok,
        r.sent,
        r.received,
        r.lost,
        r.avg_echo_rtt_us(),
        r.avg_echo_rtt(),
        r.percentile_echo_rtt_us(0.95),
        r.bytes_sent,
        r.wall_ms
    );
    if let Some(err) = &r.error {
        eprintln!("[dial] note: {err}");
    }
    if r.ok {
        Ok(())
    } else {
        Err(r.error.unwrap_or_else(|| "dial failed".into()).into())
    }
}

fn cmd_suite(
    out: PathBuf,
    deep: bool,
    gossip: bool,
    nat: bool,
    transport: TransportKind,
    relay: Option<String>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let relay = resolve_relay(relay, transport)?;
    suite::run_suite(SuiteArgs {
        out_dir: out,
        deep,
        gossip,
        nat,
        transport,
        relay,
    })
}
