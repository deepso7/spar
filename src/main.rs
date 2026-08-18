//! spar — sync sparring harness for minip2p (no Tokio / no async).

mod common;
mod suite;

use std::env;
use std::path::PathBuf;
use std::process::ExitCode;
use std::str::FromStr;
use std::sync::atomic::AtomicBool;
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::Duration;

use minip2p::PeerAddr;

use common::{run_dial_collect, run_listen_loop, DialOpts, TransportKind};
use suite::SuiteArgs;

fn main() -> ExitCode {
    let mut args: Vec<String> = env::args().skip(1).collect();
    let mut global_transport = TransportKind::Quic;
    while args.first().map(|s| s.as_str()) == Some("--transport") {
        if args.len() < 2 {
            eprintln!("--transport needs quic|tcp");
            usage();
            return ExitCode::from(2);
        }
        match TransportKind::parse(&args[1]) {
            Ok(t) => global_transport = t,
            Err(msg) => {
                eprintln!("{msg}");
                usage();
                return ExitCode::from(2);
            }
        }
        args.drain(0..2);
    }

    let Some(cmd) = args.first().cloned() else {
        usage();
        return ExitCode::from(2);
    };
    let rest = args.into_iter().skip(1);

    let result = match cmd.as_str() {
        "listen" => match parse_listen(rest, global_transport) {
            Ok((bind, transport)) => {
                let stop = Arc::new(AtomicBool::new(false));
                let (tx, rx) = mpsc::channel();
                let stop2 = Arc::clone(&stop);
                let handle = thread::spawn(move || run_listen_loop(&bind, transport, stop2, tx));
                if let Ok(addr) = rx.recv() {
                    println!("[listen] us={}", addr.peer_id());
                    println!("[listen] addr={addr}");
                    eprintln!(
                        "[listen] transport={} echoing (Ctrl-C to stop)",
                        transport.as_str()
                    );
                }
                let _ = handle.join();
                Ok(())
            }
            Err(msg) => {
                eprintln!("{msg}");
                usage();
                return ExitCode::from(2);
            }
        },
        "dial" => match parse_dial(rest, global_transport) {
            Ok(opts) => {
                let r = run_dial_collect(opts);
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
            Err(msg) => {
                eprintln!("{msg}");
                usage();
                return ExitCode::from(2);
            }
        },
        "suite" => match parse_suite(rest, global_transport) {
            Ok(suite_args) => suite::run_suite(suite_args),
            Err(msg) => {
                eprintln!("{msg}");
                usage();
                return ExitCode::from(2);
            }
        },
        "help" | "-h" | "--help" => {
            usage();
            return ExitCode::SUCCESS;
        }
        other => {
            eprintln!("unknown command: {other}");
            usage();
            return ExitCode::from(2);
        }
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}

fn usage() {
    eprintln!(
        "\
spar — sync sparring harness for minip2p (no Tokio/async)

Usage:
  spar [--transport quic|tcp] listen [--bind HOST:PORT]
  spar [--transport quic|tcp] dial <peer-multiaddr> [--count N] [--interval MS] [--payload N] [--builtin-ping N]
  spar [--transport quic|tcp] suite [--out DIR] [--deep]

  --transport quic|tcp   wire transport (default quic). Listener + dialers must match.

Dial: --count N (5)  --interval MS (200)  --payload extra bytes (0)  --builtin-ping N (0)
Suite writes reports/run-<stamp>/report.md, report.json, memory.csv
Default is a short echo suite. --deep adds long echoes, reconnect-churn-200, 30s soak."
    );
}

fn parse_listen(
    mut args: impl Iterator<Item = String>,
    mut transport: TransportKind,
) -> Result<(String, TransportKind), String> {
    let mut bind = "127.0.0.1:0".to_string();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--bind" => {
                bind = args.next().ok_or_else(|| "--bind needs a value".to_string())?;
            }
            "--transport" => {
                let v = args.next().ok_or_else(|| "--transport needs quic|tcp".to_string())?;
                transport = TransportKind::parse(&v)?;
            }
            other => return Err(format!("unknown listen option: {other}")),
        }
    }
    Ok((bind, transport))
}

fn parse_suite(
    mut args: impl Iterator<Item = String>,
    mut transport: TransportKind,
) -> Result<SuiteArgs, String> {
    let mut out = PathBuf::from("reports");
    let mut deep = false;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--out" => {
                out = args
                    .next()
                    .map(PathBuf::from)
                    .ok_or_else(|| "--out needs a value".to_string())?;
            }
            "--deep" => deep = true,
            "--transport" => {
                let v = args.next().ok_or_else(|| "--transport needs quic|tcp".to_string())?;
                transport = TransportKind::parse(&v)?;
            }
            other => return Err(format!("unknown suite option: {other}")),
        }
    }
    Ok(SuiteArgs {
        out_dir: out,
        deep,
        transport,
    })
}

fn parse_dial(
    mut args: impl Iterator<Item = String>,
    mut transport: TransportKind,
) -> Result<DialOpts, String> {
    let Some(addr_s) = args.next() else {
        return Err("dial requires a peer multiaddr".into());
    };
    let addr = PeerAddr::from_str(&addr_s).map_err(|e| format!("bad peer addr: {e}"))?;
    let mut count = 5u64;
    let mut interval_ms = 200u64;
    let mut payload = 0usize;
    let mut builtin_ping = 0u64;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--count" => {
                count = args
                    .next()
                    .ok_or("--count needs a value")?
                    .parse()
                    .map_err(|_| "bad --count")?
            }
            "--interval" => {
                interval_ms = args
                    .next()
                    .ok_or("--interval needs a value")?
                    .parse()
                    .map_err(|_| "bad --interval")?
            }
            "--payload" => {
                payload = args
                    .next()
                    .ok_or("--payload needs a value")?
                    .parse()
                    .map_err(|_| "bad --payload")?
            }
            "--builtin-ping" => {
                builtin_ping = args
                    .next()
                    .ok_or("--builtin-ping needs a value")?
                    .parse()
                    .map_err(|_| "bad --builtin-ping")?
            }
            "--transport" => {
                let v = args.next().ok_or("--transport needs quic|tcp")?;
                transport = TransportKind::parse(&v)?;
            }
            other => return Err(format!("unknown dial option: {other}")),
        }
    }
    Ok(DialOpts {
        addr,
        count,
        interval: Duration::from_millis(interval_ms),
        payload,
        builtin_ping,
        quiet: false,
        name: "cli-dial".into(),
        max_echo_duration: None,
        rtt_sample_stride: 1,
        transport,
    })
}
