//! Sync soak suite + report writer. Uses std::thread / mpsc only — no async.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use minip2p::PeerAddr;

use crate::common::{
    avg, percentile, run_dial_collect, run_listen_loop, run_reconnect_once, run_reconnect_once_ex, run_stream_churn,
    sample_mem, DialOpts, DialResult, MemSample, TransportKind,
};
use minip2p::Ed25519Keypair;

pub struct SuiteArgs {
    pub out_dir: PathBuf,
    pub deep: bool,
    pub stress: bool,
    pub gossip: bool,
    pub nat: bool,
    pub transport: TransportKind,
}

pub fn run_suite(args: SuiteArgs) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let out_dir = &args.out_dir;
    fs::create_dir_all(out_dir)?;
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let run_dir = out_dir.join(format!("run-{stamp}"));
    fs::create_dir_all(&run_dir)?;

    let transport = args.transport;
    let skip_echo = (args.gossip || args.nat) && !args.deep && !args.stress;
    let stop = Arc::new(AtomicBool::new(false));
    let mut listener = None;
    let mut listen_addr: Option<PeerAddr> = None;
    if !skip_echo {
        let (addr_tx, addr_rx) = mpsc::channel::<PeerAddr>();
        let stop_l = Arc::clone(&stop);
        listener = Some(
            thread::Builder::new()
                .name("spar-listen".into())
                .spawn(move || run_listen_loop("127.0.0.1:0", transport, stop_l, addr_tx))?,
        );
        let addr = addr_rx.recv_timeout(Duration::from_secs(5))?;
        eprintln!(
            "[suite] listener ready at {addr} (deep={} stress={} gossip={} nat={} transport={})",
            args.deep,
            args.stress,
            args.gossip,
            args.nat,
            transport.as_str()
        );
        listen_addr = Some(addr);
    } else {
        eprintln!(
            "[suite] {}-only (transport={})",
            match (args.gossip, args.nat) {
                (true, true) => "gossip+nat",
                (true, false) => "gossip",
                (false, true) => "nat",
                (false, false) => "echo",
            },
            transport.as_str()
        );
    }

    let suite_t0 = Instant::now();
    let mem_log: Arc<Mutex<Vec<(MemSample, String)>>> = Arc::new(Mutex::new(Vec::new()));
    record_mem(&mem_log, suite_t0, "suite-start");

    // Background sampler every ~2s for deep runs (same PID as dialers/listener).
    let sampler_stop = Arc::new(AtomicBool::new(false));
    let sampler = if args.deep {
        let mem_log = Arc::clone(&mem_log);
        let stop_s = Arc::clone(&sampler_stop);
        Some(thread::Builder::new().name("spar-mem".into()).spawn(move || {
            while !stop_s.load(Ordering::SeqCst) {
                thread::sleep(Duration::from_secs(2));
                if stop_s.load(Ordering::SeqCst) {
                    break;
                }
                record_mem(&mem_log, suite_t0, "periodic-2s");
            }
        })?)
    } else {
        None
    };

    let mut results: Vec<DialResult> = Vec::new();
    let mut churn_mem_start: Option<MemSample> = None;
    let mut churn_mem_end: Option<MemSample> = None;

    if let Some(addr) = listen_addr.clone() {

    // --- short smoke (always) ---
    results.push(run_named(
        "baseline-echo-100x16B",
        &addr,
        100,
        Duration::from_millis(0),
        0,
        0,
        None,
        1,
        &mem_log,
        suite_t0,
    transport,
    ));
    results.push(run_named(
        "builtin-ping-20",
        &addr,
        0,
        Duration::from_millis(0),
        0,
        20,
        None,
        1,
        &mem_log,
        suite_t0,
    transport,
    ));
    results.push(run_named(
        "echo-50x4KiB",
        &addr,
        50,
        Duration::from_millis(0),
        4 * 1024,
        0,
        None,
        1,
        &mem_log,
        suite_t0,
    transport,
    ));
    results.push(run_named(
        "echo-20x64KiB",
        &addr,
        20,
        Duration::from_millis(0),
        64 * 1024,
        0,
        None,
        1,
        &mem_log,
        suite_t0,
    transport,
    ));
    results.push(run_named(
        "burst-echo-500x16B",
        &addr,
        500,
        Duration::from_millis(0),
        0,
        0,
        None,
        1,
        &mem_log,
        suite_t0,
    transport,
    ));
    results.push(run_named(
        "paced-echo-50x1KiB-10ms",
        &addr,
        50,
        Duration::from_millis(10),
        1024,
        0,
        None,
        1,
        &mem_log,
        suite_t0,
    transport,
    ));
    let conc = run_concurrent(&addr, 4, 40, 1024, transport)?;
    record_mem(&mem_log, suite_t0, "after-concurrent-4x40");
    results.extend(conc);

    if args.deep {
        // long-echo-10000x64B (header 16 + 64 payload)
        results.push(run_named(
            "long-echo-10000x64B",
            &addr,
            10_000,
            Duration::from_millis(0),
            64,
            0,
            None,
            1,
            &mem_log,
            suite_t0,
        transport,
        ));

        results.push(run_named(
            "long-echo-2000x4KiB",
            &addr,
            2_000,
            Duration::from_millis(0),
            4 * 1024,
            0,
            None,
            1,
            &mem_log,
            suite_t0,
        transport,
        ));

        results.push(run_named(
            "long-echo-500x64KiB",
            &addr,
            500,
            Duration::from_millis(0),
            64 * 1024,
            0,
            None,
            1,
            &mem_log,
            suite_t0,
        transport,
        ));

        // reconnect-churn-200
        eprintln!("[suite] running reconnect-churn-200 …");
        let churn_t0 = Instant::now();
        churn_mem_start = sample_mem(suite_t0);
        if let Some(s) = &churn_mem_start {
            push_labeled(&mem_log, s.clone(), "reconnect-churn-start");
        }
        let mut churn = DialResult {
            name: "reconnect-churn-200".into(),
            ok: true,
            error: None,
            dial_ms: 0,
            identify_ms: 0,
            echo_open_ms: 0,
            wall_ms: 0,
            sent: 0,
            received: 0,
            lost: 0,
            bytes_sent: 0,
            bytes_recv: 0,
            builtin_ping_rtts_ms: Vec::new(),
            echo_rtts_us: Vec::new(),
            echo_rtt_samples_stored: 0,
        };
        let payload = 1024usize;
        let echoes_per = 5u64;
        for i in 0..200u64 {
            match run_reconnect_once(&addr, echoes_per, payload, transport) {
                Ok((sent, recv, rtts)) => {
                    churn.sent += sent;
                    churn.received += recv;
                    churn.lost += sent.saturating_sub(recv);
                    churn.bytes_sent += sent * (16 + payload as u64);
                    churn.bytes_recv += recv * (16 + payload as u64);
                    for r in rtts {
                        if churn.echo_rtts_us.len() < crate::common::MAX_RTT_SAMPLES {
                            churn.echo_rtts_us.push(r);
                        }
                    }
                    if sent != recv {
                        churn.ok = false;
                        churn.error = Some(format!("iter {i}: lost {}", sent - recv));
                    }
                }
                Err(e) => {
                    churn.ok = false;
                    churn.error = Some(format!("iter {i}: {e}"));
                    break;
                }
            }
            if i % 20 == 19 {
                record_mem(&mem_log, suite_t0, &format!("reconnect-churn-iter-{}", i + 1));
            }
        }
        churn.wall_ms = churn_t0.elapsed().as_millis() as u64;
        churn.echo_rtt_samples_stored = churn.echo_rtts_us.len() as u64;
        if churn.lost > 0 && churn.error.is_none() {
            churn.ok = false;
            churn.error = Some(format!("lost {} frames", churn.lost));
        }
        churn_mem_end = sample_mem(suite_t0);
        if let Some(s) = &churn_mem_end {
            push_labeled(&mem_log, s.clone(), "reconnect-churn-end");
        }
        eprintln!(
            "[suite] reconnect-churn-200 ok={} lost={} avg_rtt_us={:.1} wall_ms={} ({:.1}s)",
            churn.ok,
            churn.lost,
            churn.avg_echo_rtt_us(),
            churn.wall_ms,
            churn_t0.elapsed().as_secs_f64()
        );
        results.push(churn);

        // soak-steady-30s: continuous 1KiB echoes for ~30s; stride RTT samples
        results.push(run_named(
            "soak-steady-30s",
            &addr,
            u64::MAX / 4,
            Duration::from_micros(200), // light pacing + outstanding cap avoids quiche queue exhaustion
            1024,
            0,
            Some(Duration::from_secs(30)),
            10,
            &mem_log,
            suite_t0,
        transport,
        ));

        // concurrent-8x200x1KiB
        eprintln!("[suite] running concurrent-8x200x1KiB …");
        let conc8 = run_concurrent(&addr, 8, 200, 1024, transport)?;
        record_mem(&mem_log, suite_t0, "after-concurrent-8x200");
        results.extend(conc8);
    }

    if args.stress {
        // soak-steady-180s: same backpressure as 30s soak, longer wall
        results.push(run_named(
            "soak-steady-180s",
            &addr,
            u64::MAX / 4,
            Duration::from_micros(200),
            1024,
            0,
            Some(Duration::from_secs(180)),
            10,
            &mem_log,
            suite_t0,
            transport,
        ));

        eprintln!("[suite] running stream-churn-80 …");
        let sc_t0 = Instant::now();
        record_mem(&mem_log, suite_t0, "stream-churn-start");
        let rss_before = sample_mem(suite_t0);
        let mut stream_churn = DialResult::blank("stream-churn-80");
        let payload = 256usize;
        let echoes_per = 3u64;
        let n_streams = 80u64;
        match run_stream_churn(&addr, n_streams, echoes_per, payload, transport) {
            Ok((sent, recv, rtts)) => {
                stream_churn.sent = sent;
                stream_churn.received = recv;
                stream_churn.lost = sent.saturating_sub(recv);
                stream_churn.bytes_sent = sent * (16 + payload as u64);
                stream_churn.bytes_recv = recv * (16 + payload as u64);
                stream_churn.echo_rtts_us = rtts;
                stream_churn.echo_rtt_samples_stored = stream_churn.echo_rtts_us.len() as u64;
                if stream_churn.lost > 0 {
                    stream_churn.ok = false;
                    stream_churn.error = Some(format!("lost {} frames", stream_churn.lost));
                }
            }
            Err(e) => {
                stream_churn.ok = false;
                stream_churn.error = Some(e.to_string());
            }
        }
        stream_churn.wall_ms = sc_t0.elapsed().as_millis() as u64;
        let rss_after = sample_mem(suite_t0);
        record_mem(&mem_log, suite_t0, "stream-churn-end");
        if let (Some(a), Some(b)) = (&rss_before, &rss_after) {
            let delta = b.rss_kb as i64 - a.rss_kb as i64;
            if delta > 8 * 1024 {
                stream_churn.ok = false;
                let msg = format!(
                    "stream map leak suspect: RSS {}→{} kB (delta {delta} kB)",
                    a.rss_kb, b.rss_kb
                );
                stream_churn.error = Some(match stream_churn.error.take() {
                    Some(prev) => format!("{prev}; {msg}"),
                    None => msg,
                });
            }
        }
        eprintln!(
            "[suite] stream-churn-80 ok={} lost={} avg_rtt_us={:.1} wall_ms={} ({:.1}s)",
            stream_churn.ok,
            stream_churn.lost,
            stream_churn.avg_echo_rtt_us(),
            stream_churn.wall_ms,
            sc_t0.elapsed().as_secs_f64()
        );
        results.push(stream_churn);

        results.push(run_churn_loop(
            "same-peer-reconnect-50",
            50,
            &addr,
            transport,
            Some(Ed25519Keypair::generate()),
            false,
            &mem_log,
            suite_t0,
        ));

        results.push(run_churn_loop(
            "disconnect-churn-50",
            50,
            &addr,
            transport,
            None,
            true,
            &mem_log,
            suite_t0,
        ));
    }

    }

    if args.gossip {
        eprintln!("[suite] running gossip/pubsub scenarios …");
        results.extend(crate::gossip::run_gossip_scenarios(
            transport,
            &mem_log,
            suite_t0,
        ));
    }

    if args.nat {
        eprintln!("[suite] running NAT/circuit scenarios …");
        results.extend(crate::nat::run_nat_scenarios(
            transport,
            &mem_log,
            suite_t0,
        ));
    }

    record_mem(&mem_log, suite_t0, "suite-end");
    sampler_stop.store(true, Ordering::SeqCst);
    if let Some(h) = sampler {
        let _ = h.join();
    }

    let wall_ms = suite_t0.elapsed().as_millis() as u64;
    stop.store(true, Ordering::SeqCst);
    thread::sleep(Duration::from_millis(200));
    if let Some(h) = listener {
        let _ = h.join();
    }

    let mem_samples = mem_log.lock().unwrap().clone();
    let mem_csv = run_dir.join("memory.csv");
    write_memory_csv(&mem_csv, &mem_samples)?;

    let md_path = run_dir.join("report.md");
    let json_path = run_dir.join("report.json");
    let target = match &listen_addr {
        Some(a) => a.to_string(),
        None => {
            let mut parts = vec![format!("loopback {}", transport.as_str())];
            if args.nat {
                parts.push("nat/circuit".into());
            }
            if args.gossip {
                parts.push(format!("gossipsub {}", crate::gossip::GOSSIP_TOPIC));
            }
            parts.join(" ")
        }
    };
    write_markdown(
        &md_path,
        &target,
        wall_ms,
        &results,
        &mem_samples,
        args.deep,
        args.stress,
        args.gossip,
        args.nat,
        transport,
        churn_mem_start.as_ref(),
        churn_mem_end.as_ref(),
    )?;
    write_json(
        &json_path,
        &target,
        wall_ms,
        &results,
        &mem_samples,
        args.deep,
        args.stress,
        args.gossip,
        args.nat,
        transport,
        churn_mem_start.as_ref(),
        churn_mem_end.as_ref(),
    )?;

    println!("[suite] wrote {}", md_path.display());
    println!("[suite] wrote {}", json_path.display());
    println!("[suite] wrote {}", mem_csv.display());
    println!(
        "[suite] wall_ms={wall_ms} scenarios={} deep={} stress={} gossip={} nat={} transport={}",
        results.len(),
        args.deep,
        args.stress,
        args.gossip,
        args.nat,
        transport.as_str()
    );

    let failed = results.iter().filter(|r| !r.ok).count();
    if failed > 0 {
        Err(format!("{failed} scenario(s) failed").into())
    } else {
        Ok(())
    }
}

fn run_churn_loop(
    name: &str,
    iterations: u64,
    addr: &minip2p::PeerAddr,
    transport: TransportKind,
    identity: Option<Ed25519Keypair>,
    disconnect: bool,
    mem_log: &Arc<Mutex<Vec<(MemSample, String)>>>,
    suite_t0: Instant,
) -> DialResult {
    eprintln!("[suite] running {name} …");
    let t0 = Instant::now();
    record_mem(mem_log, suite_t0, &format!("{name}-start"));
    let mut churn = DialResult::blank(name);
    let payload = 1024usize;
    let echoes_per = 5u64;
    for i in 0..iterations {
        match run_reconnect_once_ex(
            addr,
            echoes_per,
            payload,
            transport,
            identity.clone(),
            disconnect,
        ) {
            Ok((sent, recv, rtts)) => {
                churn.sent += sent;
                churn.received += recv;
                churn.lost += sent.saturating_sub(recv);
                churn.bytes_sent += sent * (16 + payload as u64);
                churn.bytes_recv += recv * (16 + payload as u64);
                for r in rtts {
                    if churn.echo_rtts_us.len() < crate::common::MAX_RTT_SAMPLES {
                        churn.echo_rtts_us.push(r);
                    }
                }
                if sent != recv {
                    churn.ok = false;
                    churn.error = Some(format!("iter {i}: lost {}", sent - recv));
                }
            }
            Err(e) => {
                churn.ok = false;
                churn.error = Some(format!("iter {i}: {e}"));
                break;
            }
        }
        if i % 10 == 9 {
            record_mem(mem_log, suite_t0, &format!("{name}-iter-{}", i + 1));
        }
    }
    churn.wall_ms = t0.elapsed().as_millis() as u64;
    churn.echo_rtt_samples_stored = churn.echo_rtts_us.len() as u64;
    if churn.lost > 0 && churn.error.is_none() {
        churn.ok = false;
        churn.error = Some(format!("lost {} frames", churn.lost));
    }
    record_mem(mem_log, suite_t0, &format!("{name}-end"));
    eprintln!(
        "[suite] {name} ok={} lost={} avg_rtt_us={:.1} wall_ms={} ({:.1}s)",
        churn.ok,
        churn.lost,
        churn.avg_echo_rtt_us(),
        churn.wall_ms,
        t0.elapsed().as_secs_f64()
    );
    churn
}

fn record_mem(log: &Arc<Mutex<Vec<(MemSample, String)>>>, t0: Instant, label: &str) {
    if let Some(s) = sample_mem(t0) {
        push_labeled(log, s, label);
    }
}

fn push_labeled(log: &Arc<Mutex<Vec<(MemSample, String)>>>, s: MemSample, label: &str) {
    if let Ok(mut g) = log.lock() {
        g.push((s, label.to_string()));
    }
}

fn run_named(
    name: &str,
    addr: &PeerAddr,
    count: u64,
    interval: Duration,
    payload: usize,
    builtin_ping: u64,
    max_echo_duration: Option<Duration>,
    rtt_sample_stride: u64,
    mem_log: &Arc<Mutex<Vec<(MemSample, String)>>>,
    suite_t0: Instant,
    transport: TransportKind,
) -> DialResult {
    eprintln!("[suite] running {name} …");
    let t0 = Instant::now();
    record_mem(mem_log, suite_t0, &format!("before-{name}"));
    let mut opts = DialOpts::basic(name, addr.clone(), count, interval, payload, builtin_ping);
    opts.max_echo_duration = max_echo_duration;
    opts.rtt_sample_stride = rtt_sample_stride;
    opts.transport = transport;
    let mut r = run_dial_collect(opts);
    if count == 0 && builtin_ping > 0 {
        r.ok = r.error.is_none() && r.builtin_ping_rtts_ms.len() as u64 == builtin_ping;
        if !r.ok && r.error.is_none() {
            r.error = Some("builtin ping count mismatch".into());
        }
    }
    // Duration-limited soaks: success if we sent >0 and lost none.
    if max_echo_duration.is_some() {
        r.ok = r.error.is_none() && r.sent > 0 && r.lost == 0 && r.received == r.sent;
        if !r.ok && r.error.is_none() {
            r.error = Some(format!("soak incomplete or lost: sent={} recv={}", r.sent, r.received));
        }
    }
    record_mem(mem_log, suite_t0, &format!("after-{name}"));
    eprintln!(
        "[suite] {name} ok={} lost={} avg_rtt_us={:.1} avg_rtt_ms={:.3} wall_ms={} ({:.1}s)",
        r.ok,
        r.lost,
        r.avg_echo_rtt_us(),
        r.avg_echo_rtt(),
        r.wall_ms,
        t0.elapsed().as_secs_f64()
    );
    r
}

fn run_concurrent(
    addr: &PeerAddr,
    clients: usize,
    count: u64,
    payload: usize,
    transport: TransportKind,
) -> Result<Vec<DialResult>, Box<dyn std::error::Error + Send + Sync>> {
    eprintln!("[suite] running concurrent-{clients}x{count}x{payload}B …");
    let mut handles = Vec::new();
    for i in 0..clients {
        let addr = addr.clone();
        handles.push(
            thread::Builder::new()
                .name(format!("spar-dial-{i}"))
                .spawn(move || {
                    let mut opts = DialOpts::basic(
                        format!("concurrent-{clients}x{count}-client-{i}"),
                        addr,
                        count,
                        Duration::from_millis(0),
                        payload,
                        0,
                    );
                    opts.transport = transport;
                    run_dial_collect(opts)
                })?,
        );
    }
    let mut out = Vec::new();
    for h in handles {
        out.push(h.join().map_err(|_| "dial thread panicked")?);
    }
    Ok(out)
}

fn write_memory_csv(
    path: &Path,
    samples: &[(MemSample, String)],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut s = String::from("t_ms,rss_kb,vsz_kb,label\n");
    for (m, label) in samples {
        s.push_str(&format!(
            "{},{},{},{}\n",
            m.t_ms,
            m.rss_kb,
            m.vsz_kb,
            escape_csv(label)
        ));
    }
    fs::write(path, s)?;
    Ok(())
}

fn escape_csv(s: &str) -> String {
    if s.contains(',') || s.contains('"') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

struct MemVerdict {
    start_rss: u64,
    end_rss: u64,
    peak_rss: u64,
    delta_kb: i64,
    churn_start_rss: Option<u64>,
    churn_end_rss: Option<u64>,
    churn_delta_kb: Option<i64>,
    verdict: String,
    reasoning: String,
}

fn analyze_memory(
    samples: &[(MemSample, String)],
    churn_start: Option<&MemSample>,
    churn_end: Option<&MemSample>,
) -> MemVerdict {
    let start_rss = samples.first().map(|s| s.0.rss_kb).unwrap_or(0);
    let end_rss = samples.last().map(|s| s.0.rss_kb).unwrap_or(0);
    let peak_rss = samples.iter().map(|s| s.0.rss_kb).max().unwrap_or(0);
    let delta_kb = end_rss as i64 - start_rss as i64;

    let churn_start_rss = churn_start.map(|s| s.rss_kb);
    let churn_end_rss = churn_end.map(|s| s.rss_kb);
    let churn_delta_kb = match (churn_start_rss, churn_end_rss) {
        (Some(a), Some(b)) => Some(b as i64 - a as i64),
        _ => None,
    };

    // Look at RSS trend across reconnect samples + overall.
    let verdict;
    let reasoning;

    if let Some(cd) = churn_delta_kb {
        let c_start = churn_start_rss.unwrap_or(0);
        // Climbing significantly through churn → leak suspect.
        // Thresholds: >8 MiB absolute growth OR >25% growth and >2 MiB.
        let pct = if c_start > 0 {
            (cd as f64 / c_start as f64) * 100.0
        } else {
            0.0
        };
        if cd > 8 * 1024 || (cd > 2 * 1024 && pct > 25.0) {
            // Check if still climbing: compare last third of reconnect samples.
            let churn_pts: Vec<_> = samples
                .iter()
                .filter(|(_, l)| l.starts_with("reconnect-churn"))
                .map(|(m, _)| m.rss_kb)
                .collect();
            let climbing = if churn_pts.len() >= 3 {
                let mid = churn_pts.len() / 2;
                let early_avg = churn_pts[..mid].iter().sum::<u64>() as f64 / mid as f64;
                let late_avg = churn_pts[mid..].iter().sum::<u64>() as f64
                    / (churn_pts.len() - mid) as f64;
                late_avg > early_avg * 1.05
            } else {
                cd > 0
            };
            if climbing {
                verdict = "suspect".into();
                reasoning = format!(
                    "reconnect-churn RSS rose {cd} kB ({pct:.1}%); late samples still above early — LEAK SUSPECT"
                );
            } else {
                verdict = "allocator/cache growth".into();
                reasoning = format!(
                    "reconnect-churn RSS rose {cd} kB but plateaued — likely allocator/cache growth, not a clear leak"
                );
            }
        } else if delta_kb > 4 * 1024 {
            verdict = "allocator/cache growth".into();
            reasoning = format!(
                "suite RSS delta {delta_kb} kB with modest churn delta {cd} kB — consistent with allocator arenas / page cache, not a clear leak"
            );
        } else {
            verdict = "none".into();
            reasoning = format!(
                "RSS start={start_rss} peak={peak_rss} end={end_rss} (delta {delta_kb} kB); churn delta {cd} kB — no leak signal"
            );
        }
    } else if delta_kb > 4 * 1024 {
        verdict = "allocator/cache growth".into();
        reasoning = format!(
            "RSS rose {delta_kb} kB over suite (no churn data) — may be allocator growth; re-run with --deep"
        );
    } else {
        verdict = "none".into();
        reasoning = format!(
            "RSS start={start_rss} peak={peak_rss} end={end_rss} (delta {delta_kb} kB) — no leak signal"
        );
    }

    MemVerdict {
        start_rss,
        end_rss,
        peak_rss,
        delta_kb,
        churn_start_rss,
        churn_end_rss,
        churn_delta_kb,
        verdict,
        reasoning,
    }
}

fn mode_label(deep: bool, stress: bool, gossip: bool, nat: bool) -> String {
    let base = if stress {
        "stress"
    } else if deep {
        "deep"
    } else if nat && gossip {
        "nat+gossip"
    } else if nat {
        "nat"
    } else if gossip {
        "gossip"
    } else {
        "short"
    };
    if (gossip || nat) && (deep || stress) {
        let mut prefix = String::new();
        if nat {
            prefix.push_str("nat+");
        }
        if gossip {
            prefix.push_str("gossip+");
        }
        format!("{prefix}{base}")
    } else {
        base.to_string()
    }
}

fn rss_labeled(samples: &[(MemSample, String)], label: &str) -> Option<u64> {
    samples.iter().rev().find(|(_, l)| l == label).map(|(m, _)| m.rss_kb)
}

fn write_markdown(
    path: &Path,
    target: &str,
    wall_ms: u64,
    results: &[DialResult],
    mem_samples: &[(MemSample, String)],
    deep: bool,
    stress: bool,
    gossip: bool,
    nat: bool,
    transport: TransportKind,
    churn_start: Option<&MemSample>,
    churn_end: Option<&MemSample>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let passed = results.iter().filter(|r| r.ok).count();
    let failed = results.len() - passed;
    let mem = analyze_memory(mem_samples, churn_start, churn_end);

    let mut md = String::new();
    md.push_str("# spar soak report (minip2p)\n\n");
    md.push_str(&format!("- **Target:** `{target}`\n"));
    md.push_str("- **Runtime:** sync Rust only (`std::thread` / `mpsc`), no Tokio/async\n");
    md.push_str(&format!("- **Stack:** `{}`\n", transport.stack_label_with_features(gossip, nat)));
    md.push_str(&format!("- **Transport:** {}\n", transport.as_str()));
    md.push_str(&format!("- **Mode:** {}\n", mode_label(deep, stress, gossip, nat)));
    md.push_str(&format!("- **Suite wall time:** {wall_ms} ms ({:.1} s)\n", wall_ms as f64 / 1000.0));
    md.push_str(&format!(
        "- **Scenarios:** {} passed / {} failed / {} total\n\n",
        passed,
        failed,
        results.len()
    ));

    md.push_str("## Summary\n\n");
    md.push_str("| Scenario | OK | Sent | Recv | Lost | Avg RTT µs | Avg RTT ms | p50 µs | p95 µs | p99 µs | Mbps (send) | Dial ms | Identify ms | Notes |\n");
    md.push_str("|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|\n");
    for r in results {
        let note = r.error.clone().unwrap_or_default().replace('|', "/");
        md.push_str(&format!(
            "| {} | {} | {} | {} | {} | {:.1} | {:.3} | {} | {} | {} | {:.2} | {} | {} | {} |\n",
            r.name,
            if r.ok { "yes" } else { "NO" },
            r.sent,
            r.received,
            r.lost,
            r.avg_echo_rtt_us(),
            r.avg_echo_rtt(),
            r.percentile_echo_rtt_us(0.50),
            r.percentile_echo_rtt_us(0.95),
            r.percentile_echo_rtt_us(0.99),
            r.mbps(),
            r.dial_ms,
            r.identify_ms,
            note,
        ));
    }

    md.push_str("\n## Memory\n\n");
    md.push_str(&format!("- **Start RSS:** {} kB\n", mem.start_rss));
    md.push_str(&format!("- **Peak RSS:** {} kB\n", mem.peak_rss));
    md.push_str(&format!("- **End RSS:** {} kB\n", mem.end_rss));
    md.push_str(&format!("- **Delta (end−start):** {} kB\n", mem.delta_kb));
    if let (Some(a), Some(b), Some(d)) = (mem.churn_start_rss, mem.churn_end_rss, mem.churn_delta_kb) {
        md.push_str(&format!("- **Reconnect-churn RSS start→end:** {a} → {b} kB (delta {d} kB)\n"));
    }
    for (label, pretty) in [
        ("stream-churn", "Stream-churn"),
        ("same-peer-reconnect-50", "Same-peer-reconnect"),
        ("disconnect-churn-50", "Disconnect-churn"),
        ("soak-steady-180s", "Soak-steady-180s"),
        ("gossip-fanout-200", "Gossip-fanout-200"),
    ] {
        let start = rss_labeled(mem_samples, &format!("{label}-start"))
            .or_else(|| rss_labeled(mem_samples, &format!("before-{label}")));
        let end = rss_labeled(mem_samples, &format!("{label}-end"))
            .or_else(|| rss_labeled(mem_samples, &format!("after-{label}")));
        if let (Some(a), Some(b)) = (start, end) {
            md.push_str(&format!(
                "- **{pretty} RSS start→end:** {a} → {b} kB (delta {} kB)\n",
                b as i64 - a as i64
            ));
        }
    }
    md.push_str(&format!("- **Samples:** {} (see `memory.csv`)\n", mem_samples.len()));
    md.push_str(&format!("- **Verdict:** `{}`\n", mem.verdict));
    md.push_str(&format!("- **Reasoning:** {}\n", mem.reasoning));
    md.push_str("\nNote: listener + all dialer Endpoints share one process PID; samples are from `/proc/self/status` (VmRSS / VmSize).\n");

    md.push_str("\n## Findings\n\n");
    md.push_str(&findings(results, &mem, deep, stress, gossip, nat));
    md.push_str("\n## Per-scenario detail\n\n");
    for r in results {
        md.push_str(&format!("### {}\n\n", r.name));
        md.push_str(&format!("- ok: {}\n", r.ok));
        if let Some(err) = &r.error {
            md.push_str(&format!("- error: `{err}`\n"));
        }
        md.push_str(&format!(
            "- timing: dial={}ms identify={}ms echo_open={}ms echo_wall={}ms\n",
            r.dial_ms, r.identify_ms, r.echo_open_ms, r.wall_ms
        ));
        md.push_str(&format!(
            "- echo: sent={} recv={} lost={} bytes_sent={} bytes_recv={}\n",
            r.sent, r.received, r.lost, r.bytes_sent, r.bytes_recv
        ));
        if !r.echo_rtts_us.is_empty() {
            md.push_str(&format!(
                "- echo RTT µs: n={} min={} avg={:.1} p50={} p95={} p99={} max={} (ms avg={:.3})\n",
                r.echo_rtt_samples_stored,
                r.echo_rtts_us.iter().copied().min().unwrap_or(0),
                r.avg_echo_rtt_us(),
                r.percentile_echo_rtt_us(0.50),
                r.percentile_echo_rtt_us(0.95),
                r.percentile_echo_rtt_us(0.99),
                r.echo_rtts_us.iter().copied().max().unwrap_or(0),
                r.avg_echo_rtt(),
            ));
        }
        if !r.builtin_ping_rtts_ms.is_empty() {
            md.push_str(&format!(
                "- builtin ping RTT ms (API returns ms only): n={} avg={:.2} p95={} max={}\n",
                r.builtin_ping_rtts_ms.len(),
                avg(&r.builtin_ping_rtts_ms),
                percentile(&r.builtin_ping_rtts_ms, 0.95),
                r.builtin_ping_rtts_ms.iter().copied().max().unwrap_or(0),
            ));
        }
        md.push('\n');
    }

    fs::write(path, md)?;
    Ok(())
}

fn findings(results: &[DialResult], mem: &MemVerdict, deep: bool, stress: bool, gossip: bool, nat: bool) -> String {
    let mut lines = Vec::new();
    let failed: Vec<_> = results.iter().filter(|r| !r.ok).collect();
    if failed.is_empty() {
        lines.push("- All scenarios completed without lost frames or hard errors.".into());
    } else {
        for f in failed {
            lines.push(format!(
                "- **FAIL** `{}`: {}",
                f.name,
                f.error.clone().unwrap_or_else(|| "unknown".into())
            ));
        }
    }

    lines.push(format!("- **Memory verdict:** `{}` — {}", mem.verdict, mem.reasoning));

    if let Some(large) = results
        .iter()
        .filter(|r| r.name.contains("64KiB"))
        .max_by(|a, b| a.sent.cmp(&b.sent))
    {
        let total_lost: u64 = results.iter().map(|r| r.lost).sum();
        lines.push(format!(
            "- Largest 64KiB run `{}`: {:.2} Mbps send-side, p95 RTT {} µs ({:.3} ms), lost={}.",
            large.name,
            large.mbps(),
            large.percentile_echo_rtt_us(0.95),
            large.percentile_echo_rtt(0.95),
            large.lost
        ));
        lines.push(format!("- Total lost frames across suite: {total_lost}."));
    }

    let concurrent: Vec<_> = results
        .iter()
        .filter(|r| r.name.contains("concurrent-"))
        .collect();
    if !concurrent.is_empty() {
        let ok = concurrent.iter().filter(|r| r.ok).count();
        let lost: u64 = concurrent.iter().map(|r| r.lost).sum();
        lines.push(format!(
            "- Concurrent dialers: {ok}/{} clients clean, total lost frames={lost}.",
            concurrent.len()
        ));
    }

    if let Some(churn) = results.iter().find(|r| r.name.contains("reconnect-churn")) {
        lines.push(format!(
            "- Reconnect churn: {} iterations worth of dials, sent={} lost={} wall={}ms avg_rtt={:.1}µs.",
            churn.sent / 5,
            churn.sent,
            churn.lost,
            churn.wall_ms,
            churn.avg_echo_rtt_us()
        ));
    }

    for soak in results.iter().filter(|r| r.name.contains("soak-steady")) {
        lines.push(format!(
            "- {}: sent={} in {}ms ({:.1}/s) avg_rtt={:.1}µs lost={}.",
            soak.name,
            soak.sent,
            soak.wall_ms,
            soak.sent as f64 / (soak.wall_ms.max(1) as f64 / 1000.0),
            soak.avg_echo_rtt_us(),
            soak.lost
        ));
    }

    if let Some(sc) = results.iter().find(|r| r.name.contains("stream-churn")) {
        lines.push(format!(
            "- Stream churn: sent={} lost={} wall={}ms avg_rtt={:.1}µs (80 streams × 3×256B on one connection).",
            sc.sent,
            sc.lost,
            sc.wall_ms,
            sc.avg_echo_rtt_us()
        ));
    }
    if let Some(sp) = results.iter().find(|r| r.name.contains("same-peer-reconnect")) {
        lines.push(format!(
            "- Same-peer reconnect (supersede / reused Ed25519Keypair): sent={} lost={} wall={}ms avg_rtt={:.1}µs.",
            sp.sent,
            sp.lost,
            sp.wall_ms,
            sp.avg_echo_rtt_us()
        ));
    }
    if let Some(dc) = results.iter().find(|r| r.name.contains("disconnect-churn")) {
        lines.push(format!(
            "- Disconnect churn (explicit disconnect() then poll before drop): sent={} lost={} wall={}ms avg_rtt={:.1}µs.",
            dc.sent,
            dc.lost,
            dc.wall_ms,
            dc.avg_echo_rtt_us()
        ));
    }
    if stress {
        lines.push("- Stress extras: soak-steady-180s, stream-churn-80 (one connection), same-peer-reconnect-50 (reused Ed25519Keypair / supersede), disconnect-churn-50 (explicit disconnect() vs Drop).".into());
    }

    for g in results.iter().filter(|r| r.name.starts_with("gossip-")) {
        let rate = if g.wall_ms == 0 {
            0.0
        } else {
            g.sent as f64 / (g.wall_ms as f64 / 1000.0)
        };
        lines.push(format!(
            "- {}: ok={} expected_deliveries={} recv={} lost={} wall={}ms avg_delivery={:.1}µs p95={}µs ~{:.1} deliveries/s.",
            g.name,
            g.ok,
            g.sent,
            g.received,
            g.lost,
            g.wall_ms,
            g.avg_echo_rtt_us(),
            g.percentile_echo_rtt_us(0.95),
            rate
        ));
    }

    for nsc in results.iter().filter(|r| r.name.starts_with("nat-")) {
        lines.push(format!(
            "- {}: ok={} sent={} recv={} lost={} wall={}ms avg_rtt={:.1}µs notes={}.",
            nsc.name,
            nsc.ok,
            nsc.sent,
            nsc.received,
            nsc.lost,
            nsc.wall_ms,
            nsc.avg_echo_rtt_us(),
            nsc.error.clone().unwrap_or_default()
        ));
    }

    lines.push("\n### Suspected bottlenecks\n".into());
    lines.push("- **Harness (mitigated):** `FrameBuf::pop` no longer `.to_vec()`s every frame; returns a slice. Listener uses `HashMap<PeerId, HashSet<StreamId>>` and moves `data` into `send_stream` (API still needs owned `Vec<u8>`).".into());
    lines.push("- **Harness:** Prior `PeerId` clones on every HashSet contains for StreamData — reduced via HashMap keyed by PeerId.".into());
    lines.push("- **Harness:** Endpoint-per-dial in reconnect churn is intentional stress; each dial pays transport handshake + identify + stream open. Measured identify/dial costs show up in per-iteration wall time.".into());
    lines.push("- **Library:** Builtin ping API returns **milliseconds only** (`wait_ping_rtt` → `rtt_ms`); sub-ms pings collapse to 0/1. Echo path now uses µs.".into());
    lines.push("- **Library (prior review):** BTreeMap-heavy paths in minip2p swarm/peer maps can add log(n) overhead under many peers/streams vs HashMap.".into());
    lines.push("- **Library:** Identify on every reconnect is mandatory today; churn cost is dominated by handshake+identify, not echo RTT.".into());
    if deep {
        if let Some(long64) = results.iter().find(|r| r.name == "long-echo-500x64KiB") {
            lines.push(format!(
                "- **Measured:** long-echo-500x64KiB throughput {:.2} Mbps, avg RTT {:.1} µs — payload path looks {:?}bound on loopback.",
                long64.mbps(),
                long64.avg_echo_rtt_us(),
                if long64.mbps() > 500.0 { "CPU/copy" } else { "latency" }
            ));
        }
    }
    if !nat {
        lines.push("- Caveat: loopback only — does not exercise NAT/relay/WAN loss.".into());
    }
    if gossip {
        lines.push("- Gossip scenarios drive all endpoints on one thread (round-robin `next_event` + `take_pubsub_events`); pubsub streams must not leak as app StreamReady. Default gossipsub, no self-delivery.".into());
        lines.push("- Caveat: loopback gossipsub only — mesh is a star (1 listener, N-1 dial). Not a WAN/relay mesh.".into());
    }
    if nat {
        lines.push("- NAT scenarios drive application endpoints on one thread (round-robin `next_event`); the NAT agent is fed by that poll. `nat-nopath` is a pass when `ConnectFailed`/`NoPathAvailable` (or `wait_path` None). Circuit uses a vendored loopback RelayServer (HOP/STOP + byte-copy bridge).".into());
        lines.push("- Caveat: loopback NAT only — DirectDialed is the loopback candidate; circuit is a local RelayServer, not a WAN NAT.".into());
    }
    if !gossip && !nat {
        lines.push("- Caveat: measures sync Endpoint under spar’s echo protocol (QUIC/quiche or TCP/Noise/Yamux), not gossipsub/relay.".into());
    }
    lines.push('\n'.to_string());
    lines.join("\n")
}

fn write_json(
    path: &Path,
    target: &str,
    wall_ms: u64,
    results: &[DialResult],
    mem_samples: &[(MemSample, String)],
    deep: bool,
    stress: bool,
    gossip: bool,
    nat: bool,
    transport: TransportKind,
    churn_start: Option<&MemSample>,
    churn_end: Option<&MemSample>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mem = analyze_memory(mem_samples, churn_start, churn_end);
    let mut s = String::new();
    s.push_str("{\n");
    s.push_str(&format!("  \"target\": \"{}\",\n", escape(target)));
    s.push_str("  \"runtime\": \"sync-std-thread\",\n");
    s.push_str(&format!("  \"stack\": \"{}\",\n", escape(transport.stack_label_with_features(gossip, nat))));
    s.push_str(&format!("  \"transport\": \"{}\",\n", transport.as_str()));
    s.push_str(&format!("  \"deep\": {},\n", deep));
    s.push_str(&format!("  \"stress\": {},\n", stress));
    s.push_str(&format!("  \"gossip\": {},\n", gossip));
    s.push_str(&format!("  \"nat\": {},\n", nat));
    s.push_str(&format!("  \"mode\": \"{}\",\n", mode_label(deep, stress, gossip, nat)));
    s.push_str(&format!("  \"suite_wall_ms\": {wall_ms},\n"));
    s.push_str("  \"memory\": {\n");
    s.push_str(&format!("    \"start_rss_kb\": {},\n", mem.start_rss));
    s.push_str(&format!("    \"peak_rss_kb\": {},\n", mem.peak_rss));
    s.push_str(&format!("    \"end_rss_kb\": {},\n", mem.end_rss));
    s.push_str(&format!("    \"delta_kb\": {},\n", mem.delta_kb));
    s.push_str(&format!(
        "    \"churn_start_rss_kb\": {},\n",
        mem.churn_start_rss
            .map(|x| x.to_string())
            .unwrap_or_else(|| "null".into())
    ));
    s.push_str(&format!(
        "    \"churn_end_rss_kb\": {},\n",
        mem.churn_end_rss
            .map(|x| x.to_string())
            .unwrap_or_else(|| "null".into())
    ));
    s.push_str(&format!(
        "    \"churn_delta_kb\": {},\n",
        mem.churn_delta_kb
            .map(|x| x.to_string())
            .unwrap_or_else(|| "null".into())
    ));
    s.push_str(&format!("    \"verdict\": \"{}\",\n", escape(&mem.verdict)));
    s.push_str(&format!("    \"reasoning\": \"{}\",\n", escape(&mem.reasoning)));
    s.push_str("    \"samples\": [\n");
    for (i, (m, label)) in mem_samples.iter().enumerate() {
        s.push_str(&format!(
            "      {{\"t_ms\": {}, \"rss_kb\": {}, \"vsz_kb\": {}, \"label\": \"{}\"}}",
            m.t_ms,
            m.rss_kb,
            m.vsz_kb,
            escape(label)
        ));
        if i + 1 != mem_samples.len() {
            s.push(',');
        }
        s.push('\n');
    }
    s.push_str("    ]\n");
    s.push_str("  },\n");
    s.push_str("  \"scenarios\": [\n");
    for (i, r) in results.iter().enumerate() {
        s.push_str("    {\n");
        s.push_str(&format!("      \"name\": \"{}\",\n", escape(&r.name)));
        s.push_str(&format!("      \"ok\": {},\n", r.ok));
        s.push_str(&format!(
            "      \"error\": {},\n",
            r.error
                .as_ref()
                .map(|e| format!("\"{}\"", escape(e)))
                .unwrap_or_else(|| "null".into())
        ));
        s.push_str(&format!("      \"dial_ms\": {},\n", r.dial_ms));
        s.push_str(&format!("      \"identify_ms\": {},\n", r.identify_ms));
        s.push_str(&format!("      \"echo_open_ms\": {},\n", r.echo_open_ms));
        s.push_str(&format!("      \"wall_ms\": {},\n", r.wall_ms));
        s.push_str(&format!("      \"sent\": {},\n", r.sent));
        s.push_str(&format!("      \"received\": {},\n", r.received));
        s.push_str(&format!("      \"lost\": {},\n", r.lost));
        s.push_str(&format!("      \"bytes_sent\": {},\n", r.bytes_sent));
        s.push_str(&format!("      \"bytes_recv\": {},\n", r.bytes_recv));
        s.push_str(&format!("      \"mbps_send\": {:.4},\n", r.mbps()));
        s.push_str(&format!("      \"echo_rtt_avg_us\": {:.4},\n", r.avg_echo_rtt_us()));
        s.push_str(&format!("      \"echo_rtt_avg_ms\": {:.6},\n", r.avg_echo_rtt()));
        s.push_str(&format!(
            "      \"echo_rtt_p50_us\": {},\n",
            r.percentile_echo_rtt_us(0.50)
        ));
        s.push_str(&format!(
            "      \"echo_rtt_p95_us\": {},\n",
            r.percentile_echo_rtt_us(0.95)
        ));
        s.push_str(&format!(
            "      \"echo_rtt_p99_us\": {},\n",
            r.percentile_echo_rtt_us(0.99)
        ));
        s.push_str(&format!(
            "      \"echo_rtt_samples_stored\": {},\n",
            r.echo_rtt_samples_stored
        ));
        s.push_str(&format!(
            "      \"builtin_ping_rtts_ms\": [{}],\n",
            r.builtin_ping_rtts_ms
                .iter()
                .map(|x| x.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ));
        // Cap JSON echo samples to keep file manageable (stats already above).
        let cap = 2000.min(r.echo_rtts_us.len());
        s.push_str(&format!(
            "      \"echo_rtts_us\": [{}]\n",
            r.echo_rtts_us[..cap]
                .iter()
                .map(|x| x.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ));
        s.push_str("    }");
        if i + 1 != results.len() {
            s.push(',');
        }
        s.push('\n');
    }
    s.push_str("  ]\n}\n");
    fs::write(path, s)?;
    Ok(())
}

fn escape(s: impl AsRef<str>) -> String {
    s.as_ref()
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}
