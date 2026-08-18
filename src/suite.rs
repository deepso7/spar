//! Sync soak suite + report writer. Uses std::thread / mpsc only — no async.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use minip2p::PeerAddr;

use crate::common::{
    avg, percentile, run_dial_collect, run_listen_loop, run_reconnect_once, sample_mem, DialOpts,
    DialResult, MemSample, TransportKind, MAX_RTT_SAMPLES, STACK,
};

pub struct SuiteArgs {
    pub out_dir: PathBuf,
    pub deep: bool,
    pub transport: TransportKind,
}

pub fn run_suite(args: SuiteArgs) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    fs::create_dir_all(&args.out_dir)?;
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let run_dir = args.out_dir.join(format!("run-{stamp}"));
    fs::create_dir_all(&run_dir)?;

    let transport = args.transport;
    let stop = Arc::new(AtomicBool::new(false));
    let (addr_tx, addr_rx) = mpsc::channel::<PeerAddr>();
    let stop_l = Arc::clone(&stop);
    let listener = thread::Builder::new()
        .name("spar-listen".into())
        .spawn(move || run_listen_loop("127.0.0.1:0", transport, stop_l, addr_tx))?;
    let addr = addr_rx.recv_timeout(Duration::from_secs(5))?;
    eprintln!(
        "[suite] listener ready at {addr} (deep={} transport={})",
        args.deep,
        transport.as_str()
    );

    let suite_t0 = Instant::now();
    let mem_log: Arc<Mutex<Vec<(MemSample, String)>>> = Arc::new(Mutex::new(Vec::new()));
    record_mem(&mem_log, suite_t0, "suite-start");

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

    // --- short smoke (always) ---
    for (name, count, interval, payload, ping) in [
        ("baseline-echo-100x16B", 100, 0, 0, 0),
        ("builtin-ping-20", 0, 0, 0, 20),
        ("echo-20x4KiB", 20, 0, 4 * 1024, 0),
        ("echo-10x64KiB", 10, 0, 64 * 1024, 0),
        ("burst-echo-200x16B", 200, 0, 0, 0),
    ] {
        results.push(run_named(
            name,
            &addr,
            count,
            Duration::from_millis(interval),
            payload,
            ping,
            None,
            1,
            &mem_log,
            suite_t0,
            transport,
        ));
    }
    results.extend(run_concurrent(&addr, 4, 20, 1024, transport)?);
    record_mem(&mem_log, suite_t0, "after-concurrent-4x20");

    if args.deep {
        for (name, count, payload) in [
            ("long-echo-2000x64B", 2_000, 64),
            ("long-echo-200x4KiB", 200, 4 * 1024),
            ("long-echo-50x64KiB", 50, 64 * 1024),
        ] {
            results.push(run_named(
                name,
                &addr,
                count,
                Duration::from_millis(0),
                payload,
                0,
                None,
                1,
                &mem_log,
                suite_t0,
                transport,
            ));
        }

        eprintln!("[suite] running reconnect-churn-200 …");
        let churn_t0 = Instant::now();
        churn_mem_start = sample_mem(suite_t0);
        if let Some(s) = &churn_mem_start {
            push_labeled(&mem_log, s.clone(), "reconnect-churn-start");
        }
        let mut churn = DialResult::blank("reconnect-churn-200");
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
                        if churn.echo_rtts_us.len() < MAX_RTT_SAMPLES {
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

        results.push(run_named(
            "soak-steady-30s",
            &addr,
            u64::MAX / 4,
            Duration::from_micros(200),
            1024,
            0,
            Some(Duration::from_secs(30)),
            10,
            &mem_log,
            suite_t0,
            transport,
        ));

        eprintln!("[suite] running concurrent-8x100x1KiB …");
        let conc8 = run_concurrent(&addr, 8, 100, 1024, transport)?;
        record_mem(&mem_log, suite_t0, "after-concurrent-8x100");
        results.extend(conc8);
    }

    record_mem(&mem_log, suite_t0, "suite-end");
    sampler_stop.store(true, Ordering::SeqCst);
    if let Some(h) = sampler {
        let _ = h.join();
    }

    let wall_ms = suite_t0.elapsed().as_millis() as u64;
    stop.store(true, Ordering::SeqCst);
    thread::sleep(Duration::from_millis(200));
    let _ = listener.join();

    let mem_samples = mem_log.lock().unwrap().clone();
    let mem_csv = run_dir.join("memory.csv");
    write_memory_csv(&mem_csv, &mem_samples)?;

    let md_path = run_dir.join("report.md");
    let json_path = run_dir.join("report.json");
    let target = addr.to_string();
    write_markdown(
        &md_path,
        &target,
        wall_ms,
        &results,
        &mem_samples,
        args.deep,
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
        transport,
        churn_mem_start.as_ref(),
        churn_mem_end.as_ref(),
    )?;

    println!("[suite] wrote {}", md_path.display());
    println!("[suite] wrote {}", json_path.display());
    println!("[suite] wrote {}", mem_csv.display());
    println!(
        "[suite] wall_ms={wall_ms} scenarios={} mode={} transport={}",
        results.len(),
        if args.deep { "deep" } else { "short" },
        transport.as_str()
    );

    let failed = results.iter().filter(|r| !r.ok).count();
    if failed > 0 {
        Err(format!("{failed} scenario(s) failed").into())
    } else {
        Ok(())
    }
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
    let mut opts = DialOpts::basic(name, addr.clone(), count, interval, payload, builtin_ping, transport);
    opts.max_echo_duration = max_echo_duration;
    opts.rtt_sample_stride = rtt_sample_stride;
    let mut r = run_dial_collect(opts);
    if count == 0 && builtin_ping > 0 {
        r.ok = r.error.is_none() && r.builtin_ping_rtts_ms.len() as u64 == builtin_ping;
        if !r.ok && r.error.is_none() {
            r.error = Some("builtin ping count mismatch".into());
        }
    }
    if max_echo_duration.is_some() {
        r.ok = r.error.is_none() && r.sent > 0 && r.lost == 0 && r.received == r.sent;
        if !r.ok && r.error.is_none() {
            r.error = Some(format!(
                "soak incomplete or lost: sent={} recv={}",
                r.sent, r.received
            ));
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
                    run_dial_collect(DialOpts::basic(
                        format!("concurrent-{clients}x{count}-client-{i}"),
                        addr,
                        count,
                        Duration::from_millis(0),
                        payload,
                        0,
                        transport,
                    ))
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
        s.push_str(&format!("{},{},{},{}\n", m.t_ms, m.rss_kb, m.vsz_kb, escape_csv(label)));
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

    let (verdict, reasoning) = if let Some(cd) = churn_delta_kb {
        let c_start = churn_start_rss.unwrap_or(0);
        let pct = if c_start > 0 {
            (cd as f64 / c_start as f64) * 100.0
        } else {
            0.0
        };
        if cd > 8 * 1024 || (cd > 2 * 1024 && pct > 25.0) {
            let churn_pts: Vec<_> = samples
                .iter()
                .filter(|(_, l)| l.starts_with("reconnect-churn"))
                .map(|(m, _)| m.rss_kb)
                .collect();
            let climbing = if churn_pts.len() >= 3 {
                let mid = churn_pts.len() / 2;
                let early_avg = churn_pts[..mid].iter().sum::<u64>() as f64 / mid as f64;
                let late_avg =
                    churn_pts[mid..].iter().sum::<u64>() as f64 / (churn_pts.len() - mid) as f64;
                late_avg > early_avg * 1.05
            } else {
                cd > 0
            };
            if climbing {
                (
                    "suspect".into(),
                    format!(
                        "reconnect-churn RSS rose {cd} kB ({pct:.1}%); late samples still above early — LEAK SUSPECT"
                    ),
                )
            } else {
                (
                    "allocator/cache growth".into(),
                    format!(
                        "reconnect-churn RSS rose {cd} kB but plateaued — likely allocator/cache growth, not a clear leak"
                    ),
                )
            }
        } else if delta_kb > 4 * 1024 {
            (
                "allocator/cache growth".into(),
                format!(
                    "suite RSS delta {delta_kb} kB with modest churn delta {cd} kB — consistent with allocator arenas / page cache, not a clear leak"
                ),
            )
        } else {
            (
                "none".into(),
                format!(
                    "RSS start={start_rss} peak={peak_rss} end={end_rss} (delta {delta_kb} kB); churn delta {cd} kB — no leak signal"
                ),
            )
        }
    } else if delta_kb > 4 * 1024 {
        (
            "allocator/cache growth".into(),
            format!(
                "RSS rose {delta_kb} kB over suite (no churn data) — may be allocator growth; re-run with --deep"
            ),
        )
    } else {
        (
            "none".into(),
            format!(
                "RSS start={start_rss} peak={peak_rss} end={end_rss} (delta {delta_kb} kB) — no leak signal"
            ),
        )
    };

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

fn mode_label(deep: bool) -> &'static str {
    if deep {
        "deep"
    } else {
        "short"
    }
}

fn write_markdown(
    path: &Path,
    target: &str,
    wall_ms: u64,
    results: &[DialResult],
    mem_samples: &[(MemSample, String)],
    deep: bool,
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
    md.push_str(&format!("- **Stack:** `{STACK}`\n"));
    md.push_str(&format!("- **Transport:** {}\n", transport.as_str()));
    md.push_str(&format!("- **Mode:** {}\n", mode_label(deep)));
    md.push_str(&format!(
        "- **Suite wall time:** {wall_ms} ms ({:.1} s)\n",
        wall_ms as f64 / 1000.0
    ));
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
    if let (Some(a), Some(b), Some(d)) = (mem.churn_start_rss, mem.churn_end_rss, mem.churn_delta_kb)
    {
        md.push_str(&format!(
            "- **Reconnect-churn RSS start→end:** {a} → {b} kB (delta {d} kB)\n"
        ));
    }
    md.push_str(&format!(
        "- **Samples:** {} (see `memory.csv`)\n",
        mem_samples.len()
    ));
    md.push_str(&format!("- **Verdict:** `{}`\n", mem.verdict));
    md.push_str(&format!("- **Reasoning:** {}\n", mem.reasoning));
    md.push_str("\nNote: listener + all dialer Endpoints share one process PID; samples are from `/proc/self/status` (VmRSS / VmSize).\n");

    md.push_str("\n## Findings\n\n");
    md.push_str(&findings(results, &mem, deep));
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

fn findings(results: &[DialResult], mem: &MemVerdict, deep: bool) -> String {
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

    lines.push(format!(
        "- **Memory verdict:** `{}` — {}",
        mem.verdict, mem.reasoning
    ));

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
            large.percentile_echo_rtt_us(0.95) as f64 / 1000.0,
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

    lines.push("\n### Suspected bottlenecks\n".into());
    lines.push("- **Harness:** `FrameBuf::pop` returns a slice (no per-frame `.to_vec()`). Listener uses `HashMap<PeerId, HashSet<StreamId>>` and moves `data` into `send_stream`.".into());
    lines.push("- **Harness:** Endpoint-per-dial in reconnect churn is intentional (unique PeerId dial/drop). Each iter pays handshake + identify + stream open.".into());
    lines.push("- **Library:** Builtin ping API returns **milliseconds only**; sub-ms pings collapse to 0/1. Echo path uses µs.".into());
    lines.push("- **Library:** Identify on every reconnect is mandatory today; churn cost is dominated by handshake+identify, not echo RTT.".into());
    if deep {
        if let Some(long64) = results.iter().find(|r| r.name == "long-echo-50x64KiB") {
            lines.push(format!(
                "- **Measured:** long-echo-50x64KiB throughput {:.2} Mbps, avg RTT {:.1} µs — payload path looks {:?}bound on loopback.",
                long64.mbps(),
                long64.avg_echo_rtt_us(),
                if long64.mbps() > 500.0 { "CPU/copy" } else { "latency" }
            ));
        }
    }
    lines.push("- Caveat: loopback only — measures sync Endpoint under spar’s echo protocol (QUIC or TCP), not gossipsub/relay/WAN.".into());
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
    transport: TransportKind,
    churn_start: Option<&MemSample>,
    churn_end: Option<&MemSample>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mem = analyze_memory(mem_samples, churn_start, churn_end);
    let mut s = String::new();
    s.push_str("{\n");
    s.push_str(&format!("  \"target\": \"{}\",\n", escape(target)));
    s.push_str("  \"runtime\": \"sync-std-thread\",\n");
    s.push_str(&format!("  \"stack\": \"{}\",\n", escape(STACK)));
    s.push_str(&format!("  \"transport\": \"{}\",\n", transport.as_str()));
    s.push_str(&format!("  \"deep\": {},\n", deep));
    s.push_str(&format!("  \"mode\": \"{}\",\n", mode_label(deep)));
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
