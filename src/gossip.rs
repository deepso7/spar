//! Single-threaded gossipsub soak scenarios. All endpoints live on one
//! thread and are driven round-robin — the library is caller-driven.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use minip2p::{
    Endpoint, Event, PublishError, PubsubError, PubsubEvent, FLOODSUB_PROTOCOL_ID,
    MESHSUB_PROTOCOL_ID_V10, MESHSUB_PROTOCOL_ID_V11,
};

use crate::common::{
    sample_mem, DialResult, MemSample, TransportKind, AGENT, MAX_RTT_SAMPLES,
};

pub const GOSSIP_TOPIC: &str = "/spar/gossip/1";
const DRIVE_SLICE: Duration = Duration::from_millis(1);
const MESH_DEADLINE: Duration = Duration::from_secs(20);

struct DriveStats {
    pubsub_leaks: u64,
    errors: Vec<String>,
    outbound_failures: u64,
    protocol_violations: u64,
}

impl DriveStats {
    fn new() -> Self {
        Self {
            pubsub_leaks: 0,
            errors: Vec::new(),
            outbound_failures: 0,
            protocol_violations: 0,
        }
    }

    fn notes(&self) -> Option<String> {
        let mut parts = Vec::new();
        if self.pubsub_leaks > 0 {
            parts.push(format!(
                "pubsub StreamReady leaked to app x{}",
                self.pubsub_leaks
            ));
        }
        if self.protocol_violations > 0 {
            parts.push(format!("protocol_violation x{}", self.protocol_violations));
        }
        if self.outbound_failures > 0 {
            parts.push(format!("outbound_failure x{}", self.outbound_failures));
        }
        if !self.errors.is_empty() {
            parts.push(self.errors.join("; "));
        }
        if parts.is_empty() {
            None
        } else {
            Some(parts.join("; "))
        }
    }
}

fn is_pubsub_protocol(protocol_id: &str) -> bool {
    matches!(
        protocol_id,
        FLOODSUB_PROTOCOL_ID | MESHSUB_PROTOCOL_ID_V10 | MESHSUB_PROTOCOL_ID_V11
    )
}

fn build_pubsub_endpoint(
    transport: TransportKind,
) -> Result<Endpoint, Box<dyn std::error::Error + Send + Sync>> {
    let builder = Endpoint::builder().agent_version(AGENT).pubsub();
    let endpoint = match transport {
        TransportKind::Quic => builder.bind_quic("127.0.0.1:0")?,
        TransportKind::Tcp => builder.bind_tcp("127.0.0.1:0")?,
    };
    Ok(endpoint)
}

fn stamp_payload(seq: u64, send_us: u64, pad_to: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(pad_to.max(16));
    out.extend_from_slice(&seq.to_be_bytes());
    out.extend_from_slice(&send_us.to_be_bytes());
    if pad_to > 16 {
        out.extend(std::iter::repeat_n(0xA5, pad_to - 16));
    }
    out
}

fn decode_stamp(data: &[u8]) -> Option<(u64, u64)> {
    if data.len() < 16 {
        return None;
    }
    let seq = u64::from_be_bytes(data[0..8].try_into().ok()?);
    let send_us = u64::from_be_bytes(data[8..16].try_into().ok()?);
    Some((seq, send_us))
}

fn drive_step(
    eps: &mut [Endpoint],
    stats: &mut DriveStats,
    slice: Duration,
    start: usize,
) -> Vec<Vec<PubsubEvent>> {
    let n = eps.len();
    let mut collected = vec![Vec::new(); n];
    for k in 0..n {
        let i = (start + k) % n;
        let ep = &mut eps[i];
        match ep.next_event(slice) {
            Ok(Some(Event::StreamReady { protocol_id, .. })) if is_pubsub_protocol(&protocol_id) => {
                stats.pubsub_leaks += 1;
            }
            Ok(Some(Event::Error(err))) => {
                stats.errors.push(format!("swarm error: {err:?}"));
            }
            Ok(_) => {}
            Err(err) => {
                stats.errors.push(format!("next_event: {err}"));
            }
        }
        let events = ep.take_pubsub_events();
        for ev in &events {
            match ev {
                PubsubEvent::OutboundFailure { .. } => stats.outbound_failures += 1,
                PubsubEvent::ProtocolViolation { reason, .. } => {
                    stats.protocol_violations += 1;
                    stats.errors.push(format!("protocol_violation: {reason}"));
                }
                _ => {}
            }
        }
        collected[i] = events;
    }
    collected
}

fn ingest(
    events: &[PubsubEvent],
    topic: &str,
    got: &mut HashSet<u64>,
    latencies: &mut Vec<u64>,
    t0: Instant,
    self_deliveries: &mut u64,
    is_publisher: bool,
) {
    for ev in events {
        if let PubsubEvent::Message { data, topics, .. } = ev {
            if !topics.iter().any(|t| t == topic) && !topics.is_empty() {
                continue;
            }
            let Some((seq, send_us)) = decode_stamp(data) else {
                continue;
            };
            if is_publisher {
                *self_deliveries += 1;
                continue;
            }
            if got.insert(seq) && latencies.len() < MAX_RTT_SAMPLES {
                let now = t0.elapsed().as_micros() as u64;
                latencies.push(now.saturating_sub(send_us));
            }
        }
    }
}

fn ingest_step(
    eps: &mut [Endpoint],
    pub_idx: usize,
    stats: &mut DriveStats,
    got: &mut [HashSet<u64>],
    latencies: &mut [Vec<u64>],
    t0: Instant,
    self_deliveries: &mut u64,
) {
    let step = drive_step(eps, stats, DRIVE_SLICE, pub_idx);
    for (i, events) in step.iter().enumerate() {
        ingest(
            events,
            GOSSIP_TOPIC,
            &mut got[i],
            &mut latencies[i],
            t0,
            self_deliveries,
            i == pub_idx,
        );
    }
}

fn sub_count(events: &[PubsubEvent], topic: &str) -> usize {
    events
        .iter()
        .filter(|e| matches!(e, PubsubEvent::PeerSubscribed { topic: t, .. } if t == topic))
        .count()
}

fn saw_unsub(events: &[PubsubEvent], topic: &str) -> bool {
    events
        .iter()
        .any(|e| matches!(e, PubsubEvent::PeerUnsubscribed { topic: t, .. } if t == topic))
}

/// Star: node 0 listens, nodes 1..n-1 dial it. Everyone subscribes first.
fn setup_star(
    n: usize,
    transport: TransportKind,
    stats: &mut DriveStats,
) -> Result<Vec<Endpoint>, Box<dyn std::error::Error + Send + Sync>> {
    let mut eps = Vec::with_capacity(n);
    for _ in 0..n {
        eps.push(build_pubsub_endpoint(transport)?);
    }
    let hub_addr = eps[0].listen()?;
    for ep in eps.iter_mut().skip(1) {
        let _ = ep.listen()?;
    }
    for ep in &mut eps {
        let _ = ep.subscribe(GOSSIP_TOPIC)?;
    }
    for ep in eps.iter_mut().skip(1) {
        ep.dial(&hub_addr)?;
    }

    let n_leaves = n - 1;
    let until = Instant::now() + MESH_DEADLINE;
    let mut all: Vec<Vec<PubsubEvent>> = vec![Vec::new(); n];
    loop {
        let hub_ok = sub_count(&all[0], GOSSIP_TOPIC) >= n_leaves;
        let leaves_ok = all[1..].iter().all(|ev| sub_count(ev, GOSSIP_TOPIC) >= 1);
        if hub_ok && leaves_ok {
            break;
        }
        if Instant::now() >= until {
            return Err(format!(
                "mesh not ready in {:?}: hub_subs={} leaves={:?}",
                MESH_DEADLINE,
                sub_count(&all[0], GOSSIP_TOPIC),
                all[1..]
                    .iter()
                    .map(|ev| sub_count(ev, GOSSIP_TOPIC))
                    .collect::<Vec<_>>()
            )
            .into());
        }
        let step = drive_step(&mut eps, stats, DRIVE_SLICE, 0);
        for (acc, new) in all.iter_mut().zip(step) {
            acc.extend(new);
        }
    }
    Ok(eps)
}

fn publish_all(
    eps: &mut [Endpoint],
    pub_idx: usize,
    n: u64,
    pad_to: usize,
    t0: Instant,
    stats: &mut DriveStats,
    got: &mut [HashSet<u64>],
    latencies: &mut [Vec<u64>],
    self_deliveries: &mut u64,
) -> Result<(u64, u64), Box<dyn std::error::Error + Send + Sync>> {
    let mut sent = 0u64;
    let mut bytes = 0u64;
    let pub_deadline = Instant::now() + Duration::from_secs(30);
    while sent < n {
        if Instant::now() >= pub_deadline {
            return Err(format!("publish stalled at {sent}/{n}").into());
        }
        let send_us = t0.elapsed().as_micros() as u64;
        let seq = sent + 1;
        let data = stamp_payload(seq, send_us, pad_to);
        let len = data.len() as u64;
        match eps[pub_idx].publish(GOSSIP_TOPIC, data) {
            Ok(()) => {
                sent += 1;
                bytes += len;
                ingest_step(eps, pub_idx, stats, got, latencies, t0, self_deliveries);
            }
            Err(PubsubError::Publish(PublishError::Backpressure)) => {
                ingest_step(eps, pub_idx, stats, got, latencies, t0, self_deliveries);
            }
            Err(e) => return Err(format!("publish seq {seq}: {e}").into()),
        }
    }
    Ok((sent, bytes))
}

fn wait_deliveries(
    eps: &mut [Endpoint],
    pub_idx: usize,
    receivers: &[usize],
    expected: u64,
    t0: Instant,
    deadline: Duration,
    stats: &mut DriveStats,
    got: &mut [HashSet<u64>],
    latencies: &mut [Vec<u64>],
    self_deliveries: &mut u64,
) {
    let until = Instant::now() + deadline;
    loop {
        let all_done = receivers.iter().all(|&i| got[i].len() as u64 >= expected);
        if all_done || Instant::now() >= until {
            break;
        }
        ingest_step(eps, pub_idx, stats, got, latencies, t0, self_deliveries);
    }
    let grace = Instant::now() + Duration::from_millis(250);
    while Instant::now() < grace {
        ingest_step(eps, pub_idx, stats, got, latencies, t0, self_deliveries);
    }
}

fn record_mem(log: &Arc<Mutex<Vec<(MemSample, String)>>>, t0: Instant, label: &str) {
    if let Some(s) = sample_mem(t0)
        && let Ok(mut g) = log.lock()
    {
        g.push((s, label.to_string()));
    }
}

fn finish_result(
    name: &str,
    n_msgs: u64,
    n_receivers: usize,
    got: &[HashSet<u64>],
    receivers: &[usize],
    latencies: &[Vec<u64>],
    self_deliveries: u64,
    bytes_sent: u64,
    bytes_recv: u64,
    wall_ms: u64,
    mesh_ms: u64,
    stats: &DriveStats,
    extra_fail: Option<String>,
) -> DialResult {
    let expected = n_msgs * n_receivers as u64;
    let received: u64 = receivers.iter().map(|&i| got[i].len() as u64).sum();
    let lost = expected.saturating_sub(received);
    let mut rtts = Vec::new();
    for &i in receivers {
        for &lat in &latencies[i] {
            if rtts.len() < MAX_RTT_SAMPLES {
                rtts.push(lat);
            }
        }
    }
    let mut errors = Vec::new();
    if let Some(n) = stats.notes()
        && (stats.pubsub_leaks > 0 || stats.protocol_violations > 0 || !stats.errors.is_empty()
            || (stats.outbound_failures > 0 && lost > 0))
    {
        errors.push(n);
    }
    if self_deliveries > 0 {
        errors.push(format!("self-delivery x{self_deliveries}"));
    }
    if lost > 0 {
        let per: Vec<String> = receivers
            .iter()
            .map(|&i| format!("n{i}={}", got[i].len()))
            .collect();
        errors.push(format!("loss {lost}/{expected} ({})", per.join(",")));
    }
    if let Some(e) = extra_fail {
        errors.push(e);
    }
    let ok = errors.is_empty() && lost == 0 && self_deliveries == 0 && stats.pubsub_leaks == 0;
    let stored = rtts.len() as u64;
    DialResult {
        name: name.into(),
        ok,
        error: if errors.is_empty() {
            None
        } else {
            Some(errors.join("; "))
        },
        dial_ms: mesh_ms,
        identify_ms: mesh_ms,
        echo_open_ms: 0,
        wall_ms,
        sent: expected,
        received,
        lost,
        bytes_sent,
        bytes_recv,
        builtin_ping_rtts_ms: Vec::new(),
        echo_rtts_us: rtts,
        echo_rtt_samples_stored: stored,
    }
}

fn run_named(
    name: &str,
    n_nodes: usize,
    n_msgs: u64,
    pad_to: usize,
    pub_idx: usize,
    transport: TransportKind,
    delivery_deadline: Duration,
    mem_log: &Arc<Mutex<Vec<(MemSample, String)>>>,
    suite_t0: Instant,
) -> DialResult {
    eprintln!("[suite] running {name} …");
    record_mem(mem_log, suite_t0, &format!("before-{name}"));
    let t_scen = Instant::now();
    let mut stats = DriveStats::new();
    let result = (|| -> Result<DialResult, Box<dyn std::error::Error + Send + Sync>> {
        let mesh_t0 = Instant::now();
        let mut eps = setup_star(n_nodes, transport, &mut stats)?;
        let mesh_ms = mesh_t0.elapsed().as_millis() as u64;
        let t0 = Instant::now();
        let mut got = vec![HashSet::new(); n_nodes];
        let mut latencies = vec![Vec::new(); n_nodes];
        let mut self_deliveries = 0u64;
        let (n_sent, bytes_sent) = publish_all(
            &mut eps,
            pub_idx,
            n_msgs,
            pad_to,
            t0,
            &mut stats,
            &mut got,
            &mut latencies,
            &mut self_deliveries,
        )?;
        let receivers: Vec<usize> = (0..n_nodes).filter(|&i| i != pub_idx).collect();
        wait_deliveries(
            &mut eps,
            pub_idx,
            &receivers,
            n_sent,
            t0,
            delivery_deadline,
            &mut stats,
            &mut got,
            &mut latencies,
            &mut self_deliveries,
        );
        let wall_ms = t0.elapsed().as_millis() as u64;
        let bytes_recv = receivers
            .iter()
            .map(|&i| got[i].len() as u64 * pad_to as u64)
            .sum();
        drop(eps);
        Ok(finish_result(
            name,
            n_sent,
            receivers.len(),
            &got,
            &receivers,
            &latencies,
            self_deliveries,
            bytes_sent,
            bytes_recv,
            wall_ms,
            mesh_ms,
            &stats,
            None,
        ))
    })();
    record_mem(mem_log, suite_t0, &format!("after-{name}"));
    let r = match result {
        Ok(r) => r,
        Err(e) => {
            let mut r = DialResult::fail(name, e);
            r.wall_ms = t_scen.elapsed().as_millis() as u64;
            if let Some(n) = stats.notes() {
                r.error = Some(match r.error.take() {
                    Some(prev) => format!("{prev}; {n}"),
                    None => n,
                });
            }
            r
        }
    };
    eprintln!(
        "[suite] {name} ok={} sent={} recv={} lost={} avg_lat_us={:.1} wall_ms={} ({:.1}s)",
        r.ok,
        r.sent,
        r.received,
        r.lost,
        r.avg_echo_rtt_us(),
        r.wall_ms,
        t_scen.elapsed().as_secs_f64()
    );
    r
}

fn run_unsub(
    transport: TransportKind,
    mem_log: &Arc<Mutex<Vec<(MemSample, String)>>>,
    suite_t0: Instant,
) -> DialResult {
    let name = "gossip-unsub";
    eprintln!("[suite] running {name} …");
    record_mem(mem_log, suite_t0, &format!("before-{name}"));
    let t_scen = Instant::now();
    let mut stats = DriveStats::new();
    // B = hub idx 0 (listener, unsubscribes); A = idx 1 (dials, publishes).
    let result = (|| -> Result<DialResult, Box<dyn std::error::Error + Send + Sync>> {
        let mesh_t0 = Instant::now();
        let mut eps = setup_star(2, transport, &mut stats)?;
        let mesh_ms = mesh_t0.elapsed().as_millis() as u64;
        let t0 = Instant::now();
        let first_n = 5u64;
        let extra_n = 10u64;
        let pad = 16usize;
        let pub_idx = 1usize;
        let sub_idx = 0usize;
        let mut got = vec![HashSet::new(); 2];
        let mut latencies = vec![Vec::new(); 2];
        let mut self_deliveries = 0u64;
        let (n_sent, bytes_sent) = publish_all(
            &mut eps,
            pub_idx,
            first_n,
            pad,
            t0,
            &mut stats,
            &mut got,
            &mut latencies,
            &mut self_deliveries,
        )?;
        wait_deliveries(
            &mut eps,
            pub_idx,
            &[sub_idx],
            n_sent,
            t0,
            Duration::from_secs(15),
            &mut stats,
            &mut got,
            &mut latencies,
            &mut self_deliveries,
        );
        if got[sub_idx].len() as u64 != first_n {
            return Err(format!(
                "B only got {}/{} before unsub",
                got[sub_idx].len(),
                first_n
            )
            .into());
        }

        if !eps[sub_idx].unsubscribe(GOSSIP_TOPIC)? {
            return Err("B unsubscribe returned false".into());
        }
        let until = Instant::now() + Duration::from_secs(15);
        let mut saw = false;
        let mut acc_a = Vec::new();
        while Instant::now() < until {
            let step = drive_step(&mut eps, &mut stats, DRIVE_SLICE, pub_idx);
            acc_a.extend(step[pub_idx].iter().cloned());
            ingest(
                &step[sub_idx],
                GOSSIP_TOPIC,
                &mut got[sub_idx],
                &mut latencies[sub_idx],
                t0,
                &mut self_deliveries,
                false,
            );
            ingest(
                &step[pub_idx],
                GOSSIP_TOPIC,
                &mut got[pub_idx],
                &mut latencies[pub_idx],
                t0,
                &mut self_deliveries,
                true,
            );
            if saw_unsub(&acc_a, GOSSIP_TOPIC) {
                saw = true;
                break;
            }
        }
        if !saw {
            return Err("A never saw PeerUnsubscribed".into());
        }
        let settle = Instant::now() + Duration::from_millis(400);
        while Instant::now() < settle {
            ingest_step(
                &mut eps,
                pub_idx,
                &mut stats,
                &mut got,
                &mut latencies,
                t0,
                &mut self_deliveries,
            );
        }

        for i in 0..extra_n {
            let send_us = t0.elapsed().as_micros() as u64;
            let seq = first_n + i + 1;
            let data = stamp_payload(seq, send_us, pad);
            loop {
                match eps[pub_idx].publish(GOSSIP_TOPIC, data.clone()) {
                    Ok(()) => break,
                    Err(PubsubError::Publish(PublishError::Backpressure)) => {
                        ingest_step(
                            &mut eps,
                            pub_idx,
                            &mut stats,
                            &mut got,
                            &mut latencies,
                            t0,
                            &mut self_deliveries,
                        );
                    }
                    Err(e) => return Err(format!("post-unsub publish: {e}").into()),
                }
            }
            ingest_step(
                &mut eps,
                pub_idx,
                &mut stats,
                &mut got,
                &mut latencies,
                t0,
                &mut self_deliveries,
            );
        }

        let watch = Instant::now() + Duration::from_secs(2);
        let mut post = 0u64;
        while Instant::now() < watch {
            let step = drive_step(&mut eps, &mut stats, DRIVE_SLICE, pub_idx);
            for ev in &step[sub_idx] {
                if let PubsubEvent::Message { data, .. } = ev
                    && let Some((seq, _)) = decode_stamp(data)
                    && seq > first_n
                {
                    post += 1;
                }
            }
            ingest(
                &step[pub_idx],
                GOSSIP_TOPIC,
                &mut got[pub_idx],
                &mut latencies[pub_idx],
                t0,
                &mut self_deliveries,
                true,
            );
        }
        drop(eps);
        let wall_ms = t0.elapsed().as_millis() as u64;
        let extra_fail = if post > 0 {
            Some(format!(
                "B received {post} msgs after unsub settled (want 0)"
            ))
        } else {
            None
        };
        Ok(finish_result(
            name,
            first_n,
            1,
            &got,
            &[sub_idx],
            &latencies,
            self_deliveries,
            bytes_sent,
            got[sub_idx].len() as u64 * pad as u64,
            wall_ms,
            mesh_ms,
            &stats,
            extra_fail,
        ))
    })();
    record_mem(mem_log, suite_t0, &format!("after-{name}"));
    let r = match result {
        Ok(r) => r,
        Err(e) => {
            let mut r = DialResult::fail(name, e);
            r.wall_ms = t_scen.elapsed().as_millis() as u64;
            r
        }
    };
    eprintln!(
        "[suite] {name} ok={} sent={} recv={} lost={} avg_lat_us={:.1} wall_ms={} ({:.1}s)",
        r.ok,
        r.sent,
        r.received,
        r.lost,
        r.avg_echo_rtt_us(),
        r.wall_ms,
        t_scen.elapsed().as_secs_f64()
    );
    r
}

/// Run the four loopback gossipsub scenarios on one thread.
pub fn run_gossip_scenarios(
    transport: TransportKind,
    mem_log: &Arc<Mutex<Vec<(MemSample, String)>>>,
    suite_t0: Instant,
) -> Vec<DialResult> {
    let mut out = Vec::new();

    // A dials B (star of 2), A publishes, B receives.
    out.push(run_named(
        "gossip-2node-20",
        2,
        20,
        16,
        1,
        transport,
        Duration::from_secs(15),
        mem_log,
        suite_t0,
    ));

    out.push(run_named(
        "gossip-4node-mesh-50",
        4,
        50,
        16,
        1,
        transport,
        Duration::from_secs(20),
        mem_log,
        suite_t0,
    ));

    record_mem(mem_log, suite_t0, "gossip-fanout-200-start");
    let rss_before = sample_mem(suite_t0);
    let mut fanout = run_named(
        "gossip-fanout-200",
        4,
        200,
        64,
        1,
        transport,
        Duration::from_secs(30),
        mem_log,
        suite_t0,
    );
    let rss_after = sample_mem(suite_t0);
    record_mem(mem_log, suite_t0, "gossip-fanout-200-end");
    if let (Some(a), Some(b)) = (&rss_before, &rss_after) {
        let delta = b.rss_kb as i64 - a.rss_kb as i64;
        eprintln!(
            "[suite] gossip-fanout-200 RSS {}→{} kB (delta {delta} kB)",
            a.rss_kb, b.rss_kb
        );
        if delta > 8 * 1024 {
            fanout.ok = false;
            let msg = format!(
                "fanout leak suspect: RSS {}→{} kB (delta {delta} kB)",
                a.rss_kb, b.rss_kb
            );
            fanout.error = Some(match fanout.error.take() {
                Some(prev) => format!("{prev}; {msg}"),
                None => msg,
            });
        }
    }
    out.push(fanout);

    out.push(run_unsub(transport, mem_log, suite_t0));
    out
}
