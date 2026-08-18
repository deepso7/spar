//! Loopback gossipsub scenarios. One thread, round-robin `next_event`.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use minip2p::{
    Endpoint, Event, PublishError, PubsubError, PubsubEvent, FLOODSUB_PROTOCOL_ID,
    MESHSUB_PROTOCOL_ID_V10, MESHSUB_PROTOCOL_ID_V11,
};

use crate::common::{sample_mem, DialResult, MemSample, TransportKind, AGENT, MAX_RTT_SAMPLES};

pub const GOSSIP_TOPIC: &str = "/spar/gossip/1";
const SLICE: Duration = Duration::from_millis(1);
const MESH_DEADLINE: Duration = Duration::from_secs(20);

struct Stats {
    leaks: u64,
    errors: Vec<String>,
}

impl Stats {
    fn notes(&self) -> Option<String> {
        let mut parts = Vec::new();
        if self.leaks > 0 {
            parts.push(format!("pubsub StreamReady leaked to app x{}", self.leaks));
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

fn is_pubsub_protocol(id: &str) -> bool {
    matches!(
        id,
        FLOODSUB_PROTOCOL_ID | MESHSUB_PROTOCOL_ID_V10 | MESHSUB_PROTOCOL_ID_V11
    )
}

fn build_ep(transport: TransportKind) -> Result<Endpoint, Box<dyn std::error::Error + Send + Sync>> {
    let b = Endpoint::builder().agent_version(AGENT).pubsub();
    Ok(match transport {
        TransportKind::Quic => b.bind_quic("127.0.0.1:0")?,
        TransportKind::Tcp => b.bind_tcp("127.0.0.1:0")?,
    })
}

fn stamp(seq: u64, send_us: u64, pad: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(pad.max(16));
    out.extend_from_slice(&seq.to_be_bytes());
    out.extend_from_slice(&send_us.to_be_bytes());
    if pad > 16 {
        out.extend(std::iter::repeat_n(0xA5, pad - 16));
    }
    out
}

fn decode(data: &[u8]) -> Option<(u64, u64)> {
    if data.len() < 16 {
        return None;
    }
    Some((
        u64::from_be_bytes(data[0..8].try_into().ok()?),
        u64::from_be_bytes(data[8..16].try_into().ok()?),
    ))
}

fn drive(eps: &mut [Endpoint], stats: &mut Stats, start: usize) -> Vec<Vec<PubsubEvent>> {
    let n = eps.len();
    let mut out = vec![Vec::new(); n];
    for k in 0..n {
        let i = (start + k) % n;
        match eps[i].next_event(SLICE) {
            Ok(Some(Event::StreamReady { protocol_id, .. })) if is_pubsub_protocol(&protocol_id) => {
                stats.leaks += 1;
            }
            Ok(Some(Event::Error(err))) => stats.errors.push(format!("swarm error: {err:?}")),
            Err(err) => stats.errors.push(format!("next_event: {err}")),
            _ => {}
        }
        let events = eps[i].take_pubsub_events();
        for ev in &events {
            if let PubsubEvent::ProtocolViolation { reason, .. } = ev {
                stats.errors.push(format!("protocol_violation: {reason}"));
            }
        }
        out[i] = events;
    }
    out
}

fn ingest(
    events: &[PubsubEvent],
    got: &mut HashSet<u64>,
    lats: &mut Vec<u64>,
    t0: Instant,
    self_del: &mut u64,
    is_pub: bool,
) {
    for ev in events {
        let PubsubEvent::Message { data, topics, .. } = ev else {
            continue;
        };
        if !topics.is_empty() && !topics.iter().any(|t| t == GOSSIP_TOPIC) {
            continue;
        }
        let Some((seq, send_us)) = decode(data) else {
            continue;
        };
        if is_pub {
            *self_del += 1;
            continue;
        }
        if got.insert(seq) && lats.len() < MAX_RTT_SAMPLES {
            let now = t0.elapsed().as_micros() as u64;
            lats.push(now.saturating_sub(send_us));
        }
    }
}

fn ingest_all(
    eps: &mut [Endpoint],
    pub_idx: usize,
    stats: &mut Stats,
    got: &mut [HashSet<u64>],
    lats: &mut [Vec<u64>],
    t0: Instant,
    self_del: &mut u64,
) {
    let step = drive(eps, stats, pub_idx);
    for (i, events) in step.iter().enumerate() {
        ingest(events, &mut got[i], &mut lats[i], t0, self_del, i == pub_idx);
    }
}

fn sub_count(events: &[PubsubEvent]) -> usize {
    events
        .iter()
        .filter(|e| matches!(e, PubsubEvent::PeerSubscribed { topic, .. } if topic == GOSSIP_TOPIC))
        .count()
}

fn saw_unsub(events: &[PubsubEvent]) -> bool {
    events
        .iter()
        .any(|e| matches!(e, PubsubEvent::PeerUnsubscribed { topic, .. } if topic == GOSSIP_TOPIC))
}

/// Star: node 0 listens, others dial. Everyone subscribes first.
fn setup_star(
    n: usize,
    transport: TransportKind,
    stats: &mut Stats,
) -> Result<Vec<Endpoint>, Box<dyn std::error::Error + Send + Sync>> {
    let mut eps = Vec::with_capacity(n);
    for _ in 0..n {
        eps.push(build_ep(transport)?);
    }
    let hub = eps[0].listen()?;
    for ep in eps.iter_mut().skip(1) {
        let _ = ep.listen()?;
    }
    for ep in &mut eps {
        let _ = ep.subscribe(GOSSIP_TOPIC)?;
    }
    for ep in eps.iter_mut().skip(1) {
        ep.dial(&hub)?;
    }
    let leaves = n - 1;
    let until = Instant::now() + MESH_DEADLINE;
    let mut all: Vec<Vec<PubsubEvent>> = vec![Vec::new(); n];
    loop {
        let hub_ok = sub_count(&all[0]) >= leaves;
        let leaves_ok = all[1..].iter().all(|ev| sub_count(ev) >= 1);
        if hub_ok && leaves_ok {
            break;
        }
        if Instant::now() >= until {
            return Err(format!(
                "mesh not ready in {MESH_DEADLINE:?}: hub_subs={} leaves={:?}",
                sub_count(&all[0]),
                all[1..].iter().map(|ev| sub_count(ev)).collect::<Vec<_>>()
            )
            .into());
        }
        let step = drive(&mut eps, stats, 0);
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
    pad: usize,
    t0: Instant,
    stats: &mut Stats,
    got: &mut [HashSet<u64>],
    lats: &mut [Vec<u64>],
    self_del: &mut u64,
) -> Result<(u64, u64), Box<dyn std::error::Error + Send + Sync>> {
    let mut sent = 0u64;
    let mut bytes = 0u64;
    let deadline = Instant::now() + Duration::from_secs(30);
    while sent < n {
        if Instant::now() >= deadline {
            return Err(format!("publish stalled at {sent}/{n}").into());
        }
        let seq = sent + 1;
        let data = stamp(seq, t0.elapsed().as_micros() as u64, pad);
        let len = data.len() as u64;
        match eps[pub_idx].publish(GOSSIP_TOPIC, data) {
            Ok(()) => {
                sent += 1;
                bytes += len;
                ingest_all(eps, pub_idx, stats, got, lats, t0, self_del);
            }
            Err(PubsubError::Publish(PublishError::Backpressure)) => {
                ingest_all(eps, pub_idx, stats, got, lats, t0, self_del);
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
    stats: &mut Stats,
    got: &mut [HashSet<u64>],
    lats: &mut [Vec<u64>],
    self_del: &mut u64,
) {
    let until = Instant::now() + deadline;
    while Instant::now() < until && !receivers.iter().all(|&i| got[i].len() as u64 >= expected) {
        ingest_all(eps, pub_idx, stats, got, lats, t0, self_del);
    }
    let grace = Instant::now() + Duration::from_millis(250);
    while Instant::now() < grace {
        ingest_all(eps, pub_idx, stats, got, lats, t0, self_del);
    }
}

fn record_mem(log: &Arc<Mutex<Vec<(MemSample, String)>>>, t0: Instant, label: &str) {
    if let Some(s) = sample_mem(t0)
        && let Ok(mut g) = log.lock()
    {
        g.push((s, label.to_string()));
    }
}

fn finish(
    name: &str,
    n_msgs: u64,
    receivers: &[usize],
    got: &[HashSet<u64>],
    lats: &[Vec<u64>],
    self_del: u64,
    bytes_sent: u64,
    bytes_recv: u64,
    wall_ms: u64,
    mesh_ms: u64,
    stats: &Stats,
    extra: Option<String>,
) -> DialResult {
    let expected = n_msgs * receivers.len() as u64;
    let received: u64 = receivers.iter().map(|&i| got[i].len() as u64).sum();
    let lost = expected.saturating_sub(received);
    let mut rtts = Vec::new();
    for &i in receivers {
        for &lat in &lats[i] {
            if rtts.len() < MAX_RTT_SAMPLES {
                rtts.push(lat);
            }
        }
    }
    let mut errors = Vec::new();
    if let Some(n) = stats.notes() {
        errors.push(n);
    }
    if self_del > 0 {
        errors.push(format!("self-delivery x{self_del}"));
    }
    if lost > 0 {
        let per: Vec<_> = receivers
            .iter()
            .map(|&i| format!("n{i}={}", got[i].len()))
            .collect();
        errors.push(format!("loss {lost}/{expected} ({})", per.join(",")));
    }
    if let Some(e) = extra {
        errors.push(e);
    }
    let stored = rtts.len() as u64;
    DialResult {
        name: name.into(),
        ok: errors.is_empty() && lost == 0 && self_del == 0 && stats.leaks == 0,
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

fn wrap_fail(name: &str, t0: Instant, stats: &Stats, e: impl ToString) -> DialResult {
    let mut r = DialResult::fail(name, e);
    r.wall_ms = t0.elapsed().as_millis() as u64;
    if let Some(n) = stats.notes() {
        r.error = Some(match r.error.take() {
            Some(prev) => format!("{prev}; {n}"),
            None => n,
        });
    }
    r
}

fn run_named(
    name: &str,
    n_nodes: usize,
    n_msgs: u64,
    pad: usize,
    pub_idx: usize,
    transport: TransportKind,
    delivery: Duration,
    mem_log: &Arc<Mutex<Vec<(MemSample, String)>>>,
    suite_t0: Instant,
) -> DialResult {
    eprintln!("[suite] running {name} …");
    record_mem(mem_log, suite_t0, &format!("before-{name}"));
    let t_scen = Instant::now();
    let mut stats = Stats {
        leaks: 0,
        errors: Vec::new(),
    };
    let result = (|| -> Result<DialResult, Box<dyn std::error::Error + Send + Sync>> {
        let mesh_t0 = Instant::now();
        let mut eps = setup_star(n_nodes, transport, &mut stats)?;
        let mesh_ms = mesh_t0.elapsed().as_millis() as u64;
        let t0 = Instant::now();
        let mut got = vec![HashSet::new(); n_nodes];
        let mut lats = vec![Vec::new(); n_nodes];
        let mut self_del = 0u64;
        let (n_sent, bytes_sent) =
            publish_all(&mut eps, pub_idx, n_msgs, pad, t0, &mut stats, &mut got, &mut lats, &mut self_del)?;
        let receivers: Vec<usize> = (0..n_nodes).filter(|&i| i != pub_idx).collect();
        wait_deliveries(
            &mut eps, pub_idx, &receivers, n_sent, t0, delivery, &mut stats, &mut got, &mut lats, &mut self_del,
        );
        let wall_ms = t0.elapsed().as_millis() as u64;
        let bytes_recv = receivers.iter().map(|&i| got[i].len() as u64 * pad as u64).sum();
        drop(eps);
        Ok(finish(
            name, n_sent, &receivers, &got, &lats, self_del, bytes_sent, bytes_recv, wall_ms, mesh_ms, &stats, None,
        ))
    })();
    record_mem(mem_log, suite_t0, &format!("after-{name}"));
    let r = match result {
        Ok(r) => r,
        Err(e) => wrap_fail(name, t_scen, &stats, e),
    };
    eprintln!(
        "[suite] {name} ok={} sent={} recv={} lost={} avg_lat_us={:.1} wall_ms={} ({:.1}s)",
        r.ok, r.sent, r.received, r.lost, r.avg_echo_rtt_us(), r.wall_ms, t_scen.elapsed().as_secs_f64()
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
    let mut stats = Stats {
        leaks: 0,
        errors: Vec::new(),
    };
    // B = hub 0 (unsubscribes); A = 1 (publishes).
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
        let mut lats = vec![Vec::new(); 2];
        let mut self_del = 0u64;
        let (n_sent, bytes_sent) =
            publish_all(&mut eps, pub_idx, first_n, pad, t0, &mut stats, &mut got, &mut lats, &mut self_del)?;
        wait_deliveries(
            &mut eps, pub_idx, &[sub_idx], n_sent, t0, Duration::from_secs(15), &mut stats, &mut got, &mut lats,
            &mut self_del,
        );
        if got[sub_idx].len() as u64 != first_n {
            return Err(format!("B only got {}/{first_n} before unsub", got[sub_idx].len()).into());
        }
        if !eps[sub_idx].unsubscribe(GOSSIP_TOPIC)? {
            return Err("B unsubscribe returned false".into());
        }
        let until = Instant::now() + Duration::from_secs(15);
        let mut saw = false;
        let mut acc_a = Vec::new();
        while Instant::now() < until {
            let step = drive(&mut eps, &mut stats, pub_idx);
            acc_a.extend(step[pub_idx].iter().cloned());
            ingest(&step[sub_idx], &mut got[sub_idx], &mut lats[sub_idx], t0, &mut self_del, false);
            ingest(&step[pub_idx], &mut got[pub_idx], &mut lats[pub_idx], t0, &mut self_del, true);
            if saw_unsub(&acc_a) {
                saw = true;
                break;
            }
        }
        if !saw {
            return Err("A never saw PeerUnsubscribed".into());
        }
        let settle = Instant::now() + Duration::from_millis(400);
        while Instant::now() < settle {
            ingest_all(&mut eps, pub_idx, &mut stats, &mut got, &mut lats, t0, &mut self_del);
        }
        for i in 0..extra_n {
            let seq = first_n + i + 1;
            let data = stamp(seq, t0.elapsed().as_micros() as u64, pad);
            loop {
                match eps[pub_idx].publish(GOSSIP_TOPIC, data.clone()) {
                    Ok(()) => break,
                    Err(PubsubError::Publish(PublishError::Backpressure)) => {
                        ingest_all(&mut eps, pub_idx, &mut stats, &mut got, &mut lats, t0, &mut self_del);
                    }
                    Err(e) => return Err(format!("post-unsub publish: {e}").into()),
                }
            }
            ingest_all(&mut eps, pub_idx, &mut stats, &mut got, &mut lats, t0, &mut self_del);
        }
        let watch = Instant::now() + Duration::from_secs(2);
        let mut post = 0u64;
        while Instant::now() < watch {
            let step = drive(&mut eps, &mut stats, pub_idx);
            for ev in &step[sub_idx] {
                if let PubsubEvent::Message { data, .. } = ev
                    && let Some((seq, _)) = decode(data)
                    && seq > first_n
                {
                    post += 1;
                }
            }
            ingest(&step[pub_idx], &mut got[pub_idx], &mut lats[pub_idx], t0, &mut self_del, true);
        }
        drop(eps);
        let extra = if post > 0 {
            Some(format!("B received {post} msgs after unsub settled (want 0)"))
        } else {
            None
        };
        Ok(finish(
            name,
            first_n,
            &[sub_idx],
            &got,
            &lats,
            self_del,
            bytes_sent,
            got[sub_idx].len() as u64 * pad as u64,
            t0.elapsed().as_millis() as u64,
            mesh_ms,
            &stats,
            extra,
        ))
    })();
    record_mem(mem_log, suite_t0, &format!("after-{name}"));
    let r = match result {
        Ok(r) => r,
        Err(e) => wrap_fail(name, t_scen, &stats, e),
    };
    eprintln!(
        "[suite] {name} ok={} sent={} recv={} lost={} avg_lat_us={:.1} wall_ms={} ({:.1}s)",
        r.ok, r.sent, r.received, r.lost, r.avg_echo_rtt_us(), r.wall_ms, t_scen.elapsed().as_secs_f64()
    );
    r
}

/// Four loopback gossipsub scenarios on one thread.
pub fn run_gossip_scenarios(
    transport: TransportKind,
    mem_log: &Arc<Mutex<Vec<(MemSample, String)>>>,
    suite_t0: Instant,
) -> Vec<DialResult> {
    let mut out = Vec::new();
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
