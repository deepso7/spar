//! Shared sync helpers. No async, no Tokio.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::str::FromStr;
use std::time::{Duration, Instant};

use minip2p::{Endpoint, EndpointBuilder, Event, PeerAddr, PeerId, StreamId};

pub const AGENT: &str = "spar/0.1.6";
/// Crate version of the sparred stack (minip2p-rs from crates.io).
pub const STACK: &str = "minip2p-rs 0.4.6";
pub const ECHO_PROTOCOL: &str = "/spar/echo/1.0.0";
pub const FRAME_LEN: usize = 16;
pub const MAX_RTT_SAMPLES: usize = 50_000;

/// Wire transport for listen/dial/suite (must match on both sides).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TransportKind {
    #[default]
    Quic,
    Tcp,
}

impl TransportKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Quic => "quic",
            Self::Tcp => "tcp",
        }
    }

    pub fn stack_label(self) -> String {
        match self {
            Self::Quic => format!("{STACK} (QUIC / quiche)"),
            Self::Tcp => format!("{STACK} (TCP / Noise / Yamux)"),
        }
    }

    pub fn stack_label_with_features(self, gossip: bool, nat: bool) -> String {
        let mut base = self.stack_label();
        if nat {
            base.push_str(" + nat/circuit");
        }
        if gossip {
            base.push_str(" + gossipsub");
        }
        base
    }

    pub fn parse(s: &str) -> Result<Self, String> {
        match s.to_ascii_lowercase().as_str() {
            "quic" => Ok(Self::Quic),
            "tcp" => Ok(Self::Tcp),
            other => Err(format!("unknown --transport {other:?} (want quic|tcp)")),
        }
    }
}

fn wants_dual_stack(bind: &str) -> bool {
    bind == "0.0.0.0:0"
}

fn bind_endpoint(
    make: impl Fn() -> EndpointBuilder,
    transport: TransportKind,
    bind: &str,
) -> Result<Endpoint, Box<dyn std::error::Error + Send + Sync>> {
    match transport {
        TransportKind::Quic if wants_dual_stack(bind) => match make().bind_quic_dual_stack() {
            Ok(endpoint) => Ok(endpoint),
            Err(err) => {
                eprintln!("[spar] QUIC IPv6 wildcard unavailable ({err}); listening on {bind}");
                Ok(make().bind_quic(bind)?)
            }
        },
        TransportKind::Quic => Ok(make().bind_quic(bind)?),
        TransportKind::Tcp if wants_dual_stack(bind) => {
            match make().tcp("0.0.0.0:0").tcp("[::]:0").bind() {
                Ok(endpoint) => Ok(endpoint),
                Err(err) => {
                    eprintln!("[spar] TCP IPv6 wildcard unavailable ({err}); listening on {bind}");
                    Ok(make().bind_tcp(bind)?)
                }
            }
        }
        TransportKind::Tcp => Ok(make().bind_tcp(bind)?),
    }
}

pub fn build_endpoint(
    bind: Option<&str>,
    transport: TransportKind,
) -> Result<Endpoint, Box<dyn std::error::Error + Send + Sync>> {
    let addr = bind.unwrap_or("127.0.0.1:0");
    bind_endpoint(
        || {
            Endpoint::builder()
                .agent_version(AGENT)
                .protocol(ECHO_PROTOCOL)
        },
        transport,
        addr,
    )
}

pub fn encode_header(seq: u64, send_ms: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(FRAME_LEN);
    out.extend_from_slice(&seq.to_be_bytes());
    out.extend_from_slice(&send_ms.to_be_bytes());
    out
}

pub fn decode_header(bytes: &[u8]) -> (u64, u64) {
    let seq = u64::from_be_bytes(bytes[0..8].try_into().unwrap());
    let send_ms = u64::from_be_bytes(bytes[8..16].try_into().unwrap());
    (seq, send_ms)
}

pub fn millis(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// Process memory sample from `/proc/self/status` (Linux).
#[derive(Clone, Debug)]
pub struct MemSample {
    pub t_ms: u64,
    pub rss_kb: u64,
    pub vsz_kb: u64,
}

/// Sample VmRSS / VmSize for this process (listener + dialers share the PID).
pub fn sample_mem(t0: Instant) -> Option<MemSample> {
    let text = fs::read_to_string("/proc/self/status").ok()?;
    let mut rss_kb = None;
    let mut vsz_kb = None;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            rss_kb = parse_kb_field(rest);
        } else if let Some(rest) = line.strip_prefix("VmSize:") {
            vsz_kb = parse_kb_field(rest);
        }
        if rss_kb.is_some() && vsz_kb.is_some() {
            break;
        }
    }
    Some(MemSample {
        t_ms: millis(t0),
        rss_kb: rss_kb?,
        vsz_kb: vsz_kb?,
    })
}

fn parse_kb_field(rest: &str) -> Option<u64> {
    rest.split_whitespace().next()?.parse().ok()
}

/// Push an RTT sample with optional stride and hard cap (avoids huge reports).
pub fn push_rtt_sample(samples: &mut Vec<u64>, rtt_us: u64, received: u64, stride: u64) {
    let stride = stride.max(1);
    if received % stride != 0 {
        return;
    }
    if samples.len() < MAX_RTT_SAMPLES {
        samples.push(rtt_us);
    }
}

fn is_backpressure(err: &dyn std::fmt::Display) -> bool {
    let msg = err.to_string();
    msg.contains("resource exhausted")
        || msg.contains("queued")
        || msg.contains("send buffer is full")
        || msg.contains("buffer is full")
}

#[derive(Default)]
pub struct FrameBuf {
    buf: Vec<u8>,
    head: usize,
}

impl FrameBuf {
    pub fn push(&mut self, data: &[u8]) {
        if self.head != 0 {
            self.buf.copy_within(self.head.., 0);
            self.buf.truncate(self.buf.len() - self.head);
            self.head = 0;
        }
        self.buf.extend_from_slice(data);
    }

    /// Returns a borrowed frame slice (no `.to_vec()`). Compact happens on next `push`.
    pub fn pop(&mut self, frame_len: usize) -> Option<&[u8]> {
        let end = self.head.checked_add(frame_len)?;
        if end > self.buf.len() {
            return None;
        }
        let start = self.head;
        self.head = end;
        Some(&self.buf[start..end])
    }
}

#[derive(Clone, Debug)]
pub struct DialResult {
    pub name: String,
    pub ok: bool,
    pub error: Option<String>,
    pub dial_ms: u64,
    pub identify_ms: u64,
    pub echo_open_ms: u64,
    pub wall_ms: u64,
    pub sent: u64,
    pub received: u64,
    pub lost: u64,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub builtin_ping_rtts_ms: Vec<u64>,
    /// Echo RTTs in microseconds (prefer over ms for sub-ms work).
    pub echo_rtts_us: Vec<u64>,
    /// How many echo RTT samples were dropped due to stride/cap (informational).
    pub echo_rtt_samples_stored: u64,
    pub us: String,
    pub first_path: String,
    pub final_path: String,
    pub punch_attempts: u32,
    pub punch_upgraded: bool,
    pub fell_back_to_relay: bool,
}

impl DialResult {
    pub fn fail(name: &str, err: impl ToString) -> Self {
        Self {
            name: name.into(),
            ok: false,
            error: Some(err.to_string()),
            ..Self::blank(name)
        }
    }

    pub fn blank(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
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
            us: String::new(),
            first_path: String::new(),
            final_path: String::new(),
            punch_attempts: 0,
            punch_upgraded: false,
            fell_back_to_relay: false,
        }
    }

    pub fn avg_echo_rtt_us(&self) -> f64 {
        avg(&self.echo_rtts_us)
    }

    /// Average echo RTT in milliseconds (derived from µs samples).
    pub fn avg_echo_rtt(&self) -> f64 {
        self.avg_echo_rtt_us() / 1000.0
    }

    pub fn percentile_echo_rtt_us(&self, p: f64) -> u64 {
        percentile(&self.echo_rtts_us, p)
    }

    pub fn mbps(&self) -> f64 {
        if self.wall_ms == 0 {
            return 0.0;
        }
        (self.bytes_sent as f64 * 8.0) / (self.wall_ms as f64 / 1000.0) / 1_000_000.0
    }
}

pub fn avg(samples: &[u64]) -> f64 {
    if samples.is_empty() {
        0.0
    } else {
        samples.iter().sum::<u64>() as f64 / samples.len() as f64
    }
}

pub fn percentile(samples: &[u64], p: f64) -> u64 {
    if samples.is_empty() {
        return 0;
    }
    let mut v = samples.to_vec();
    v.sort_unstable();
    let idx = ((p.clamp(0.0, 1.0) * (v.len() as f64 - 1.0)).round() as usize).min(v.len() - 1);
    v[idx]
}

pub struct DialOpts {
    pub addr: PeerAddr,
    pub count: u64,
    pub interval: Duration,
    pub payload: usize,
    pub builtin_ping: u64,
    pub quiet: bool,
    pub name: String,
    /// Stop sending after this wall duration (in addition to `count`).
    pub max_echo_duration: Option<Duration>,
    /// Store every Nth echo RTT (1 = all). Counts remain exact.
    pub rtt_sample_stride: u64,
    pub transport: TransportKind,
}

impl DialOpts {
    pub fn basic(
        name: impl Into<String>,
        addr: PeerAddr,
        count: u64,
        interval: Duration,
        payload: usize,
        builtin_ping: u64,
        transport: TransportKind,
    ) -> Self {
        Self {
            addr,
            count,
            interval,
            payload,
            builtin_ping,
            quiet: true,
            name: name.into(),
            max_echo_duration: None,
            rtt_sample_stride: 1,
            transport,
        }
    }
}

pub fn run_dial_collect(opts: DialOpts) -> DialResult {
    let name = opts.name.clone();
    match run_dial_collect_inner(opts) {
        Ok(r) => r,
        Err(e) => DialResult::fail(&name, e),
    }
}

fn wait_stream_ready(
    endpoint: &mut Endpoint,
    peer: &PeerId,
    stream: StreamId,
    timeout: Duration,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let deadline = Instant::now() + timeout;
    loop {
        let Some(event) = endpoint.next_event(deadline)? else {
            return Err("echo stream never became ready".into());
        };
        match event {
            Event::StreamReady {
                peer_id,
                stream_id,
                protocol_id,
                initiated_locally: true,
                ..
            } if peer_id == *peer && stream_id == stream && protocol_id == ECHO_PROTOCOL => {
                return Ok(());
            }
            Event::Error(err) => {
                let msg = format!("{err:?}");
                if msg.contains("StreamReset") {
                    continue;
                }
                return Err(format!("swarm error while opening stream: {err:?}").into());
            }
            _ => {}
        }
    }
}

fn open_echo(
    endpoint: &mut Endpoint,
    peer: &PeerId,
) -> Result<StreamId, Box<dyn std::error::Error + Send + Sync>> {
    let stream = endpoint.open_stream(peer, ECHO_PROTOCOL)?;
    wait_stream_ready(endpoint, peer, stream, Duration::from_secs(15))?;
    Ok(stream)
}

fn stream_gone(err: &dyn std::fmt::Display) -> bool {
    let msg = err.to_string();
    msg.contains("is not active") || msg.contains("StreamNotFound")
}

fn run_dial_collect_inner(
    opts: DialOpts,
) -> Result<DialResult, Box<dyn std::error::Error + Send + Sync>> {
    let quiet = opts.quiet;
    let stride = opts.rtt_sample_stride.max(1);
    let mut endpoint = build_endpoint(None, opts.transport)?;
    let _ = endpoint.listen_all()?;
    let t0 = Instant::now();

    let ids = endpoint.dial(&opts.addr)?;
    let dial_ms = millis(t0);
    if !quiet {
        println!("[dial] dial-started ids={ids:?} elapsed_ms={dial_ms}");
    }

    let peer = opts.addr.peer_id().clone();
    let _ready = endpoint
        .wait_peer_ready(&peer, Duration::from_secs(20))?
        .ok_or("identify timed out")?;
    let identify_ms = millis(t0);

    let mut builtin_ping_rtts_ms = Vec::new();
    for _ in 0..opts.builtin_ping {
        endpoint.ping(&peer)?;
        let rtt = endpoint
            .wait_ping_rtt(&peer, Duration::from_secs(5))?
            .ok_or("builtin ping timed out")?;
        builtin_ping_rtts_ms.push(rtt);
    }

    let stream = endpoint.open_stream(&peer, ECHO_PROTOCOL)?;
    wait_stream_ready(&mut endpoint, &peer, stream, Duration::from_secs(15))?;
    let echo_open_ms = millis(t0);

    let mut frames = FrameBuf::default();
    let mut outstanding: HashMap<u64, Instant> = HashMap::new();
    let mut sent = 0u64;
    let mut received = 0u64;
    let mut bytes_sent = 0u64;
    let mut bytes_recv = 0u64;
    let mut echo_rtts_us = Vec::new();
    let mut next_send = Instant::now();
    let mut closing = false;
    let echo_start = Instant::now();
    let frame_len = FRAME_LEN + opts.payload;
    // Cap in-flight echoes so we do not fill quiche stream queues (soak hazard).
    let max_outstanding: usize = if opts.payload >= 16 * 1024 {
        8
    } else if opts.payload >= 1024 {
        32
    } else {
        128
    };

    loop {
        let blocked = outstanding.len() >= max_outstanding;
        let wait_for = if closing {
            Instant::now() + Duration::from_secs(5)
        } else if blocked {
            Instant::now() + Duration::from_millis(5)
        } else {
            next_send
        };

        match endpoint.next_event(wait_for)? {
            None => {
                if closing {
                    break;
                }
                let duration_done = opts
                    .max_echo_duration
                    .is_some_and(|d| echo_start.elapsed() >= d);
                if sent >= opts.count || duration_done {
                    endpoint.close_stream_write(&peer, stream)?;
                    closing = true;
                    continue;
                }
                if outstanding.len() >= max_outstanding {
                    continue;
                }
                sent += 1;
                let seq = sent;
                let mut frame = encode_header(seq, millis(t0));
                if opts.payload > 0 {
                    frame.extend(std::iter::repeat_n(0xAB, opts.payload));
                }
                let len = frame.len() as u64;
                match endpoint.send_stream(&peer, stream, frame) {
                    Ok(()) => {
                        bytes_sent += len;
                        outstanding.insert(seq, Instant::now());
                        next_send = Instant::now() + opts.interval;
                    }
                    Err(err) => {
                        // Back off and drain; common under burst before flow control catches up.
                        // QUIC: "resource exhausted" / "queued"; TCP/Yamux: "send buffer is full".
                        if is_backpressure(&err) {
                            sent -= 1;
                            next_send = Instant::now() + Duration::from_millis(2);
                            continue;
                        }
                        return Err(format!("send_stream failed: {err}").into());
                    }
                }
            }
            Some(Event::StreamData {
                peer_id,
                stream_id,
                data,
                ..
            }) if peer_id == peer && stream_id == stream => {
                bytes_recv += data.len() as u64;
                frames.push(&data);
                while let Some(frame) = frames.pop(frame_len) {
                    if frame.len() < FRAME_LEN {
                        continue;
                    }
                    let (seq, _) = decode_header(&frame[..FRAME_LEN]);
                    if let Some(sent_at) = outstanding.remove(&seq) {
                        let rtt = sent_at.elapsed().as_micros() as u64;
                        received += 1;
                        push_rtt_sample(&mut echo_rtts_us, rtt, received, stride);
                    }
                }
                if closing && outstanding.is_empty() {
                    break;
                }
            }
            Some(Event::StreamRemoteWriteClosed {
                peer_id, stream_id, ..
            })
            | Some(Event::StreamClosed {
                peer_id, stream_id, ..
            }) if peer_id == peer && stream_id == stream => break,
            Some(Event::Error(err)) => return Err(format!("swarm error: {err:?}").into()),
            Some(_) => {}
        }
    }

    let wall_ms = echo_start.elapsed().as_millis() as u64;
    let stored = echo_rtts_us.len() as u64;
    Ok(DialResult {
        name: opts.name,
        ok: sent > 0 && received == sent,
        error: if received == sent {
            None
        } else {
            Some(format!("lost {} frames", sent.saturating_sub(received)))
        },
        dial_ms,
        identify_ms,
        echo_open_ms,
        wall_ms,
        sent,
        received,
        lost: sent.saturating_sub(received),
        bytes_sent,
        bytes_recv,
        builtin_ping_rtts_ms,
        echo_rtts_us,
        echo_rtt_samples_stored: stored,
        ..DialResult::blank("")
    })
}

/// One reconnect iteration: dial → identify → open → N echoes → drop Endpoint.
/// Fresh identity (unique PeerId) each call — this found the 0.4.1 leak.
pub fn run_reconnect_once(
    addr: &PeerAddr,
    echoes: u64,
    payload: usize,
    transport: TransportKind,
) -> Result<(u64, u64, Vec<u64>), Box<dyn std::error::Error + Send + Sync>> {
    let mut endpoint = build_endpoint(None, transport)?;
    let _ = endpoint.listen_all()?;
    let peer = addr.peer_id().clone();
    endpoint.dial(addr)?;
    let _ = endpoint
        .wait_peer_ready(&peer, Duration::from_secs(20))?
        .ok_or("identify timed out")?;
    let stream = endpoint.open_stream(&peer, ECHO_PROTOCOL)?;
    wait_stream_ready(&mut endpoint, &peer, stream, Duration::from_secs(15))?;

    let mut frames = FrameBuf::default();
    let mut outstanding: HashMap<u64, Instant> = HashMap::new();
    let mut sent = 0u64;
    let mut received = 0u64;
    let mut rtts = Vec::new();
    let mut next_send = Instant::now();
    let mut closing = false;
    let frame_len = FRAME_LEN + payload;
    let t0 = Instant::now();

    loop {
        let wait_for = if closing {
            Instant::now() + Duration::from_secs(5)
        } else {
            next_send
        };
        match endpoint.next_event(wait_for)? {
            None => {
                if closing {
                    break;
                }
                if sent >= echoes {
                    endpoint.close_stream_write(&peer, stream)?;
                    closing = true;
                    continue;
                }
                sent += 1;
                let mut frame = encode_header(sent, millis(t0));
                if payload > 0 {
                    frame.extend(std::iter::repeat_n(0xCD, payload));
                }
                match endpoint.send_stream(&peer, stream, frame) {
                    Ok(()) => {
                        outstanding.insert(sent, Instant::now());
                        next_send = Instant::now();
                    }
                    Err(err) => {
                        if is_backpressure(&err) {
                            sent -= 1;
                            next_send = Instant::now() + Duration::from_millis(2);
                            continue;
                        }
                        return Err(format!("send_stream failed: {err}").into());
                    }
                }
            }
            Some(Event::StreamData {
                peer_id,
                stream_id,
                data,
                ..
            }) if peer_id == peer && stream_id == stream => {
                frames.push(&data);
                while let Some(frame) = frames.pop(frame_len) {
                    if frame.len() < FRAME_LEN {
                        continue;
                    }
                    let (seq, _) = decode_header(&frame[..FRAME_LEN]);
                    if let Some(sent_at) = outstanding.remove(&seq) {
                        received += 1;
                        push_rtt_sample(
                            &mut rtts,
                            sent_at.elapsed().as_micros() as u64,
                            received,
                            1,
                        );
                    }
                }
                if closing && outstanding.is_empty() {
                    break;
                }
            }
            Some(Event::StreamRemoteWriteClosed {
                peer_id, stream_id, ..
            })
            | Some(Event::StreamClosed {
                peer_id, stream_id, ..
            }) if peer_id == peer && stream_id == stream => break,
            Some(Event::Error(err)) => return Err(format!("swarm error: {err:?}").into()),
            Some(_) => {}
        }
    }
    // Endpoint dropped here — critical for reconnect churn leak detection.
    Ok((sent, received, rtts))
}

pub fn run_listen_loop(
    bind: &str,
    transport: TransportKind,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    addr_tx: std::sync::mpsc::Sender<PeerAddr>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use std::sync::atomic::Ordering;

    let mut endpoint = build_endpoint(Some(bind), transport)?;
    let addrs = endpoint.listen_all()?;
    let first = addrs
        .into_iter()
        .next()
        .ok_or("listen produced no addresses")?;
    let _ = addr_tx.send(first);

    // HashMap avoids (PeerId, StreamId) tuple clones on every StreamData lookup.
    let mut streams: HashMap<PeerId, HashSet<StreamId>> = HashMap::new();
    while !stop.load(Ordering::SeqCst) {
        let Some(event) = endpoint.next_event(Duration::from_millis(100))? else {
            continue;
        };
        match event {
            Event::StreamReady {
                peer_id,
                stream_id,
                protocol_id,
                initiated_locally: false,
                ..
            } if protocol_id == ECHO_PROTOCOL => {
                streams.entry(peer_id).or_default().insert(stream_id);
            }
            Event::StreamData {
                peer_id,
                stream_id,
                data,
                ..
            } => {
                let active = streams
                    .get(&peer_id)
                    .is_some_and(|s| s.contains(&stream_id));
                if !active {
                    continue;
                }
                // Move owned Vec into send_stream — API requires Into<Vec<u8>>.
                if let Err(err) = endpoint.send_stream(&peer_id, stream_id, data) {
                    eprintln!("[listen] echo send failed: {err}");
                    if let Some(set) = streams.get_mut(&peer_id) {
                        set.remove(&stream_id);
                    }
                }
            }
            Event::StreamRemoteWriteClosed {
                peer_id, stream_id, ..
            } => {
                if streams
                    .get(&peer_id)
                    .is_some_and(|s| s.contains(&stream_id))
                {
                    let _ = endpoint.close_stream_write(&peer_id, stream_id);
                    if let Some(set) = streams.get_mut(&peer_id) {
                        set.remove(&stream_id);
                    }
                }
            }
            Event::StreamClosed {
                peer_id, stream_id, ..
            } => {
                if let Some(set) = streams.get_mut(&peer_id) {
                    set.remove(&stream_id);
                }
            }
            Event::Error(err) => eprintln!("[listen] swarm error: {err:?}"),
            _ => {}
        }
    }
    Ok(())
}

// --- WAN listen/dial via a public Circuit Relay v2 hop (punch enabled) ---

use minip2p::{Multiaddr, NatConfig, NatEvent, Path, Protocol, ReservationPolicy};

fn path_name(path: &Path) -> String {
    match path {
        Path::DirectDialed => "DirectDialed".into(),
        Path::DirectPunched => "DirectPunched".into(),
        Path::Relayed { relay } => format!("Relayed({relay})"),
    }
}

pub fn circuit_addr(relay: &PeerAddr, us: &PeerId) -> String {
    format!("{}/p2p-circuit/p2p/{us}", relay.to_multiaddr())
}

pub enum DialTarget {
    Direct(PeerAddr),
    Circuit { relay: PeerAddr, peer: PeerId },
}

pub fn parse_dial_target(raw: &str) -> Result<DialTarget, String> {
    let addr = Multiaddr::from_str(raw).map_err(|e| format!("invalid target '{raw}': {e}"))?;
    if !addr
        .protocols()
        .iter()
        .any(|p| matches!(p, Protocol::P2pCircuit))
    {
        let target =
            PeerAddr::from_str(raw).map_err(|e| format!("invalid target peer-addr '{raw}': {e}"))?;
        return Ok(DialTarget::Direct(target));
    }
    match addr.protocols() {
        [prefix @ .., Protocol::P2p(relay_id), Protocol::P2pCircuit, Protocol::P2p(peer)]
            if !prefix.is_empty() =>
        {
            let relay = PeerAddr::new(Multiaddr::from_protocols(prefix.to_vec()), relay_id.clone())
                .map_err(|e| format!("invalid relay in '{raw}': {e}"))?;
            Ok(DialTarget::Circuit {
                relay,
                peer: peer.clone(),
            })
        }
        _ => Err(format!(
            "circuit target must end /p2p/<relay>/p2p-circuit/p2p/<peer>, got '{raw}'"
        )),
    }
}

fn build_nat_endpoint(
    bind: &str,
    transport: TransportKind,
    relays: &[PeerAddr],
    policy: ReservationPolicy,
    force_relay: bool,
) -> Result<Endpoint, Box<dyn std::error::Error + Send + Sync>> {
    bind_endpoint(
        || {
            let mut cfg = NatConfig {
                reservation_policy: policy,
                force_relay,
                ..NatConfig::default()
            };
            cfg.relays.extend(relays.iter().cloned());
            let mut builder = Endpoint::builder()
                .agent_version(AGENT)
                .protocol(ECHO_PROTOCOL)
                .nat_config(cfg);
            for r in relays {
                builder = builder.relay(r.clone());
            }
            builder
        },
        transport,
        bind,
    )
}

fn print_nat(tag: &str, event: &NatEvent) {
    match event {
        NatEvent::RelayReserved {
            relay,
            expires_unix_secs,
            ..
        } => eprintln!("[{tag}] nat-relay-reserved relay={relay} expires-unix={expires_unix_secs:?}"),
        NatEvent::RelayReservationLost { relay } => {
            eprintln!("[{tag}] nat-reservation-lost relay={relay}")
        }
        NatEvent::PathEstablished { peer, path, .. } => {
            eprintln!("[{tag}] nat-path-established peer={peer} path={}", path_name(path))
        }
        NatEvent::PathUpgraded { peer, from, to, .. } => eprintln!(
            "[{tag}] nat-path-upgraded peer={peer} from={} to={}",
            path_name(from),
            path_name(to)
        ),
        NatEvent::FellBackToRelay { peer, .. } => {
            eprintln!("[{tag}] nat-fell-back-to-relay peer={peer}")
        }
        NatEvent::ConnectFailed { peer, error, .. } => {
            eprintln!("[{tag}] nat-connect-failed peer={peer} error={error:?}")
        }
        NatEvent::HolePunchFailed { attempt, reason, .. } => {
            eprintln!("[{tag}] nat-hole-punch-failed attempt={attempt} reason={reason}")
        }
        NatEvent::InboundDirectUpgrade { peer } => {
            eprintln!("[{tag}] nat-inbound-direct-upgrade peer={peer}")
        }
        NatEvent::InboundPathEstablished { peer, path } => {
            eprintln!("[{tag}] nat-inbound-path peer={peer} path={}", path_name(path))
        }
        other => eprintln!("[{tag}] nat {other:?}"),
    }
}

/// Listener that reserves on `relay` (Always, punch enabled) and echoes.
pub fn run_listen_relay(
    bind: &str,
    transport: TransportKind,
    relay: PeerAddr,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    addr_tx: std::sync::mpsc::Sender<String>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use std::sync::atomic::Ordering;
    let bind = if bind == "127.0.0.1:0" {
        "0.0.0.0:0"
    } else {
        bind
    };
    let mut endpoint = build_nat_endpoint(
        bind,
        transport,
        std::slice::from_ref(&relay),
        ReservationPolicy::Always,
        false,
    )?;
    let addrs = endpoint.listen_all()?;
    let us = endpoint.peer_id().clone();
    let _ = addr_tx.send(format!("us={us}"));
    for a in &addrs {
        let _ = addr_tx.send(format!("addr={a}"));
    }

    let until = Instant::now() + Duration::from_secs(20);
    let mut reserved = false;
    while Instant::now() < until {
        match endpoint.next_nat_event(until)? {
            Some(NatEvent::RelayReserved { .. }) => {
                let circuit = circuit_addr(&relay, &us);
                let _ = addr_tx.send(format!("circuit={circuit}"));
                reserved = true;
                break;
            }
            Some(ev) => print_nat("listen", &ev),
            None => break,
        }
    }
    if !reserved {
        let _ = addr_tx.send("warn=no reservation within 20s; still listening".into());
    }

    let mut streams: HashMap<PeerId, HashSet<StreamId>> = HashMap::new();
    while !stop.load(Ordering::SeqCst) {
        for ev in endpoint.take_nat_events() {
            print_nat("listen", &ev);
        }
        let Some(event) = endpoint.next_event(Duration::from_millis(100))? else {
            continue;
        };
        match event {
            Event::StreamReady {
                peer_id,
                stream_id,
                protocol_id,
                initiated_locally: false,
                ..
            } if protocol_id == ECHO_PROTOCOL => {
                streams.entry(peer_id).or_default().insert(stream_id);
            }
            Event::StreamData {
                peer_id,
                stream_id,
                data,
                ..
            } => {
                let active = streams
                    .get(&peer_id)
                    .is_some_and(|s| s.contains(&stream_id));
                if !active {
                    continue;
                }
                if let Err(err) = endpoint.send_stream(&peer_id, stream_id, data) {
                    eprintln!("[listen] echo send failed: {err}");
                    if let Some(set) = streams.get_mut(&peer_id) {
                        set.remove(&stream_id);
                    }
                }
            }
            Event::StreamRemoteWriteClosed {
                peer_id, stream_id, ..
            } => {
                if streams
                    .get(&peer_id)
                    .is_some_and(|s| s.contains(&stream_id))
                {
                    let _ = endpoint.close_stream_write(&peer_id, stream_id);
                    if let Some(set) = streams.get_mut(&peer_id) {
                        set.remove(&stream_id);
                    }
                }
            }
            Event::StreamClosed {
                peer_id, stream_id, ..
            } => {
                if let Some(set) = streams.get_mut(&peer_id) {
                    set.remove(&stream_id);
                }
            }
            Event::Error(err) => eprintln!("[listen] swarm error: {err:?}"),
            _ => {}
        }
    }
    Ok(())
}

/// Dial a direct or circuit target with the NAT agent (punch enabled).
pub fn run_dial_nat(
    target: DialTarget,
    extra_relay: Option<PeerAddr>,
    count: u64,
    interval: Duration,
    payload: usize,
    transport: TransportKind,
) -> DialResult {
    let name = "cli-dial-nat";
    match run_dial_nat_inner(target, extra_relay, count, interval, payload, transport) {
        Ok(r) => r,
        Err(e) => DialResult::fail(name, e),
    }
}

fn run_dial_nat_inner(
    target: DialTarget,
    extra_relay: Option<PeerAddr>,
    count: u64,
    interval: Duration,
    payload: usize,
    transport: TransportKind,
) -> Result<DialResult, Box<dyn std::error::Error + Send + Sync>> {
    let mut relays = Vec::new();
    if let DialTarget::Circuit { relay, .. } = &target {
        relays.push(relay.clone());
    }
    if let Some(extra) = extra_relay
        && !relays.iter().any(|r| r.peer_id() == extra.peer_id())
    {
        relays.push(extra);
    }
    if relays.is_empty() {
        return Err("dial --relay / circuit target required for NAT dial".into());
    }

    let mut endpoint = build_nat_endpoint(
        "0.0.0.0:0",
        transport,
        &relays,
        ReservationPolicy::Never,
        false,
    )?;
    let _ = endpoint.listen_all()?;
    eprintln!("[dial] us={}", endpoint.peer_id());

    let t0 = Instant::now();
    let (peer, connect_id) = match &target {
        DialTarget::Circuit { peer, relay } => {
            eprintln!("[dial] target={peer} via-relay={}", relay.peer_id());
            let id = endpoint.connect(peer)?;
            (peer.clone(), id)
        }
        DialTarget::Direct(addr) => {
            eprintln!("[dial] target={addr}");
            let id = endpoint.connect_addr(addr)?;
            (addr.peer_id().clone(), id)
        }
    };

    let path = endpoint.wait_path(connect_id, Duration::from_secs(25))?;
    let Some(path) = path else {
        for ev in endpoint.take_nat_events() {
            print_nat("dial", &ev);
        }
        return Err("no path to the target".into());
    };
    let first = path_name(&path);
    eprintln!(
        "[dial] path-established path={first} elapsed={}ms",
        t0.elapsed().as_millis()
    );

    let _ = endpoint.wait_peer_ready(&peer, Duration::from_secs(15))?;
    let mut stream = open_echo(&mut endpoint, &peer)?;
    let mut reopen = false;

    let mut frames = FrameBuf::default();
    let mut outstanding: HashMap<u64, Instant> = HashMap::new();
    let mut sent = 0u64;
    let mut received = 0u64;
    let mut rtts = Vec::new();
    let mut next_send = Instant::now();
    let mut last_path = first.clone();
    let mut punch_attempts = 0u32;
    let mut punch_upgraded = false;
    let mut fell_back = false;
    let mut fatal: Option<String> = None;
    let frame_len = FRAME_LEN + payload;
    let echo_t0 = Instant::now();
    let us = endpoint.peer_id().to_string();

    while received < count && fatal.is_none() {
        for ev in endpoint.take_nat_events() {
            match &ev {
                NatEvent::PathUpgraded { to, .. } => {
                    last_path = path_name(to);
                    if matches!(to, Path::DirectDialed | Path::DirectPunched) {
                        punch_upgraded = true;
                        reopen = true;
                    }
                }
                NatEvent::HolePunchFailed { .. } => punch_attempts += 1,
                NatEvent::FellBackToRelay { .. } => fell_back = true,
                _ => {}
            }
            print_nat("dial", &ev);
        }
        if reopen {
            match open_echo(&mut endpoint, &peer) {
                Ok(new_stream) => {
                    stream = new_stream;
                    reopen = false;
                    outstanding.clear();
                    eprintln!("[dial] echo-stream reopened path={last_path}");
                }
                Err(err) => {
                    eprintln!("[dial] echo-stream reopen failed: {err}");
                }
            }
        }
        match endpoint.next_event(next_send)? {
            Some(Event::StreamClosed {
                peer_id,
                stream_id,
                ..
            }) if peer_id == peer && stream_id == stream => {
                reopen = true;
            }
            None => {
                if sent >= count {
                    next_send = Instant::now() + Duration::from_millis(50);
                    continue;
                }
                sent += 1;
                let mut frame = encode_header(sent, millis(echo_t0));
                if payload > 0 {
                    frame.extend(std::iter::repeat_n(0xCD, payload));
                }
                match endpoint.send_stream(&peer, stream, frame) {
                    Ok(()) => {
                        outstanding.insert(sent, Instant::now());
                        next_send = Instant::now() + interval;
                    }
                    Err(err) if is_backpressure(&err) => {
                        sent -= 1;
                        next_send = Instant::now() + Duration::from_millis(2);
                    }
                    Err(err) if stream_gone(&err) => {
                        sent -= 1;
                        reopen = true;
                    }
                    Err(err) => {
                        fatal = Some(format!("send_stream: {err}"));
                    }
                }
            }
            Some(Event::StreamData {
                peer_id,
                stream_id,
                data,
                ..
            }) if peer_id == peer && stream_id == stream => {
                frames.push(&data);
                while let Some(frame) = frames.pop(frame_len) {
                    if frame.len() < FRAME_LEN {
                        continue;
                    }
                    let (seq, _) = decode_header(&frame[..FRAME_LEN]);
                    if let Some(sent_at) = outstanding.remove(&seq) {
                        received += 1;
                        rtts.push(sent_at.elapsed().as_micros() as u64);
                    }
                }
            }
            Some(Event::Error(err)) => {
                let msg = format!("{err:?}");
                if msg.contains("StreamReset") {
                    eprintln!("[dial] swarm error (ignored): {err:?}");
                } else {
                    fatal = Some(format!("swarm error: {err:?}"));
                }
            }
            Some(_) => {}
        }
        if echo_t0.elapsed() > Duration::from_secs(60) {
            break;
        }
    }

    let mut r = DialResult::blank("cli-dial-nat");
    r.us = us;
    r.first_path = first;
    r.final_path = last_path;
    r.punch_attempts = punch_attempts;
    r.punch_upgraded = punch_upgraded;
    r.fell_back_to_relay = fell_back;
    r.ok = fatal.is_none() && received == count && sent == count;
    r.sent = sent;
    r.received = received;
    r.lost = sent.saturating_sub(received);
    r.bytes_sent = sent * frame_len as u64;
    r.bytes_recv = received * frame_len as u64;
    r.echo_rtts_us = rtts;
    r.echo_rtt_samples_stored = r.echo_rtts_us.len() as u64;
    r.wall_ms = t0.elapsed().as_millis() as u64;
    r.error = fatal;
    Ok(r)
}

#[cfg(test)]
mod bind_tests {
    use super::*;

    #[test]
    fn wildcard_quic_advertises_ipv6_when_kernel_has_it() {
        let mut endpoint = build_endpoint(Some("0.0.0.0:0"), TransportKind::Quic).expect("bind");
        let addrs = endpoint.listen_all().expect("listen");
        let joined: Vec<String> = addrs.iter().map(|a| a.to_string()).collect();
        assert!(
            joined.iter().any(|a| a.contains("/ip4/")),
            "missing ipv4 listen addr: {joined:?}"
        );
        if std::net::UdpSocket::bind("[::]:0").is_ok() {
            assert!(
                joined.iter().any(|a| a.contains("/ip6/")),
                "missing ipv6 listen addr: {joined:?}"
            );
        }
    }
}
