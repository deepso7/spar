//! Single-threaded NAT + circuit-relay soak scenarios.
//! All application endpoints live on one thread and are driven round-robin
//! via `next_event` (the NAT agent is fed by that poll). A loopback
//! [`RelayServer`] runs on its own thread as a service.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use minip2p::{
    ConnectId, Ed25519Keypair, Endpoint, Event, NatConfig, NatError, NatEvent, Path, PeerId,
    ReservationPolicy, StreamId,
};

use crate::common::{
    decode_header, encode_header, sample_mem, DialResult, FrameBuf, MemSample, TransportKind,
    AGENT, ECHO_PROTOCOL, FRAME_LEN, MAX_RTT_SAMPLES,
};
use crate::relay_server::RelayServer;

const DRIVE_SLICE: Duration = Duration::from_millis(5);
const PATH_DEADLINE: Duration = Duration::from_secs(15);
const RESERVE_DEADLINE: Duration = Duration::from_secs(10);
const ECHO_DEADLINE: Duration = Duration::from_secs(15);

fn path_kind(path: &Path) -> String {
    match path {
        Path::DirectDialed => "DirectDialed".into(),
        Path::DirectPunched => "DirectPunched".into(),
        Path::Relayed { relay } => format!("Relayed({relay})"),
    }
}

fn bind(
    builder: minip2p::EndpointBuilder,
    transport: TransportKind,
) -> Result<Endpoint, Box<dyn std::error::Error + Send + Sync>> {
    let ep = match transport {
        TransportKind::Quic => builder.bind_quic("127.0.0.1:0")?,
        TransportKind::Tcp => builder.bind_tcp("127.0.0.1:0")?,
    };
    Ok(ep)
}

fn nat_builder() -> minip2p::EndpointBuilder {
    Endpoint::builder()
        .agent_version(AGENT)
        .protocol(ECHO_PROTOCOL)
        .nat_config(NatConfig {
            reservation_policy: ReservationPolicy::Always,
            ..NatConfig::default()
        })
}

fn plain_builder() -> minip2p::EndpointBuilder {
    Endpoint::builder()
        .agent_version(AGENT)
        .protocol(ECHO_PROTOCOL)
}

fn drive_one(ep: &mut Endpoint, slice: Duration) -> Result<Option<Event>, String> {
    ep.next_event(slice).map_err(|e| format!("next_event: {e}"))
}

fn record_mem(log: &Arc<Mutex<Vec<(MemSample, String)>>>, t0: Instant, label: &str) {
    if let Some(s) = sample_mem(t0)
        && let Ok(mut g) = log.lock()
    {
        g.push((s, label.to_string()));
    }
}

fn finish_ok(
    name: &str,
    wall_ms: u64,
    path_ms: u64,
    sent: u64,
    received: u64,
    bytes_sent: u64,
    bytes_recv: u64,
    rtts: Vec<u64>,
    note: String,
) -> DialResult {
    let lost = sent.saturating_sub(received);
    let stored = rtts.len() as u64;
    let ok = lost == 0 && (sent == 0 || received == sent);
    DialResult {
        name: name.into(),
        ok,
        error: if ok {
            Some(note)
        } else {
            Some(format!(
                "{note}; lost {lost} frames (sent={sent} recv={received})"
            ))
        },
        dial_ms: path_ms,
        identify_ms: path_ms,
        echo_open_ms: 0,
        wall_ms,
        sent,
        received,
        lost,
        bytes_sent,
        bytes_recv,
        builtin_ping_rtts_ms: Vec::new(),
        echo_rtts_us: rtts,
        echo_rtt_samples_stored: stored,
    }
}

fn wrap_fail(name: &str, t0: Instant, err: impl ToString) -> DialResult {
    let mut r = DialResult::fail(name, err);
    r.wall_ms = t0.elapsed().as_millis() as u64;
    r
}

/// Round-robin `next_event` on every endpoint. NAT events are drained so the
/// agent queue does not stall; swarm events are returned per endpoint.
fn drive_step(eps: &mut [Endpoint], start: usize) -> Result<Vec<Vec<Event>>, String> {
    let n = eps.len();
    let mut collected = vec![Vec::new(); n];
    for k in 0..n {
        let i = (start + k) % n;
        match drive_one(&mut eps[i], DRIVE_SLICE)? {
            Some(ev) => collected[i].push(ev),
            None => {}
        }
        // NAT events stay queued for the caller (wait_path / take_nat_events).
        // Swallowing them here would drop PathEstablished.
    }
    Ok(collected)
}

fn wait_peer_ready_rr(
    eps: &mut [Endpoint],
    idx: usize,
    peer: &PeerId,
    deadline: Duration,
) -> Result<(), String> {
    let until = Instant::now() + deadline;
    while !eps[idx].is_peer_ready(peer) {
        if Instant::now() >= until {
            return Err(format!("identify timed out for {peer}"));
        }
        let _ = drive_step(eps, idx)?;
    }
    Ok(())
}

/// Echo `n` frames from initiator → responder over an already-established path.
/// Both endpoints must live in `eps` and are driven together.
fn echo_n(
    eps: &mut [Endpoint],
    init: usize,
    resp: usize,
    n: u64,
) -> Result<(u64, u64, u64, u64, Vec<u64>), String> {
    let resp_peer = eps[resp].peer_id().clone();
    let init_peer = eps[init].peer_id().clone();
    wait_peer_ready_rr(eps, init, &resp_peer, Duration::from_secs(10))?;

    let stream = eps[init]
        .open_stream(&resp_peer, ECHO_PROTOCOL)
        .map_err(|e| format!("open_stream: {e}"))?;

    let until_ready = Instant::now() + Duration::from_secs(10);
    let mut init_ready = false;
    let mut resp_stream: Option<StreamId> = None;
    while !init_ready || resp_stream.is_none() {
        if Instant::now() >= until_ready {
            return Err("echo stream never became ready".into());
        }
        let step = drive_step(eps, init)?;
        for ev in &step[init] {
            if let Event::StreamReady {
                peer_id,
                stream_id,
                protocol_id,
                initiated_locally: true,
                ..
            } = ev
                && *peer_id == resp_peer
                && *stream_id == stream
                && protocol_id == ECHO_PROTOCOL
            {
                init_ready = true;
            }
        }
        for ev in &step[resp] {
            if let Event::StreamReady {
                peer_id,
                stream_id,
                protocol_id,
                initiated_locally: false,
                ..
            } = ev
                && *peer_id == init_peer
                && protocol_id == ECHO_PROTOCOL
            {
                resp_stream = Some(*stream_id);
            }
        }
    }
    let resp_stream = resp_stream.expect("responder stream");

    let mut frames = FrameBuf::default();
    let mut outstanding: HashMap<u64, Instant> = HashMap::new();
    let mut sent = 0u64;
    let mut received = 0u64;
    let mut bytes_sent = 0u64;
    let mut bytes_recv = 0u64;
    let mut rtts = Vec::new();
    let frame_len = FRAME_LEN;
    let echo_until = Instant::now() + ECHO_DEADLINE;
    let t0 = Instant::now();

    while received < n {
        if Instant::now() >= echo_until {
            return Err(format!("echo timed out sent={sent} recv={received} want={n}"));
        }
        if sent < n && outstanding.is_empty() {
            sent += 1;
            let seq = sent;
            let frame = encode_header(seq, t0.elapsed().as_millis() as u64);
            let len = frame.len() as u64;
            eps[init]
                .send_stream(&resp_peer, stream, frame)
                .map_err(|e| format!("send_stream seq {seq}: {e}"))?;
            bytes_sent += len;
            outstanding.insert(seq, Instant::now());
        }
        let step = drive_step(eps, init)?;
        for ev in &step[resp] {
            if let Event::StreamData {
                peer_id,
                stream_id,
                data,
                ..
            } = ev
                && *peer_id == init_peer
                && *stream_id == resp_stream
            {
                if let Err(e) = eps[resp].send_stream(&init_peer, resp_stream, data.clone()) {
                    return Err(format!("responder echo send: {e}"));
                }
            }
        }
        for ev in &step[init] {
            if let Event::StreamData {
                peer_id,
                stream_id,
                data,
                ..
            } = ev
                && *peer_id == resp_peer
                && *stream_id == stream
            {
                bytes_recv += data.len() as u64;
                frames.push(data);
                while let Some(frame) = frames.pop(frame_len) {
                    if frame.len() < FRAME_LEN {
                        continue;
                    }
                    let (seq, _) = decode_header(&frame[..FRAME_LEN]);
                    if let Some(sent_at) = outstanding.remove(&seq) {
                        received += 1;
                        if rtts.len() < MAX_RTT_SAMPLES {
                            rtts.push(sent_at.elapsed().as_micros() as u64);
                        }
                    }
                }
            }
        }
    }
    Ok((sent, received, bytes_sent, bytes_recv, rtts))
}

fn wait_path_established(
    eps: &mut [Endpoint],
    init: usize,
    id: ConnectId,
    deadline: Duration,
) -> Result<(Path, u64), String> {
    let t0 = Instant::now();
    let until = Instant::now() + deadline;
    let mut failed: Option<String> = None;
    loop {
        // Drain NAT events *before* driving so a PathEstablished produced by
        // the previous step (or by connect() itself) is not discarded.
        for event in eps[init].take_nat_events() {
            match event {
                NatEvent::PathEstablished {
                    connect_id,
                    path,
                    ..
                } if connect_id == id => {
                    return Ok((path, t0.elapsed().as_millis() as u64));
                }
                NatEvent::ConnectFailed {
                    connect_id,
                    error,
                    ..
                } if connect_id == id => {
                    failed = Some(format!("ConnectFailed: {error:?}"));
                }
                _ => {}
            }
        }
        if let Some(msg) = failed {
            return Err(msg);
        }
        if Instant::now() >= until {
            return Err(format!("wait_path timed out after {:?}", deadline));
        }
        let _ = drive_step(eps, init)?;
    }
}

fn disconnect_and_clear_path(
    eps: &mut [Endpoint],
    init: usize,
    peer: &PeerId,
) -> Result<(), String> {
    eps[init]
        .disconnect(peer)
        .map_err(|e| format!("disconnect: {e}"))?;
    let until = Instant::now() + Duration::from_secs(5);
    while eps[init].path(peer).is_some() || eps[init].connected_peers().contains(peer) {
        if Instant::now() >= until {
            return Err(format!(
                "path did not clear after disconnect (path={:?} connected={})",
                eps[init].path(peer),
                eps[init].connected_peers().contains(peer)
            ));
        }
        let _ = drive_step(eps, init)?;
    }
    if eps[init].path(peer).is_some() {
        return Err("path() still Some after disconnect".into());
    }
    Ok(())
}

fn run_direct_path(
    name: &str,
    echoes: u64,
    transport: TransportKind,
    mem_log: &Arc<Mutex<Vec<(MemSample, String)>>>,
    suite_t0: Instant,
) -> DialResult {
    eprintln!("[suite] running {name} …");
    record_mem(mem_log, suite_t0, &format!("before-{name}"));
    let t_scen = Instant::now();
    let result = (|| -> Result<DialResult, Box<dyn std::error::Error + Send + Sync>> {
        let mut a = bind(nat_builder(), transport)?;
        let mut b = bind(plain_builder(), transport)?;
        let b_addr = b.listen()?;
        a.listen()?;
        let b_peer = b_addr.peer_id().clone();
        let id = a.connect_addr(&b_addr)?;

        let mut eps = [a, b];
        let (path, path_ms) = wait_path_established(&mut eps, 0, id, PATH_DEADLINE)?;
        if !matches!(path, Path::DirectDialed) {
            return Err(format!("expected DirectDialed, got {}", path_kind(&path)).into());
        }
        if !matches!(eps[0].path(&b_peer), Some(Path::DirectDialed)) {
            return Err("path() did not survive PathEstablished consumption".into());
        }

        let (sent, received, bytes_sent, bytes_recv, rtts) = if echoes == 0 {
            wait_peer_ready_rr(&mut eps, 0, &b_peer, Duration::from_secs(10))?;
            eps[0]
                .ping(&b_peer)
                .map_err(|e| format!("ping: {e}"))?;
            let ping_until = Instant::now() + Duration::from_secs(5);
            let mut pinged = false;
            while Instant::now() < ping_until && !pinged {
                let step = drive_step(&mut eps, 0)?;
                for ev in &step[0] {
                    if let Event::PingRttMeasured { peer_id, .. } = ev
                        && *peer_id == b_peer
                    {
                        pinged = true;
                    }
                }
            }
            if !pinged {
                return Err("builtin ping timed out".into());
            }
            (0, 0, 0, 0, Vec::new())
        } else {
            echo_n(&mut eps, 0, 1, echoes)?
        };

        disconnect_and_clear_path(&mut eps, 0, &b_peer)?;
        drop(eps);
        Ok(finish_ok(
            name,
            t_scen.elapsed().as_millis() as u64,
            path_ms,
            sent,
            received,
            bytes_sent,
            bytes_recv,
            rtts,
            format!("path={}", path_kind(&path)),
        ))
    })();
    record_mem(mem_log, suite_t0, &format!("after-{name}"));
    let r = match result {
        Ok(r) => r,
        Err(e) => wrap_fail(name, t_scen, e),
    };
    eprintln!(
        "[suite] {name} ok={} sent={} recv={} lost={} avg_rtt_us={:.1} wall_ms={} note={}",
        r.ok,
        r.sent,
        r.received,
        r.lost,
        r.avg_echo_rtt_us(),
        r.wall_ms,
        r.error.clone().unwrap_or_default()
    );
    r
}

fn run_nopath(
    transport: TransportKind,
    mem_log: &Arc<Mutex<Vec<(MemSample, String)>>>,
    suite_t0: Instant,
) -> DialResult {
    let name = "nat-nopath";
    eprintln!("[suite] running {name} …");
    record_mem(mem_log, suite_t0, &format!("before-{name}"));
    let t_scen = Instant::now();
    let result = (|| -> Result<DialResult, Box<dyn std::error::Error + Send + Sync>> {
        let mut a = bind(nat_builder(), transport)?;
        a.listen()?;
        let stranger = Ed25519Keypair::generate().peer_id();
        let id = a.connect(&stranger)?;
        // Single endpoint: wait_path drives the NAT agent.
        let path = a.wait_path(id, Duration::from_secs(2))?;
        if path.is_some() {
            return Err(format!("unexpected path {path:?}").into());
        }
        let events = a.take_nat_events();
        let failed_ok = events.iter().any(|event| {
            matches!(
                event,
                NatEvent::ConnectFailed {
                    connect_id,
                    error: NatError::NoPathAvailable,
                    ..
                } if *connect_id == id
            )
        });
        if !failed_ok {
            return Err(format!("expected ConnectFailed/NoPathAvailable, got {events:?}").into());
        }
        drop(a);
        Ok(finish_ok(
            name,
            t_scen.elapsed().as_millis() as u64,
            t_scen.elapsed().as_millis() as u64,
            0,
            0,
            0,
            0,
            Vec::new(),
            "ConnectFailed/NoPathAvailable (expected)".into(),
        ))
    })();
    record_mem(mem_log, suite_t0, &format!("after-{name}"));
    let r = match result {
        Ok(r) => r,
        Err(e) => wrap_fail(name, t_scen, e),
    };
    eprintln!(
        "[suite] {name} ok={} wall_ms={} note={}",
        r.ok,
        r.wall_ms,
        r.error.clone().unwrap_or_default()
    );
    r
}

fn spawn_relay(transport: TransportKind) -> Result<RelayServer, String> {
    match transport {
        TransportKind::Quic => RelayServer::spawn(),
        TransportKind::Tcp => RelayServer::spawn_tcp(),
    }
}

fn wait_reserved(
    ep: &mut Endpoint,
    relay_peer: &PeerId,
    relay: &RelayServer,
) -> Result<(), String> {
    let until = Instant::now() + RESERVE_DEADLINE;
    loop {
        if Instant::now() >= until {
            return Err(format!(
                "responder did not reserve; relay_trace={:?}",
                relay.trace()
            ));
        }
        let _ = drive_one(ep, DRIVE_SLICE)?;
        if ep.take_nat_events().iter().any(
            |event| matches!(event, NatEvent::RelayReserved { relay, .. } if relay == relay_peer),
        ) {
            return Ok(());
        }
        relay.check()?;
    }
}

fn run_circuit_echo(
    transport: TransportKind,
    mem_log: &Arc<Mutex<Vec<(MemSample, String)>>>,
    suite_t0: Instant,
) -> DialResult {
    let name = "nat-circuit-echo-10";
    eprintln!("[suite] running {name} …");
    record_mem(mem_log, suite_t0, &format!("before-{name}"));
    let t_scen = Instant::now();
    let result = (|| -> Result<DialResult, Box<dyn std::error::Error + Send + Sync>> {
        let relay = spawn_relay(transport).map_err(|e| format!("relay spawn: {e}"))?;
        let relay_addr = relay.addr().clone();
        let relay_peer = relay_addr.peer_id().clone();

        let mut responder = bind(
            Endpoint::builder()
                .agent_version(AGENT)
                .protocol(ECHO_PROTOCOL)
                .relay(relay_addr.clone())
                .nat_config(NatConfig {
                    reservation_policy: ReservationPolicy::Always,
                    ..NatConfig::default()
                }),
            transport,
        )?;
        responder.listen()?;
        wait_reserved(&mut responder, &relay_peer, &relay)?;

        let mut initiator = bind(
            Endpoint::builder()
                .agent_version(AGENT)
                .protocol(ECHO_PROTOCOL)
                .relay(relay_addr.clone())
                .nat_config(NatConfig {
                    reservation_policy: ReservationPolicy::Never,
                    ..NatConfig::default()
                }),
            transport,
        )?;
        initiator.listen()?;
        let responder_peer = responder.peer_id().clone();
        let id = initiator
            .connect(&responder_peer)
            .map_err(|e| format!("connect(peer): {e}"))?;

        let mut eps = [initiator, responder];
        let (path, path_ms) = wait_path_established(&mut eps, 0, id, PATH_DEADLINE)
            .map_err(|e| {
                format!(
                    "{e}; relay_trace={:?}; relay_err={:?}",
                    relay.trace(),
                    relay.check().err()
                )
            })?;
        relay.check().map_err(|e| e.to_string())?;

        let kind = path_kind(&path);
        let (sent, received, bytes_sent, bytes_recv, rtts) = echo_n(&mut eps, 0, 1, 10)
            .map_err(|e| format!("echo over {kind}: {e}"))?;
        relay.check().map_err(|e| e.to_string())?;

        let final_path = eps[0]
            .path(&responder_peer)
            .map(|p| path_kind(&p))
            .unwrap_or_else(|| "none".into());
        drop(eps);
        drop(relay);
        Ok(finish_ok(
            name,
            t_scen.elapsed().as_millis() as u64,
            path_ms,
            sent,
            received,
            bytes_sent,
            bytes_recv,
            rtts,
            format!("first_path={kind} final_path={final_path}"),
        ))
    })();
    record_mem(mem_log, suite_t0, &format!("after-{name}"));
    let r = match result {
        Ok(r) => r,
        Err(e) => wrap_fail(name, t_scen, e),
    };
    eprintln!(
        "[suite] {name} ok={} sent={} recv={} lost={} avg_rtt_us={:.1} wall_ms={} note={}",
        r.ok,
        r.sent,
        r.received,
        r.lost,
        r.avg_echo_rtt_us(),
        r.wall_ms,
        r.error.clone().unwrap_or_default()
    );
    r
}

/// Run the NAT / circuit scenarios. Circuit is attempted; a real failure is
/// reported as a failed scenario (not a fake pass).
pub fn run_nat_scenarios(
    transport: TransportKind,
    mem_log: &Arc<Mutex<Vec<(MemSample, String)>>>,
    suite_t0: Instant,
) -> Vec<DialResult> {
    let mut out = Vec::new();
    out.push(run_direct_path(
        "nat-direct-path",
        0,
        transport,
        mem_log,
        suite_t0,
    ));
    out.push(run_nopath(transport, mem_log, suite_t0));
    out.push(run_direct_path(
        "nat-direct-echo-20",
        20,
        transport,
        mem_log,
        suite_t0,
    ));
    out.push(run_circuit_echo(transport, mem_log, suite_t0));
    out
}
