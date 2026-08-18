//! Compact loopback Circuit Relay v2 hop: HOP RESERVE/CONNECT, STOP CONNECT, then byte-copy.

use std::collections::{HashMap, HashSet};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Duration;

use minip2p::{Endpoint, Event, PeerAddr, PeerId, StreamId};
use minip2p_relay::{
    decode_frame, encode_frame, FrameDecode, HopMessage, HopMessageType, Peer, Reservation, Status,
    StopMessage, StopMessageType, HOP_PROTOCOL_ID, STOP_PROTOCOL_ID,
};

use crate::common::TransportKind;

type Key = (PeerId, StreamId);

struct Pending {
    hop: Key,
    hop_trailing: Vec<u8>,
    stop_buf: Vec<u8>,
}

#[derive(Default)]
struct Hop {
    reserved: HashSet<PeerId>,
    hop_buf: HashMap<Key, Vec<u8>>,
    pending: HashMap<Key, Pending>,
    hop_to_stop: HashMap<Key, Key>,
    bridge: HashMap<Key, Key>,
}

fn hop_ok_reserve() -> Vec<u8> {
    encode_frame(
        &HopMessage {
            kind: HopMessageType::Status,
            peer: None,
            reservation: Some(Reservation {
                expire: Some(9_999_999_999),
                addrs: Vec::new(),
                voucher: None,
            }),
            limit: None,
            status: Some(Status::Ok),
        }
        .encode(),
    )
}

fn hop_status(status: Status) -> Vec<u8> {
    encode_frame(
        &HopMessage {
            kind: HopMessageType::Status,
            peer: None,
            reservation: None,
            limit: None,
            status: Some(status),
        }
        .encode(),
    )
}

fn stop_connect(initiator: &PeerId) -> Vec<u8> {
    encode_frame(
        &StopMessage {
            kind: StopMessageType::Connect,
            peer: Some(Peer {
                id: initiator.to_bytes(),
                addrs: Vec::new(),
            }),
            limit: None,
            status: None,
        }
        .encode(),
    )
}

impl Hop {
    fn handle(&mut self, ep: &mut Endpoint, event: Event) -> Result<(), String> {
        match event {
            Event::StreamReady {
                peer_id,
                stream_id,
                protocol_id,
                initiated_locally: false,
                ..
            } if protocol_id == HOP_PROTOCOL_ID => {
                self.hop_buf.entry((peer_id, stream_id)).or_default();
            }
            Event::StreamReady {
                peer_id,
                stream_id,
                protocol_id,
                initiated_locally: true,
                ..
            } if protocol_id == STOP_PROTOCOL_ID => {
                let key = (peer_id.clone(), stream_id);
                let bytes = stop_connect(&self.pending.get(&key).ok_or("STOP ready without CONNECT")?.hop.0);
                ep.send_stream(&peer_id, stream_id, bytes)
                    .map_err(|e| format!("send STOP CONNECT: {e}"))?;
            }
            Event::StreamData {
                peer_id,
                stream_id,
                data,
                ..
            } => self.on_data(ep, (peer_id, stream_id), data)?,
            Event::StreamRemoteWriteClosed {
                peer_id, stream_id, ..
            } => {
                if let Some((other, sid)) = self.bridge.get(&(peer_id, stream_id)).cloned() {
                    let _ = ep.close_stream_write(&other, sid);
                }
            }
            Event::StreamClosed {
                peer_id, stream_id, ..
            } => self.drop_stream(ep, &(peer_id, stream_id)),
            Event::ConnectionClosed { peer_id, .. } => {
                let dead: Vec<_> = self
                    .bridge
                    .keys()
                    .filter(|(p, _)| p == &peer_id)
                    .cloned()
                    .collect();
                for k in dead {
                    self.drop_stream(ep, &k);
                }
                self.hop_buf.retain(|(p, _), _| p != &peer_id);
                self.pending.retain(|(p, _), _| p != &peer_id);
                self.hop_to_stop
                    .retain(|(p, _), stop| p != &peer_id && stop.0 != peer_id);
            }
            _ => {}
        }
        Ok(())
    }

    fn on_data(&mut self, ep: &mut Endpoint, key: Key, data: Vec<u8>) -> Result<(), String> {
        if let Some((other, sid)) = self.bridge.get(&key).cloned() {
            ep.send_stream(&other, sid, data)
                .map_err(|e| format!("bridge forward: {e}"))?;
            return Ok(());
        }
        if let Some(stop) = self.hop_to_stop.get(&key).cloned() {
            if let Some(p) = self.pending.get_mut(&stop) {
                p.hop_trailing.extend(data);
            }
            return Ok(());
        }
        if self.pending.contains_key(&key) {
            return self.on_stop(ep, key, data);
        }
        let buf = match self.hop_buf.get_mut(&key) {
            Some(b) => b,
            None => return Ok(()),
        };
        buf.extend(data);
        let FrameDecode::Complete { payload, consumed } = decode_frame(buf) else {
            return Ok(());
        };
        let msg = HopMessage::decode(payload).map_err(|e| format!("decode HOP: {e}"))?;
        let trailing = buf[consumed..].to_vec();
        self.hop_buf.remove(&key);
        match msg.kind {
            HopMessageType::Reserve => {
                if !trailing.is_empty() {
                    return Err("trailing bytes after RESERVE".into());
                }
                self.reserved.insert(key.0.clone());
                ep.send_stream(&key.0, key.1, hop_ok_reserve())
                    .map_err(|e| format!("RESERVE reply: {e}"))?;
            }
            HopMessageType::Connect => {
                let raw = msg
                    .peer
                    .as_ref()
                    .map(|p| p.id.clone())
                    .ok_or("CONNECT missing peer")?;
                let target =
                    PeerId::from_bytes(&raw).map_err(|_| "CONNECT invalid peer id")?;
                if !self.reserved.contains(&target) {
                    ep.send_stream(&key.0, key.1, hop_status(Status::NoReservation))
                        .map_err(|e| format!("CONNECT refuse: {e}"))?;
                    return Ok(());
                }
                let stop = ep
                    .open_stream(&target, STOP_PROTOCOL_ID)
                    .map_err(|e| format!("open STOP: {e}"))?;
                let stop_key = (target, stop);
                self.hop_to_stop.insert(key.clone(), stop_key.clone());
                self.pending.insert(
                    stop_key,
                    Pending {
                        hop: key,
                        hop_trailing: trailing,
                        stop_buf: Vec::new(),
                    },
                );
            }
            other => return Err(format!("unexpected HOP {other:?}")),
        }
        Ok(())
    }

    fn on_stop(&mut self, ep: &mut Endpoint, key: Key, data: Vec<u8>) -> Result<(), String> {
        {
            let p = self.pending.get_mut(&key).expect("pending STOP");
            p.stop_buf.extend(data);
            if !matches!(decode_frame(&p.stop_buf), FrameDecode::Complete { .. }) {
                return Ok(());
            }
        }
        let p = self.pending.remove(&key).expect("complete STOP");
        self.hop_to_stop.remove(&p.hop);
        let FrameDecode::Complete { payload, consumed } = decode_frame(&p.stop_buf) else {
            return Err("STOP frame vanished".into());
        };
        let msg = StopMessage::decode(payload).map_err(|e| format!("decode STOP: {e}"))?;
        if msg.kind != StopMessageType::Status || msg.status != Some(Status::Ok) {
            return Err("expected STOP STATUS:OK".into());
        }
        let stop_trailing = p.stop_buf[consumed..].to_vec();
        ep.send_stream(&p.hop.0, p.hop.1, hop_status(Status::Ok))
            .map_err(|e| format!("HOP OK: {e}"))?;
        if !p.hop_trailing.is_empty() {
            ep.send_stream(&key.0, key.1, p.hop_trailing)
                .map_err(|e| format!("pipeline to dest: {e}"))?;
        }
        if !stop_trailing.is_empty() {
            ep.send_stream(&p.hop.0, p.hop.1, stop_trailing)
                .map_err(|e| format!("pipeline to src: {e}"))?;
        }
        self.bridge.insert(p.hop.clone(), key.clone());
        self.bridge.insert(key, p.hop);
        Ok(())
    }

    fn drop_stream(&mut self, ep: &mut Endpoint, key: &Key) {
        self.hop_buf.remove(key);
        if let Some(stop) = self.hop_to_stop.remove(key) {
            self.pending.remove(&stop);
            let _ = ep.reset_stream(&stop.0, stop.1);
        }
        if let Some(other) = self.bridge.remove(key) {
            self.bridge.remove(&other);
            let _ = ep.reset_stream(&other.0, other.1);
        }
    }
}

/// Background loopback relay with an address for NAT `relay()`.
pub struct RelayServer {
    addr: PeerAddr,
    stop: mpsc::Sender<()>,
    err: Arc<Mutex<Option<String>>>,
    join: Option<thread::JoinHandle<()>>,
}

impl RelayServer {
    pub fn spawn(transport: TransportKind) -> Result<Self, String> {
        let mut ep = {
            let b = Endpoint::builder()
                .protocol(HOP_PROTOCOL_ID)
                .protocol(STOP_PROTOCOL_ID);
            match transport {
                TransportKind::Quic => b.bind_quic("127.0.0.1:0").map_err(|e| format!("relay bind: {e}"))?,
                TransportKind::Tcp => b.bind_tcp("127.0.0.1:0").map_err(|e| format!("relay bind: {e}"))?,
            }
        };
        let addr = ep.listen().map_err(|e| format!("relay listen: {e}"))?;
        let (tx, rx) = mpsc::channel();
        let err = Arc::new(Mutex::new(None));
        let sink = Arc::clone(&err);
        let join = thread::spawn(move || {
            let mut hop = Hop::default();
            loop {
                match rx.try_recv() {
                    Ok(()) | Err(mpsc::TryRecvError::Disconnected) => break,
                    Err(mpsc::TryRecvError::Empty) => {}
                }
                match ep.next_event(Duration::from_millis(10)) {
                    Ok(Some(event)) => {
                        if let Err(e) = hop.handle(&mut ep, event) {
                            *sink.lock().expect("relay err") = Some(e);
                            break;
                        }
                    }
                    Ok(None) => {}
                    Err(e) => {
                        *sink.lock().expect("relay err") = Some(format!("relay endpoint: {e}"));
                        break;
                    }
                }
            }
        });
        Ok(Self {
            addr,
            stop: tx,
            err,
            join: Some(join),
        })
    }

    pub fn addr(&self) -> &PeerAddr {
        &self.addr
    }

    pub fn check(&self) -> Result<(), String> {
        match self.err.lock().expect("relay err").clone() {
            Some(e) => Err(format!("loopback relay failed: {e}")),
            None => Ok(()),
        }
    }
}

impl Drop for RelayServer {
    fn drop(&mut self) {
        let _ = self.stop.send(());
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}
