//! Server side of the key exchange.

use std::sync::atomic::Ordering::Relaxed;

use http::StatusCode;
use hyper::body::Incoming;
use tracing::{debug, info, warn};

use super::sessions::Inserted;
use super::ServerState;
use crate::body::FrameReader;
use crate::crypto::{self, HELLO_LEN, HELLO_OK_LEN};
use crate::proto::{MSG_HELLO, VERSION};
use crate::stats::human_duration;
use crate::util::{short_id, unix_now};

/// Reads and answers a HELLO whose 2-byte prefix was already consumed.
pub(super) async fn accept(st: &ServerState, mut reader: FrameReader<Incoming>) -> Result<[u8; HELLO_OK_LEN], StatusCode> {
    let mut hello = [0u8; HELLO_LEN];
    hello[0] = VERSION;
    hello[1] = MSG_HELLO;
    let rest = reader.read_exact(HELLO_LEN - 2).await.map_err(|_| StatusCode::BAD_REQUEST)?;
    hello[2..].copy_from_slice(&rest);
    match establish(st, &hello) {
        Ok(reply) => {
            st.stats.handshake_ok();
            Ok(reply)
        }
        Err(reason) => {
            // Unauthenticated input: log quietly, the periodic summary reports the count.
            st.stats.handshake_failed();
            debug!("key exchange rejected: {reason}");
            Err(StatusCode::FORBIDDEN)
        }
    }
}

/// Authenticates the HELLO, checks freshness and creates the session.
fn establish(st: &ServerState, hello: &[u8; HELLO_LEN]) -> Result<[u8; HELLO_OK_LEN], String> {
    let view = crypto::parse_hello(hello).map_err(|e| e.to_string())?;
    let now = unix_now();
    let skew = st.cfg.max_clock_skew_secs;
    let drift = now.abs_diff(view.timestamp);
    if drift > skew {
        return Err(format!("timestamp differs from the server clock by {drift}s (max {skew}s)"));
    }
    let index = st
        .clients
        .iter()
        .position(|c| c.pairing.key_hint(view.timestamp) == view.key_hint)
        .ok_or("unknown pairing key")?;
    let client = &st.clients[index];
    crypto::verify_hello(&client.pairing, hello).map_err(|e| format!("client `{}`: {e}", client.name))?;
    st.hello_replay
        .lock()
        .insert(view.client_random, view.timestamp.saturating_add(skew), now)
        .map_err(|e| format!("client `{}`: {e}", client.name))?;

    let lifetime_secs = st.sessions.lifetime().as_secs() as u32;
    let (reply, est) = crypto::server_accept(&client.pairing, hello, &st.rng, lifetime_secs).map_err(|e| e.to_string())?;
    if let Inserted::EvictedActive = st.sessions.insert(est.session_id, index, est.keys)? {
        warn!(
            client = %client.name,
            "evicted a session that was still in use: is this pairing key shared by several client processes? \
             Give each client its own key (`webproxy add-client`)"
        );
    }
    client.last_handshake_unix.store(now, Relaxed);
    info!(
        client = %client.name,
        session = %short_id(&est.session_id),
        valid_for = %human_duration(lifetime_secs.into()),
        "new session keys established"
    );
    Ok(reply)
}
