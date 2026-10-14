//! Key exchange and frame encryption.
//!
//! Pairing: client and server share a 32-byte pairing key (PSK). It never encrypts traffic
//! directly; it only authenticates the key exchange.
//!
//! Key exchange (one round trip, repeated every `rekey_interval`):
//!
//! ```text
//! C -> S  HELLO    = ver | type | key_hint(8) | unix_ts(8) | client_random(32) | eph_C(32) | HMAC(mac_key, ..)(32)
//! S -> C  HELLO_OK = ver | type | session_id(16) | eph_S(32) | lifetime_secs(4) | confirm(32)
//!
//! th        = SHA-256(label | HELLO | HELLO_OK[..54])
//! prk       = HKDF-Extract(salt = PSK-derived salt, ikm = X25519(eph_C, eph_S))
//! c2s, s2c  = HKDF-Expand(prk, "c2s"|th), HKDF-Expand(prk, "s2c"|th)
//! confirm   = HMAC(HKDF-Expand(prk, "confirm"|th), "server-finished")
//! ```
//!
//! `key_hint` = HMAC(id_key, unix_ts / 600)[..8] lets the server find the pairing key without
//! giving the CDN a constant identifier to link sessions with.
//!
//! Ephemeral X25519 keys give forward secrecy; the PSK-derived MAC / salt stop a
//! man-in-the-middle (e.g. the CDN) from substituting its own keys. Each request uses
//! fresh keys `HKDF-Expand(c2s|s2c, "request"|"response" | seq)`, so frame nonces can simply
//! be a counter (plus the LAST flag) without any risk of reuse.

use base64::Engine;
use bytes::{BufMut, Bytes, BytesMut};
use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::agreement::{self, EphemeralPrivateKey, UnparsedPublicKey, X25519};
use ring::rand::{SecureRandom, SystemRandom};
use ring::{digest, hkdf, hmac};
use zeroize::Zeroizing;

use crate::proto::{ProtoError, FRAME_SIZE, KEY_HINT_LEN, MAX_HEAD_LEN, MSG_HELLO, MSG_HELLO_OK, SESSION_ID_LEN, VERSION};

pub const PAIRING_KEY_LEN: usize = 32;
pub const TAG_LEN: usize = 16;
pub const FRAME_HDR_LEN: usize = 4;
/// Per-frame overhead on the wire.
pub const FRAME_OVERHEAD: usize = FRAME_HDR_LEN + TAG_LEN;
const LAST_FLAG: u32 = 1 << 31;
/// Largest ciphertext a peer may send in one frame (heads can exceed FRAME_SIZE).
pub const MAX_FRAME_CT: usize = MAX_HEAD_LEN + TAG_LEN;

pub const HELLO_LEN: usize = 2 + KEY_HINT_LEN + 8 + 32 + 32 + 32;
/// Seconds per key-hint period.
const HINT_PERIOD_SECS: u64 = 600;
pub const HELLO_OK_LEN: usize = 2 + SESSION_ID_LEN + 32 + 4 + 32;
const HELLO_MAC_OFFSET: usize = HELLO_LEN - 32;
const HELLO_OK_CONFIRM_OFFSET: usize = HELLO_OK_LEN - 32;

struct Len(usize);

impl hkdf::KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}

fn expand<const N: usize>(prk: &hkdf::Prk, info: &[&[u8]]) -> Zeroizing<[u8; N]> {
    let mut out = Zeroizing::new([0u8; N]);
    prk.expand(info, Len(N))
        .and_then(|okm| okm.fill(out.as_mut()))
        .expect("HKDF-SHA256 output of <= 32 bytes is always valid");
    out
}

pub fn fill_random(rng: &SystemRandom, buf: &mut [u8]) -> Result<(), ProtoError> {
    rng.fill(buf).map_err(|_| ProtoError("system random number generator failed"))
}

/// Raw pairing secret; wiped when dropped.
pub type PairingSecret = Zeroizing<[u8; PAIRING_KEY_LEN]>;

/// Decodes a base64 pairing key (standard or URL-safe alphabet, padding optional).
pub fn parse_pairing_key(s: &str) -> Result<PairingSecret, String> {
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
    let s = s.trim();
    let bytes = [STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD]
        .iter()
        .find_map(|e| e.decode(s).ok().map(Zeroizing::new))
        .ok_or_else(|| "pairing key is not valid base64".to_string())?;
    if bytes.len() != PAIRING_KEY_LEN {
        return Err(format!("pairing key must be {PAIRING_KEY_LEN} bytes, got {}", bytes.len()));
    }
    let mut secret = Zeroizing::new([0u8; PAIRING_KEY_LEN]);
    secret.copy_from_slice(&bytes);
    Ok(secret)
}

pub fn generate_pairing_key() -> Result<String, ProtoError> {
    let mut k = Zeroizing::new([0u8; PAIRING_KEY_LEN]);
    fill_random(&SystemRandom::new(), k.as_mut())?;
    Ok(base64::engine::general_purpose::STANDARD.encode(k.as_ref()))
}

/// Long-term pairing secret, pre-processed into its sub-keys.
pub struct PairingKey {
    id_key: hmac::Key,
    hello_mac: hmac::Key,
    session_salt: hkdf::Salt,
}

impl PairingKey {
    pub fn new(secret: &[u8; PAIRING_KEY_LEN]) -> Self {
        let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, b"webproxy/v1 pairing").extract(secret);
        let id: Zeroizing<[u8; 32]> = expand(&prk, &[b"key-hint"]);
        let mac: Zeroizing<[u8; 32]> = expand(&prk, &[b"hello-mac"]);
        let salt: Zeroizing<[u8; 32]> = expand(&prk, &[b"session-salt"]);
        Self {
            id_key: hmac::Key::new(hmac::HMAC_SHA256, id.as_ref()),
            hello_mac: hmac::Key::new(hmac::HMAC_SHA256, mac.as_ref()),
            session_salt: hkdf::Salt::new(hkdf::HKDF_SHA256, salt.as_ref()),
        }
    }

    /// Lookup hint carried by HELLOs sent at `unix_ts`; it changes every HINT_PERIOD_SECS.
    pub fn key_hint(&self, unix_ts: u64) -> [u8; KEY_HINT_LEN] {
        let tag = hmac::sign(&self.id_key, &(unix_ts / HINT_PERIOD_SECS).to_be_bytes());
        tag.as_ref()[..KEY_HINT_LEN].try_into().expect("HMAC-SHA256 is longer than the hint")
    }
}

/// Traffic secrets of one session (wiped on drop); per-request keys are derived from them.
pub struct SessionKeys {
    c2s: Zeroizing<[u8; 32]>,
    s2c: Zeroizing<[u8; 32]>,
}

/// Keys for one request/response exchange.
pub struct RequestKeys {
    /// Encrypts the request (client -> server).
    pub c2s: LessSafeKey,
    /// Encrypts the response (server -> client).
    pub s2c: LessSafeKey,
}

impl SessionKeys {
    pub fn request_keys(&self, seq: u64) -> RequestKeys {
        let s = seq.to_be_bytes();
        let derive = |secret: &[u8; 32], label: &[u8]| {
            let prk = hkdf::Prk::new_less_safe(hkdf::HKDF_SHA256, secret);
            let info = [label, &s];
            let okm = prk
                .expand(&info, &aead::CHACHA20_POLY1305)
                .expect("HKDF output length equals the AEAD key length");
            LessSafeKey::new(UnboundKey::from(okm))
        };
        RequestKeys { c2s: derive(&self.c2s, b"request"), s2c: derive(&self.s2c, b"response") }
    }
}

fn transcript_hash(hello: &[u8], hello_ok_without_confirm: &[u8]) -> digest::Digest {
    let mut ctx = digest::Context::new(&digest::SHA256);
    ctx.update(b"webproxy/v1 transcript");
    ctx.update(hello);
    ctx.update(hello_ok_without_confirm);
    ctx.finish()
}

fn derive_session(pairing: &PairingKey, shared: &[u8], th: &[u8]) -> (SessionKeys, hmac::Key) {
    let prk = pairing.session_salt.extract(shared);
    let confirm: Zeroizing<[u8; 32]> = expand(&prk, &[b"confirm", th]);
    (
        SessionKeys { c2s: expand(&prk, &[b"c2s", th]), s2c: expand(&prk, &[b"s2c", th]) },
        hmac::Key::new(hmac::HMAC_SHA256, confirm.as_ref()),
    )
}

/// Client side of an in-flight handshake.
pub struct PendingHello {
    msg: [u8; HELLO_LEN],
    eph: EphemeralPrivateKey,
}

impl PendingHello {
    pub fn message(&self) -> &[u8] {
        &self.msg
    }
}

pub fn client_hello(pairing: &PairingKey, rng: &SystemRandom, unix_now: u64) -> Result<PendingHello, ProtoError> {
    let eph = EphemeralPrivateKey::generate(&X25519, rng).map_err(|_| ProtoError("key generation failed"))?;
    let public = eph.compute_public_key().map_err(|_| ProtoError("key generation failed"))?;
    let mut msg = [0u8; HELLO_LEN];
    msg[0] = VERSION;
    msg[1] = MSG_HELLO;
    msg[2..10].copy_from_slice(&pairing.key_hint(unix_now));
    msg[10..18].copy_from_slice(&unix_now.to_be_bytes());
    fill_random(rng, &mut msg[18..50])?;
    msg[50..82].copy_from_slice(public.as_ref());
    let tag = hmac::sign(&pairing.hello_mac, &msg[..HELLO_MAC_OFFSET]);
    msg[HELLO_MAC_OFFSET..].copy_from_slice(tag.as_ref());
    Ok(PendingHello { msg, eph })
}

/// Result of a successful handshake.
pub struct Established {
    pub session_id: [u8; SESSION_ID_LEN],
    pub lifetime_secs: u32,
    pub keys: SessionKeys,
}

pub fn client_finish(pairing: &PairingKey, pending: PendingHello, resp: &[u8]) -> Result<Established, ProtoError> {
    if resp.len() != HELLO_OK_LEN || resp[0] != VERSION || resp[1] != MSG_HELLO_OK {
        return Err(ProtoError("malformed handshake response"));
    }
    let th = transcript_hash(&pending.msg, &resp[..HELLO_OK_CONFIRM_OFFSET]);
    let peer = UnparsedPublicKey::new(&X25519, &resp[18..50]);
    let (keys, confirm_key) = agreement::agree_ephemeral(pending.eph, &peer, |shared| {
        derive_session(pairing, shared, th.as_ref())
    })
    .map_err(|_| ProtoError("invalid server key share"))?;
    hmac::verify(&confirm_key, b"server-finished", &resp[HELLO_OK_CONFIRM_OFFSET..])
        .map_err(|_| ProtoError("server failed authentication (wrong pairing key or tampered handshake)"))?;
    let mut session_id = [0u8; SESSION_ID_LEN];
    session_id.copy_from_slice(&resp[2..18]);
    let lifetime_secs = u32::from_be_bytes(resp[50..54].try_into().unwrap());
    Ok(Established { session_id, lifetime_secs, keys })
}

/// Unauthenticated view of a HELLO message (verify with [`verify_hello`] before trusting it).
pub struct HelloView {
    pub key_hint: [u8; KEY_HINT_LEN],
    pub timestamp: u64,
    pub client_random: [u8; 32],
}

pub fn parse_hello(msg: &[u8]) -> Result<HelloView, ProtoError> {
    if msg.len() != HELLO_LEN || msg[0] != VERSION || msg[1] != MSG_HELLO {
        return Err(ProtoError("malformed hello"));
    }
    Ok(HelloView {
        key_hint: msg[2..10].try_into().unwrap(),
        timestamp: u64::from_be_bytes(msg[10..18].try_into().unwrap()),
        client_random: msg[18..50].try_into().unwrap(),
    })
}

pub fn verify_hello(pairing: &PairingKey, msg: &[u8]) -> Result<(), ProtoError> {
    if msg.len() != HELLO_LEN {
        return Err(ProtoError("malformed hello"));
    }
    hmac::verify(&pairing.hello_mac, &msg[..HELLO_MAC_OFFSET], &msg[HELLO_MAC_OFFSET..])
        .map_err(|_| ProtoError("hello authentication failed"))
}

/// Server side: answers an already verified HELLO.
pub fn server_accept(
    pairing: &PairingKey,
    hello: &[u8],
    rng: &SystemRandom,
    lifetime_secs: u32,
) -> Result<([u8; HELLO_OK_LEN], Established), ProtoError> {
    if hello.len() != HELLO_LEN {
        return Err(ProtoError("malformed hello"));
    }
    let eph = EphemeralPrivateKey::generate(&X25519, rng).map_err(|_| ProtoError("key generation failed"))?;
    let public = eph.compute_public_key().map_err(|_| ProtoError("key generation failed"))?;
    let mut resp = [0u8; HELLO_OK_LEN];
    resp[0] = VERSION;
    resp[1] = MSG_HELLO_OK;
    fill_random(rng, &mut resp[2..18])?;
    resp[18..50].copy_from_slice(public.as_ref());
    resp[50..54].copy_from_slice(&lifetime_secs.to_be_bytes());
    let th = transcript_hash(hello, &resp[..HELLO_OK_CONFIRM_OFFSET]);
    let peer = UnparsedPublicKey::new(&X25519, &hello[50..82]);
    // ring rejects low-order points (all-zero shared secret) here.
    let (keys, confirm_key) = agreement::agree_ephemeral(eph, &peer, |shared| {
        derive_session(pairing, shared, th.as_ref())
    })
    .map_err(|_| ProtoError("invalid client key share"))?;
    let confirm = hmac::sign(&confirm_key, b"server-finished");
    resp[HELLO_OK_CONFIRM_OFFSET..].copy_from_slice(confirm.as_ref());
    let mut session_id = [0u8; SESSION_ID_LEN];
    session_id.copy_from_slice(&resp[2..18]);
    Ok((resp, Established { session_id, lifetime_secs, keys }))
}

fn frame_nonce(counter: u64, last: bool) -> Nonce {
    let mut n = [0u8; aead::NONCE_LEN];
    n[..8].copy_from_slice(&counter.to_be_bytes());
    n[8] = last as u8;
    Nonce::assume_unique_for_key(n)
}

/// Splits a frame header into (ciphertext length, LAST flag), validating the length.
pub fn parse_frame_header(h: u32) -> Result<(usize, bool), ProtoError> {
    let last = h & LAST_FLAG != 0;
    let len = (h & !LAST_FLAG) as usize;
    if !(TAG_LEN..=MAX_FRAME_CT).contains(&len) {
        return Err(ProtoError("invalid frame length"));
    }
    Ok((len, last))
}

/// Wire size of `plain` body bytes in FRAME_SIZE frames where the final (LAST) frame carries
/// the last 1..=FRAME_SIZE bytes plus `trailer` bytes (an empty body is one trailer-only frame).
pub fn sealed_body_len(plain: u64, trailer: u64) -> u64 {
    let frames = plain.div_ceil(FRAME_SIZE as u64).max(1);
    plain + trailer + frames * FRAME_OVERHEAD as u64
}

/// Encrypts the frames of one direction of one request.
pub struct Sealer {
    key: LessSafeKey,
    counter: u64,
}

impl Sealer {
    pub fn new(key: LessSafeKey) -> Self {
        Self { key, counter: 0 }
    }

    /// Appends one frame whose plaintext is produced by `write` directly into `out`
    /// (no intermediate buffer), then encrypts it in place.
    pub fn seal_with(
        &mut self,
        out: &mut BytesMut,
        last: bool,
        write: impl FnOnce(&mut BytesMut) -> Result<(), ProtoError>,
    ) -> Result<(), ProtoError> {
        let header_at = out.len();
        out.put_u32(0);
        let start = out.len();
        let sealed = write(out).and_then(|()| {
            let ct_len = out.len() - start + TAG_LEN;
            if ct_len > MAX_FRAME_CT {
                return Err(ProtoError("frame too large"));
            }
            let nonce = frame_nonce(self.counter, last);
            self.counter = self.counter.checked_add(1).ok_or(ProtoError("frame counter exhausted"))?;
            let tag = self
                .key
                .seal_in_place_separate_tag(nonce, Aad::empty(), &mut out[start..])
                .map_err(|_| ProtoError("encryption failed"))?;
            out.extend_from_slice(tag.as_ref());
            Ok(ct_len as u32 | if last { LAST_FLAG } else { 0 })
        });
        match sealed {
            Ok(header) => {
                out[header_at..start].copy_from_slice(&header.to_be_bytes());
                Ok(())
            }
            Err(e) => {
                out.truncate(header_at);
                Err(e)
            }
        }
    }

    /// Appends one frame whose plaintext is `a`, `b` and `c` concatenated.
    pub fn seal_into(&mut self, out: &mut BytesMut, parts: [&[u8]; 3], last: bool) -> Result<(), ProtoError> {
        out.reserve(FRAME_OVERHEAD + parts.iter().map(|p| p.len()).sum::<usize>());
        self.seal_with(out, last, |o| {
            parts.iter().for_each(|p| o.extend_from_slice(p));
            Ok(())
        })
    }
}

/// Decrypts the frames of one direction of one request, enforcing their order.
pub struct Opener {
    key: LessSafeKey,
    counter: u64,
}

impl Opener {
    pub fn new(key: LessSafeKey) -> Self {
        Self { key, counter: 0 }
    }

    /// Decrypts a frame (ciphertext + tag) in place. `last` comes from the frame header and is
    /// authenticated through the nonce.
    pub fn open(&mut self, mut frame: BytesMut, last: bool) -> Result<Bytes, ProtoError> {
        let nonce = frame_nonce(self.counter, last);
        self.counter = self.counter.checked_add(1).ok_or(ProtoError("frame counter exhausted"))?;
        let n = self
            .key
            .open_in_place(nonce, Aad::empty(), &mut frame[..])
            .map_err(|_| ProtoError("frame authentication failed"))?
            .len();
        frame.truncate(n);
        Ok(frame.freeze())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> (PairingKey, PairingKey) {
        let k = parse_pairing_key(&generate_pairing_key().unwrap()).unwrap();
        (PairingKey::new(&k), PairingKey::new(&k))
    }

    fn handshake(client: &PairingKey, server: &PairingKey) -> Result<(Established, Established), ProtoError> {
        let rng = SystemRandom::new();
        let pending = client_hello(client, &rng, 1_700_000_000)?;
        let hello = pending.message().to_vec();
        let view = parse_hello(&hello)?;
        assert_eq!(view.key_hint, server.key_hint(view.timestamp));
        verify_hello(server, &hello)?;
        let (resp, s) = server_accept(server, &hello, &rng, 86_400)?;
        let c = client_finish(client, pending, &resp)?;
        Ok((c, s))
    }

    #[test]
    fn handshake_agrees_on_keys() {
        let (c, s) = pair();
        let (ce, se) = handshake(&c, &s).unwrap();
        assert_eq!(ce.session_id, se.session_id);
        assert_eq!(ce.lifetime_secs, 86_400);
        for seq in [0u64, 1, 99, u64::MAX] {
            let ck = ce.keys.request_keys(seq);
            let sk = se.keys.request_keys(seq);
            let mut sealer = Sealer::new(ck.c2s);
            let mut opener = Opener::new(sk.c2s);
            let mut out = BytesMut::new();
            sealer.seal_into(&mut out, [b"hello ", b"world", b""], false).unwrap();
            let (len, last) = parse_frame_header(u32::from_be_bytes(out[..4].try_into().unwrap())).unwrap();
            assert!(!last);
            let pt = opener.open(BytesMut::from(&out[4..4 + len]), last).unwrap();
            assert_eq!(&pt[..], b"hello world");
            // Response direction uses a different key.
            let mut wrong = Opener::new(se.keys.request_keys(seq).s2c);
            assert!(wrong.open(BytesMut::from(&out[4..4 + len]), last).is_err());
        }
    }

    #[test]
    fn wrong_pairing_key_is_rejected() {
        let (c, _) = pair();
        let (_, other) = pair();
        let rng = SystemRandom::new();
        let pending = client_hello(&c, &rng, 1).unwrap();
        assert!(verify_hello(&other, pending.message()).is_err());
        // Even if a MITM answers with the wrong key, the client refuses.
        let (resp, _) = server_accept(&other, pending.message(), &rng, 10).unwrap();
        assert!(client_finish(&c, pending, &resp).is_err());
    }

    #[test]
    fn tampered_handshake_is_rejected() {
        let (c, s) = pair();
        let rng = SystemRandom::new();
        for i in 0..HELLO_LEN {
            let pending = client_hello(&c, &rng, 5).unwrap();
            let mut hello = pending.message().to_vec();
            hello[i] ^= 1;
            let ok = parse_hello(&hello).is_ok() && verify_hello(&s, &hello).is_ok();
            assert!(!ok, "byte {i} of hello not authenticated");
        }
        for i in 0..HELLO_OK_LEN {
            let pending = client_hello(&c, &rng, 5).unwrap();
            let (mut resp, _) = server_accept(&s, pending.message(), &rng, 10).unwrap();
            resp[i] ^= 1;
            assert!(client_finish(&c, pending, &resp).is_err(), "byte {i} of hello_ok not authenticated");
        }
    }

    #[test]
    fn frames_detect_tamper_reorder_and_flag_flip() {
        let (c, s) = pair();
        let (ce, se) = handshake(&c, &s).unwrap();
        let mut sealer = Sealer::new(ce.keys.request_keys(7).c2s);
        let mut f0 = BytesMut::new();
        let mut f1 = BytesMut::new();
        sealer.seal_into(&mut f0, [b"zero", b"", b""], false).unwrap();
        sealer.seal_into(&mut f1, [b"one", b"", b""], true).unwrap();
        let key = || Opener::new(se.keys.request_keys(7).c2s);
        // reorder
        assert!(key().open(BytesMut::from(&f1[4..]), true).is_err());
        // flag flip
        assert!(key().open(BytesMut::from(&f0[4..]), true).is_err());
        // bit flip
        let mut t = BytesMut::from(&f0[4..]);
        t[0] ^= 0x80;
        assert!(key().open(t, false).is_err());
        // correct order works
        let mut o = key();
        assert_eq!(&o.open(BytesMut::from(&f0[4..]), false).unwrap()[..], b"zero");
        assert_eq!(&o.open(BytesMut::from(&f1[4..]), true).unwrap()[..], b"one");
    }

    #[test]
    fn sealed_len_formula() {
        let o = FRAME_OVERHEAD as u64;
        let f = FRAME_SIZE as u64;
        assert_eq!(sealed_body_len(0, 0), o);
        assert_eq!(sealed_body_len(0, 8), o + 8);
        assert_eq!(sealed_body_len(1, 8), 1 + 8 + o);
        assert_eq!(sealed_body_len(f, 0), f + o);
        assert_eq!(sealed_body_len(f + 1, 8), f + 1 + 8 + 2 * o);
        assert_eq!(sealed_body_len(2 * f + 5, 0), 2 * f + 5 + 3 * o);
    }

    #[test]
    fn key_hint_rotates_with_time() {
        let (c, s) = pair();
        assert_eq!(c.key_hint(1000), s.key_hint(1100));
        assert_ne!(c.key_hint(1000), c.key_hint(1000 + HINT_PERIOD_SECS));
        let (_, other) = pair();
        assert_ne!(c.key_hint(1000), other.key_hint(1000));
    }

    #[test]
    fn pairing_key_parsing() {
        assert!(parse_pairing_key("not base64!").is_err());
        assert!(parse_pairing_key("AAAA").is_err());
        let k = generate_pairing_key().unwrap();
        assert!(parse_pairing_key(&k).is_ok());
        assert!(parse_pairing_key(&format!("  {k}\n")).is_ok());
    }
}
