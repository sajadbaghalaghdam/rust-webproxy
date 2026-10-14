//! Configuration files. One binary, the `mode` key decides whether it runs as server or client.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;
use zeroize::Zeroizing;

use crate::crypto::parse_pairing_key;

pub enum Config {
    Server(ServerConfig),
    Client(ClientConfig),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientEntry {
    pub name: String,
    pub key: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    #[serde(default = "d_server_listen")]
    pub listen: SocketAddr,
    #[serde(default = "d_tunnel_path")]
    pub tunnel_path: String,
    /// Local status page; empty string disables it.
    #[serde(default = "d_server_status")]
    pub status_listen: String,
    /// Session keys are replaced by a fresh X25519 exchange this often.
    #[serde(default = "d_rekey")]
    pub rekey_interval_secs: u64,
    #[serde(default = "d_skew")]
    pub max_clock_skew_secs: u64,
    /// Requests older than this when they reach the server (e.g. held back by the CDN) are refused.
    #[serde(default = "d_300")]
    pub max_request_age_secs: u64,
    /// Destinations clients may reach: "*", "host", "host:port", "host:*", "*.domain:443".
    #[serde(default = "d_allowed")]
    pub allowed_targets: Vec<String>,
    #[serde(default)]
    pub tls_cert: Option<PathBuf>,
    #[serde(default)]
    pub tls_key: Option<PathBuf>,
    #[serde(default = "d_10")]
    pub upstream_connect_timeout_secs: u64,
    /// Time the destination may take to answer once the request has been sent completely.
    #[serde(default = "d_300")]
    pub upstream_response_timeout_secs: u64,
    #[serde(default = "d_60")]
    pub upstream_pool_idle_secs: u64,
    #[serde(default = "d_1024")]
    pub upstream_pool_max_idle: usize,
    #[serde(default)]
    pub upstream_ca_file: Option<PathBuf>,
    #[serde(default = "d_server_conns")]
    pub max_connections: usize,
    /// Concurrent tunnelled requests; more are refused with 503.
    #[serde(default = "d_server_requests")]
    pub max_requests: usize,
    /// Largest request body forwarded to a destination, in MiB; 0 = no limit.
    #[serde(default)]
    pub max_request_body_mb: u64,
    #[serde(default = "d_60")]
    pub idle_timeout_secs: u64,
    /// A body that transfers nothing for this long is aborted; 0 disables (long-lived SSE).
    #[serde(default = "d_300")]
    pub stream_idle_timeout_secs: u64,
    /// Start the outer response after this long even if the destination has not answered yet,
    /// so CDN time-to-first-byte limits (Cloudflare: 100 s) don't cut slow requests; 0 = never.
    #[serde(default = "d_20")]
    pub early_response_secs: u64,
    #[serde(default = "d_30")]
    pub shutdown_timeout_secs: u64,
    /// Worker threads; 0 = number of CPU cores.
    #[serde(default)]
    pub workers: usize,
    #[serde(default)]
    pub clients: Vec<ClientEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {
    #[serde(default = "d_client_listen")]
    pub listen: SocketAddr,
    #[serde(default = "d_client_status")]
    pub status_listen: String,
    /// Full tunnel URL of the server (normally the CDN hostname), including the tunnel path.
    pub server_url: String,
    pub key: String,
    /// Destination used when a request names none (no absolute URL / X-Tunnel-* header).
    #[serde(default)]
    pub default_target: Option<String>,
    /// Keep the Host header sent by the local app instead of using the target's host.
    #[serde(default)]
    pub preserve_host: bool,
    /// Host names (besides IP literals and localhost) local apps may use to reach the
    /// client; protects against DNS rebinding.
    #[serde(default)]
    pub allowed_hosts: Vec<String>,
    /// Rewrite redirects from base-URL destinations (default_target, X-Tunnel-Target) so they
    /// come back through the client.
    #[serde(default = "d_true")]
    pub rewrite_redirects: bool,
    #[serde(default)]
    pub ca_file: Option<PathBuf>,
    #[serde(default = "d_10")]
    pub connect_timeout_secs: u64,
    /// Time the server may take to answer once the request has been sent completely.
    #[serde(default = "d_300")]
    pub response_timeout_secs: u64,
    #[serde(default = "d_300")]
    pub stream_idle_timeout_secs: u64,
    #[serde(default = "d_90")]
    pub pool_idle_secs: u64,
    #[serde(default = "d_1024")]
    pub pool_max_idle: usize,
    #[serde(default = "d_client_conns")]
    pub max_connections: usize,
    /// Concurrent requests in flight; more are refused with 503.
    #[serde(default = "d_client_requests")]
    pub max_requests: usize,
    /// Largest request body accepted from local apps, in MiB; 0 = no limit.
    #[serde(default)]
    pub max_request_body_mb: u64,
    #[serde(default = "d_60")]
    pub idle_timeout_secs: u64,
    #[serde(default = "d_30")]
    pub shutdown_timeout_secs: u64,
    #[serde(default)]
    pub workers: usize,
}

fn d_server_listen() -> SocketAddr {
    SocketAddr::from(([0, 0, 0, 0], 8443))
}
fn d_client_listen() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 8080))
}
fn d_tunnel_path() -> String {
    "/api/v1/stream".into()
}
fn d_server_status() -> String {
    "127.0.0.1:9901".into()
}
fn d_client_status() -> String {
    "127.0.0.1:9902".into()
}
fn d_rekey() -> u64 {
    86_400
}
fn d_skew() -> u64 {
    300
}
fn d_allowed() -> Vec<String> {
    vec!["*".into()]
}
fn d_true() -> bool {
    true
}
fn d_10() -> u64 {
    10
}
fn d_20() -> u64 {
    20
}
fn d_30() -> u64 {
    30
}
fn d_60() -> u64 {
    60
}
fn d_90() -> u64 {
    90
}
fn d_300() -> u64 {
    300
}
fn d_1024() -> usize {
    1024
}
fn d_server_conns() -> usize {
    20_000
}
fn d_server_requests() -> usize {
    10_000
}
fn d_client_conns() -> usize {
    10_000
}
fn d_client_requests() -> usize {
    10_000
}

/// `secs` as a duration, with 0 meaning "disabled".
pub fn optional_secs(secs: u64) -> Option<Duration> {
    (secs > 0).then(|| Duration::from_secs(secs))
}

impl Config {
    pub fn workers(&self) -> usize {
        match self {
            Config::Server(c) => c.workers,
            Config::Client(c) => c.workers,
        }
    }

    pub fn status_listen(&self) -> &str {
        match self {
            Config::Server(c) => &c.status_listen,
            Config::Client(c) => &c.status_listen,
        }
    }
}

pub fn load(path: &Path) -> Result<Config, String> {
    let text = Zeroizing::new(std::fs::read_to_string(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?);
    parse(&text).map_err(|e| format!("{}: {e}", path.display()))
}

/// Parses and validates a config document.
pub fn parse(text: &str) -> Result<Config, String> {
    let mut table: toml::Table = text.parse().map_err(|e| describe_toml_error(text, &e))?;
    let mode = match table.remove("mode") {
        Some(toml::Value::String(s)) => s,
        _ => return Err("missing `mode = \"server\"` or `mode = \"client\"`".into()),
    };
    let value = toml::Value::Table(table);
    let cfg = match mode.as_str() {
        // These errors name the offending key and carry no source text (no secrets).
        "server" => Config::Server(value.try_into().map_err(|e: toml::de::Error| e.to_string().trim_end().to_owned())?),
        "client" => Config::Client(value.try_into().map_err(|e: toml::de::Error| e.to_string().trim_end().to_owned())?),
        other => return Err(format!("unknown mode `{other}` (use server or client)")),
    };
    match &cfg {
        Config::Server(c) => c.validate()?,
        Config::Client(c) => c.validate()?,
    }
    Ok(cfg)
}

/// Line/column and message only: the default rendering quotes the offending line, which
/// may contain a pairing key.
fn describe_toml_error(text: &str, e: &toml::de::Error) -> String {
    match e.span() {
        Some(span) => {
            let before = &text[..span.start.min(text.len())];
            let line = before.matches('\n').count() + 1;
            let column = before.len() - before.rfind('\n').map_or(0, |i| i + 1) + 1;
            format!("line {line}, column {column}: {}", e.message())
        }
        None => e.message().to_owned(),
    }
}

/// Parses an optional listen address ("" disables).
pub fn parse_optional_addr(s: &str) -> Result<Option<SocketAddr>, String> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(None);
    }
    s.parse().map(Some).map_err(|_| format!("invalid address `{s}`"))
}

fn check_range(name: &str, v: u64, min: u64, max: u64) -> Result<(), String> {
    if (min..=max).contains(&v) {
        Ok(())
    } else {
        Err(format!("{name} must be between {min} and {max}"))
    }
}

const DAY: u64 = 86_400;
/// Upper bound for `max_request_body_mb` (1 TiB).
const MAX_BODY_MB: u64 = 1 << 20;

/// `max_request_body_mb` in bytes; `None` = no limit.
pub fn body_limit(mb: u64) -> Option<u64> {
    (mb > 0).then_some(mb << 20)
}

impl ServerConfig {
    pub fn validate(&self) -> Result<(), String> {
        if !self.tunnel_path.starts_with('/') {
            return Err("tunnel_path must start with '/'".into());
        }
        check_range("rekey_interval_secs", self.rekey_interval_secs, 10, 7 * DAY)?;
        check_range("max_clock_skew_secs", self.max_clock_skew_secs, 1, DAY)?;
        check_range("max_request_age_secs", self.max_request_age_secs, 1, DAY)?;
        check_range("upstream_connect_timeout_secs", self.upstream_connect_timeout_secs, 1, DAY)?;
        check_range("upstream_response_timeout_secs", self.upstream_response_timeout_secs, 1, DAY)?;
        check_range("upstream_pool_idle_secs", self.upstream_pool_idle_secs, 1, DAY)?;
        check_range("idle_timeout_secs", self.idle_timeout_secs, 1, DAY)?;
        check_range("stream_idle_timeout_secs", self.stream_idle_timeout_secs, 0, DAY)?;
        check_range("early_response_secs", self.early_response_secs, 0, DAY)?;
        check_range("shutdown_timeout_secs", self.shutdown_timeout_secs, 0, 3600)?;
        check_range("max_request_body_mb", self.max_request_body_mb, 0, MAX_BODY_MB)?;
        if self.tls_cert.is_some() != self.tls_key.is_some() {
            return Err("tls_cert and tls_key must be set together".into());
        }
        if self.max_connections == 0 || self.max_requests == 0 {
            return Err("max_connections and max_requests must be > 0".into());
        }
        parse_optional_addr(&self.status_listen)?;
        crate::server::AllowList::parse(&self.allowed_targets)?;
        if self.clients.is_empty() {
            return Err("no [[clients]] configured; run `webproxy add-client`".into());
        }
        let mut names = HashSet::new();
        let mut keys: Zeroizing<Vec<[u8; 32]>> = Zeroizing::new(Vec::with_capacity(self.clients.len()));
        for c in &self.clients {
            if c.name.trim().is_empty() {
                return Err("client name must not be empty".into());
            }
            if !names.insert(c.name.as_str()) {
                return Err(format!("duplicate client name `{}`", c.name));
            }
            let secret = parse_pairing_key(&c.key).map_err(|e| format!("client `{}`: {e}", c.name))?;
            if keys.contains(&*secret) {
                return Err(format!("client `{}` reuses another client's key", c.name));
            }
            keys.push(*secret);
        }
        Ok(())
    }
}

impl ClientConfig {
    pub fn validate(&self) -> Result<(), String> {
        let uri: http::Uri = self.server_url.parse().map_err(|_| "server_url is not a valid URL".to_string())?;
        if !matches!(uri.scheme_str(), Some("http" | "https")) || uri.authority().is_none() {
            return Err("server_url must be an absolute http:// or https:// URL".into());
        }
        parse_pairing_key(&self.key)?;
        if let Some(t) = &self.default_target {
            crate::client::TargetBase::parse(t).map_err(|e| format!("default_target: {e}"))?;
        }
        if self.allowed_hosts.iter().any(|h| h.trim().is_empty()) {
            return Err("allowed_hosts must not contain empty names".into());
        }
        check_range("connect_timeout_secs", self.connect_timeout_secs, 1, DAY)?;
        check_range("response_timeout_secs", self.response_timeout_secs, 1, DAY)?;
        check_range("stream_idle_timeout_secs", self.stream_idle_timeout_secs, 0, DAY)?;
        check_range("pool_idle_secs", self.pool_idle_secs, 1, DAY)?;
        check_range("idle_timeout_secs", self.idle_timeout_secs, 1, DAY)?;
        check_range("shutdown_timeout_secs", self.shutdown_timeout_secs, 0, 3600)?;
        check_range("max_request_body_mb", self.max_request_body_mb, 0, MAX_BODY_MB)?;
        if self.max_connections == 0 || self.max_requests == 0 {
            return Err("max_connections and max_requests must be > 0".into());
        }
        parse_optional_addr(&self.status_listen)?;
        Ok(())
    }
}

/// TOML-escapes a string value.
fn q(s: &str) -> String {
    toml::Value::String(s.to_owned()).to_string()
}

pub fn client_block(name: &str, key: &str) -> String {
    format!("\n[[clients]]\nname = {}\nkey = {}\n", q(name), q(key))
}

pub fn server_template(listen: &str, client_name: &str, key: &str) -> String {
    format!(
        r#"# webproxy server configuration
mode = "server"

# Address the CDN (or clients directly) connect to.
listen = {listen}
# Only POST requests to this path are tunnel traffic; anything else gets a plain 404.
tunnel_path = "/api/v1/stream"
# Local status page / JSON (http://127.0.0.1:9901/). Empty string disables it.
status_listen = "127.0.0.1:9901"

# Session keys are renegotiated (ephemeral X25519) this often. 86400 = 24h.
rekey_interval_secs = 86400
# Accepted clock difference between client and server for key exchange messages.
max_clock_skew_secs = 300
# Requests that reach the server later than this after being sent (e.g. held back by the CDN)
# are refused. Keep it at or below the client's response_timeout_secs.
max_request_age_secs = 300

# Which destinations clients may ask for. Examples:
#   ["*"]                                  anything
#   ["127.0.0.1:*", "localhost:*"]         only local services
#   ["api.example.com:443", "*.internal"]
allowed_targets = ["*"]

# Optional TLS for the listener (e.g. CDN "Full (strict)" mode).
# tls_cert = "/etc/webproxy/cert.pem"
# tls_key  = "/etc/webproxy/key.pem"

upstream_connect_timeout_secs = 10
# Time a destination may take to answer after the request was sent completely.
upstream_response_timeout_secs = 300
upstream_pool_idle_secs = 60
upstream_pool_max_idle = 1024
# Extra CA bundle for https:// destinations with private certificates.
# upstream_ca_file = "/etc/webproxy/internal-ca.pem"

max_connections = 20000
# Concurrent tunnelled requests; beyond this new requests get 503.
max_requests = 10000
# Largest request body (upload) forwarded to destinations, in MiB; larger ones get 413. 0 = no limit.
max_request_body_mb = 0
# Idle keep-alive connections are closed after this long.
idle_timeout_secs = 60
# Abort a request/response body that transfers nothing for this long (0 = never, e.g. for SSE).
stream_idle_timeout_secs = 300
# Send the response headers to the CDN after this long even if the destination is still
# working, so CDN time-to-first-byte limits (Cloudflare: 100 s) don't cut it (0 = never).
early_response_secs = 20
# On SIGTERM / Ctrl-C, in-flight requests get this long to finish.
shutdown_timeout_secs = 30
workers = 0
{block}"#,
        listen = q(listen),
        block = client_block(client_name, key),
    )
}

pub fn client_template(listen: &str, server_url: &str, key: &str, default_target: Option<&str>) -> String {
    let target = match default_target {
        Some(t) => format!("default_target = {}", q(t)),
        None => "# default_target = \"http://127.0.0.1:3000\"".into(),
    };
    format!(
        r#"# webproxy client configuration
mode = "client"

# Local applications send their HTTP requests here (as a normal server or as an HTTP proxy).
listen = {listen}
# Local status page / JSON (http://127.0.0.1:9902/). Empty string disables it.
status_listen = "127.0.0.1:9902"

# Tunnel URL of the server, normally through the CDN: https://<cdn-host><tunnel_path>
server_url = {server_url}
# Pairing key (must match the server's [[clients]] entry). Keep it secret.
key = {key}

# Destination for requests that name none. Per request, apps choose the destination with
#   X-Tunnel-Target: http://host:port   (base URL; the request path and query are appended)
#   X-Tunnel-Url: http://host:port/exact/path?query
# or by using this client as an HTTP proxy.
{target}
# Rewrite redirects (Location) from base-URL destinations (default_target or X-Tunnel-Target)
# back to this client; X-Tunnel-Url and proxy-mode requests are left alone.
rewrite_redirects = true

# Send the local app's Host header instead of the destination's host.
preserve_host = false
# Host names local apps may use to reach this client, besides IP addresses and "localhost"
# (protects against DNS rebinding from web pages).
allowed_hosts = []
# Extra CA bundle to trust for server_url (self-signed origin without CDN).
# ca_file = "/etc/webproxy/ca.pem"

connect_timeout_secs = 10
# Time the server may take to answer after the request was sent completely.
response_timeout_secs = 300
# Abort a body that transfers nothing for this long (0 = never, e.g. for SSE).
stream_idle_timeout_secs = 300
pool_idle_secs = 90
pool_max_idle = 1024
max_connections = 10000
# Concurrent requests in flight; beyond this new requests get 503.
max_requests = 10000
# Largest request body (upload) accepted from local apps, in MiB; larger ones get 413 (bodies
# with a Content-Length before anything is sent). 0 = no limit. E.g. 10 for images up to 8 MB
# plus form fields.
max_request_body_mb = 0
idle_timeout_secs = 60
shutdown_timeout_secs = 30
workers = 0
"#,
        listen = q(listen),
        server_url = q(server_url),
        key = q(key),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // Synthetic, non-secret test keys: the bytes 0x00..=0x1f and a descending pattern.
    const KEY_A: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
    const KEY_B: &str = "HxweHRwbGhkYFxYVFBMSERAPDg0MCwoJCAcGBQQDAgE=";

    fn server(extra: &str) -> Result<Config, String> {
        parse(&(server_template("127.0.0.1:1", "a", KEY_A) + extra))
    }

    fn client(target: Option<&str>) -> Result<Config, String> {
        parse(&client_template("127.0.0.1:1", "https://cdn.example.com/api/v1/stream", KEY_A, target))
    }

    #[test]
    fn templates_are_valid() {
        assert!(matches!(server(""), Ok(Config::Server(_))));
        assert!(matches!(client(Some("http://127.0.0.1:3000")), Ok(Config::Client(_))));
        assert!(matches!(client(None), Ok(Config::Client(_))));
    }

    #[test]
    fn invalid_server_configs_are_rejected() {
        assert!(server(&client_block("b", KEY_A)).err().expect("must be rejected").contains("reuses"));
        assert!(server(&client_block("a", KEY_B)).err().expect("must be rejected").contains("duplicate client name"));
        assert!(server(&client_block("b", "short")).is_err());
        let replace = |from: &str, to: &str| parse(&server_template("127.0.0.1:1", "a", KEY_A).replace(from, to));
        assert!(replace("rekey_interval_secs = 86400", "rekey_interval_secs = 5").is_err());
        assert!(replace("max_request_age_secs = 300", "max_request_age_secs = 0").is_err());
        assert!(replace("tunnel_path = \"/api/v1/stream\"", "tunnel_path = \"api\"").is_err());
        assert!(replace("allowed_targets = [\"*\"]", "allowed_targets = [\"a*b\"]").is_err());
        assert!(replace("# tls_cert = \"/etc/webproxy/cert.pem\"", "tls_cert = \"c.pem\"").is_err());
        assert!(replace("max_requests = 10000", "max_requests = 0").is_err());
        assert!(replace("max_request_body_mb = 0", "max_request_body_mb = 2000000").is_err());
        assert!(replace("workers = 0", "workers = 0\nunknown_key = 1").is_err());
    }

    #[test]
    fn invalid_client_configs_are_rejected() {
        assert!(client(Some("ftp://x")).is_err());
        let base = client_template("127.0.0.1:1", "https://cdn.example.com/api/v1/stream", KEY_A, None);
        assert!(parse(&base.replace("https://cdn.example.com/api/v1/stream", "/relative")).is_err());
        assert!(parse(&base.replace("allowed_hosts = []", "allowed_hosts = [\"\"]")).is_err());
        assert!(parse(&base.replace("response_timeout_secs = 300", "response_timeout_secs = 0")).is_err());
    }

    #[test]
    fn type_errors_name_the_key() {
        let base = client_template("127.0.0.1:1", "https://cdn.example.com/api/v1/stream", KEY_A, None);
        let err = parse(&base.replace("max_requests = 10000", "max_requests = \"many\"")).err().expect("must be rejected");
        assert!(err.contains("max_requests"), "{err}");
    }

    #[test]
    fn syntax_errors_do_not_echo_the_offending_line() {
        let text = format!("mode = \"client\"\nkey = \"{KEY_A}\nserver_url = 1\n");
        let err = parse(&text).err().expect("must be rejected");
        assert!(!err.contains(KEY_A), "{err}");
        assert!(err.starts_with("line 2"), "{err}");
    }
}
