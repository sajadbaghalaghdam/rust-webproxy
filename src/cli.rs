//! Administrative commands: config generation, pairing and status display.

use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, ToSocketAddrs};
use std::path::Path;
use std::time::Duration;

use serde_json::Value;
use zeroize::Zeroizing;

use crate::config::{self, Config};
use crate::crypto;
use crate::stats::human_duration;

const STATUS_TIMEOUT: Duration = Duration::from_secs(5);

/// Where `init --mode client` takes the pairing key from.
pub enum KeySource {
    Value(String),
    File(std::path::PathBuf),
}

impl KeySource {
    fn read(&self) -> Result<Zeroizing<String>, String> {
        let key = match self {
            KeySource::Value(v) => Zeroizing::new(v.trim().to_owned()),
            KeySource::File(p) => Zeroizing::new(
                std::fs::read_to_string(p)
                    .map_err(|e| format!("cannot read {}: {e}", p.display()))?
                    .trim()
                    .to_owned(),
            ),
        };
        crypto::parse_pairing_key(&key)?;
        Ok(key)
    }
}

pub struct ClientInit {
    pub server_url: String,
    pub key: KeySource,
    pub default_target: Option<String>,
}

pub fn init_server(out: &Path, listen: &str, client_name: &str, force: bool) -> Result<(), String> {
    let key = Zeroizing::new(crypto::generate_pairing_key().map_err(|e| e.to_string())?);
    let text = Zeroizing::new(config::server_template(listen, client_name, &key));
    write_config(out, &text, force)?;
    println!("server config written to {}", out.display());
    println!();
    println!("pairing key for client `{client_name}` (keep it secret):");
    println!("  {}", key.as_str());
    println!();
    println!("on the client machine, save it to a file only root can read (e.g. /etc/webproxy/client.key)");
    println!("and create the client config with (it copies the key, so the file can be deleted afterwards):");
    println!("  webproxy init --mode client --out /etc/webproxy/client.toml --server-url https://<cdn-host>/api/v1/stream --key-file /etc/webproxy/client.key");
    Ok(())
}

pub fn init_client(out: &Path, listen: &str, c: &ClientInit, force: bool) -> Result<(), String> {
    let key = c.key.read()?;
    let text = Zeroizing::new(config::client_template(listen, &c.server_url, &key, c.default_target.as_deref()));
    write_config(out, &text, force)?;
    println!("client config written to {}", out.display());
    Ok(())
}

pub fn add_client(path: &Path, name: &str) -> Result<(), String> {
    let Config::Server(cfg) = config::load(path)? else {
        return Err(format!("{} is not a server config", path.display()));
    };
    if cfg.clients.iter().any(|c| c.name == name) {
        return Err(format!("client `{name}` already exists"));
    }
    let key = Zeroizing::new(crypto::generate_pairing_key().map_err(|e| e.to_string())?);
    let mut text =
        Zeroizing::new(std::fs::read_to_string(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?);
    if !text.ends_with('\n') {
        text.push('\n');
    }
    text.push_str(&config::client_block(name, &key));
    write_config(path, &text, true)?;
    println!("client `{name}` added to {} (restart the server to apply)", path.display());
    println!("pairing key: {}", key.as_str());
    Ok(())
}

pub fn keygen() -> Result<(), String> {
    let key = Zeroizing::new(crypto::generate_pairing_key().map_err(|e| e.to_string())?);
    println!("{}", key.as_str());
    Ok(())
}

/// Validates `text`, then replaces `path` atomically. A new file is created readable by the
/// owner only (mode 0600 on Unix) — it holds pairing keys; an existing file keeps its owner,
/// group and mode, so a service account that could read it still can.
fn write_config(path: &Path, text: &str, overwrite: bool) -> Result<(), String> {
    config::parse(text).map_err(|e| format!("refusing to write an invalid config: {e}"))?;
    let existing = std::fs::metadata(path).ok();
    if existing.is_some() && !overwrite {
        return Err(format!("{} already exists (use --force to overwrite)", path.display()));
    }
    let file_name = path.file_name().ok_or_else(|| format!("{} is not a file path", path.display()))?;
    let dir = path.parent().filter(|d| !d.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let tmp = dir.join(format!(".{}.{}.tmp", file_name.to_string_lossy(), std::process::id()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let written = options.open(&tmp).and_then(|mut f| {
        f.write_all(text.as_bytes())?;
        if let Some(meta) = &existing {
            keep_ownership(&f, meta)?;
        }
        f.sync_all()
    });
    if let Err(e) = written.and_then(|()| std::fs::rename(&tmp, path)) {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("cannot write {}: {e}", path.display()));
    }
    Ok(())
}

/// Gives a replacement file the owner, group and permissions of the file it replaces.
#[cfg(unix)]
fn keep_ownership(file: &std::fs::File, meta: &std::fs::Metadata) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    file.set_permissions(meta.permissions())?;
    // Only root may hand a file to another user; otherwise the caller owns both anyway.
    if let Err(e) = std::os::unix::fs::fchown(file, Some(meta.uid()), Some(meta.gid())) {
        eprintln!("warning: could not keep the config file's owner ({e})");
    }
    Ok(())
}

#[cfg(not(unix))]
fn keep_ownership(file: &std::fs::File, meta: &std::fs::Metadata) -> std::io::Result<()> {
    file.set_permissions(meta.permissions())
}

pub fn status(config_path: Option<&Path>, addr: Option<&str>, raw: bool) -> Result<(), String> {
    let addr = status_addr(config_path, addr)?;
    let snapshot = fetch_status(addr)?;
    if raw {
        println!("{}", serde_json::to_string_pretty(&snapshot).unwrap_or_default());
    } else {
        print_status(&snapshot);
    }
    Ok(())
}

fn status_addr(config_path: Option<&Path>, addr: Option<&str>) -> Result<SocketAddr, String> {
    if let Some(a) = addr {
        return a
            .to_socket_addrs()
            .map_err(|e| format!("invalid address {a}: {e}"))?
            .next()
            .ok_or_else(|| format!("{a} did not resolve"));
    }
    let path = config_path.ok_or("pass --config or --addr")?;
    let cfg = config::load(path)?;
    let mut addr =
        config::parse_optional_addr(cfg.status_listen())?.ok_or("the status page is disabled in this config")?;
    // A wildcard listen address is reachable through loopback (connecting to it fails on Windows).
    if addr.ip().is_unspecified() {
        let loopback = if addr.is_ipv4() { IpAddr::V4(Ipv4Addr::LOCALHOST) } else { IpAddr::V6(Ipv6Addr::LOCALHOST) };
        addr.set_ip(loopback);
    }
    Ok(addr)
}

fn fetch_status(addr: SocketAddr) -> Result<Value, String> {
    let mut s = TcpStream::connect_timeout(&addr, STATUS_TIMEOUT).map_err(|e| format!("cannot connect to {addr}: {e}"))?;
    s.set_read_timeout(Some(STATUS_TIMEOUT)).map_err(|e| e.to_string())?;
    write!(s, "GET /status.json HTTP/1.0\r\nHost: {addr}\r\n\r\n").map_err(|e| e.to_string())?;
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).map_err(|e| e.to_string())?;
    let body = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| &buf[i + 4..])
        .ok_or("invalid status response")?;
    serde_json::from_slice(body).map_err(|e| format!("invalid status JSON: {e}"))
}

fn print_status(v: &Value) {
    let num = |p: &str| v.pointer(p).and_then(Value::as_u64).unwrap_or(0);
    let text = |p: &str| v.pointer(p).and_then(Value::as_str).unwrap_or("-");
    println!("webproxy {} v{}, up {}", text("/mode"), text("/version"), human_duration(num("/uptime_secs")));
    println!("  connections    active {:<10} total {}", num("/connections/active"), num("/connections/total"));
    println!(
        "  requests       active {:<10} total {:<12} failed {}",
        num("/requests/active"),
        num("/requests/total"),
        num("/requests/failed")
    );
    println!(
        "  traffic        received {:<12} sent {:<12} total {}",
        text("/traffic/received"),
        text("/traffic/sent"),
        text("/traffic/total")
    );
    println!("  key exchanges  ok {:<14} failed {}", num("/handshakes/ok"), num("/handshakes/failed"));
    println!(
        "  refused        busy {:<12} replayed {:<8} delayed {:<8} unknown session {}",
        num("/rejected/busy"),
        num("/rejected/replayed"),
        num("/rejected/stale"),
        num("/rejected/unknown_session")
    );
    if v.pointer("/session/id").is_some() {
        println!(
            "  session        {} (age {}), next rotation in {}, rotations so far {}",
            text("/session/id"),
            human_duration(num("/session/age_secs")),
            text("/session/rotates_in"),
            num("/key_rotations")
        );
    }
    if v.pointer("/last_key_exchange_error/error").is_some() {
        println!(
            "  last key exchange error: {} ({}s ago)",
            text("/last_key_exchange_error/error"),
            num("/last_key_exchange_error/secs_ago")
        );
    }
    if v.pointer("/sessions/active").is_some() {
        println!("  sessions       active {}, keys rotate every {}", num("/sessions/active"), text("/sessions/rekey_interval"));
    }
    for c in v.get("clients").and_then(Value::as_array).into_iter().flatten() {
        let last = c["last_key_exchange_secs_ago"]
            .as_u64()
            .map_or_else(|| "never".to_string(), |s| format!("{} ago", human_duration(s)));
        println!(
            "  client {:<16} sessions {}, last key exchange {}",
            c["name"].as_str().unwrap_or("-"),
            c["sessions"].as_u64().unwrap_or(0),
            last
        );
    }
}
