//! `allowed_targets`: which destinations clients may reach through the server.

#[derive(Debug, Clone, PartialEq)]
enum HostPattern {
    Any,
    Exact(String),
    /// `*.example.com`, stored as `.example.com`.
    Suffix(String),
}

#[derive(Debug, Clone)]
struct Rule {
    host: HostPattern,
    /// `None` matches any port.
    port: Option<u16>,
}

#[derive(Debug, Clone)]
pub struct AllowList(Vec<Rule>);

impl AllowList {
    /// Entries: `*`, `host`, `host:port`, `host:*`, `*.domain[:port]`, `[v6addr][:port]`.
    pub fn parse(entries: &[String]) -> Result<Self, String> {
        entries.iter().map(String::as_str).map(parse_rule).collect::<Result<_, _>>().map(Self)
    }

    pub fn permits(&self, host: &str, port: u16) -> bool {
        let host = host.trim_end_matches('.');
        self.0.iter().any(|r| {
            r.port.is_none_or(|p| p == port)
                && match &r.host {
                    HostPattern::Any => true,
                    HostPattern::Exact(h) => h.eq_ignore_ascii_case(host),
                    HostPattern::Suffix(s) => {
                        let (h, s) = (host.as_bytes(), s.as_bytes());
                        h.len() > s.len() && h[h.len() - s.len()..].eq_ignore_ascii_case(s)
                    }
                }
        })
    }
}

fn parse_rule(raw: &str) -> Result<Rule, String> {
    let bad = || format!("invalid allowed_targets entry `{raw}`");
    let entry = raw.trim().to_ascii_lowercase();
    let (host, port) = match entry.strip_prefix('[') {
        Some(rest) => {
            let end = rest.find(']').ok_or_else(bad)?;
            let port = match &rest[end + 1..] {
                "" => None,
                p => Some(p.strip_prefix(':').ok_or_else(bad)?),
            };
            (&entry[..end + 2], port)
        }
        None => match entry.rsplit_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (entry.as_str(), None),
        },
    };
    let port = match port {
        None | Some("*") => None,
        Some(p) => Some(p.parse::<u16>().map_err(|_| bad())?),
    };
    let host = match host {
        "" => return Err(bad()),
        "*" => HostPattern::Any,
        h if h.starts_with("*.") && !h[2..].contains('*') => HostPattern::Suffix(h[1..].to_owned()),
        h if h.contains('*') => return Err(bad()),
        h => HostPattern::Exact(h.to_owned()),
    };
    Ok(Rule { host, port })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list(entries: &[&str]) -> AllowList {
        AllowList::parse(&entries.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap()
    }

    #[test]
    fn matching() {
        let a = list(&["127.0.0.1:*", "localhost:3000", "*.example.com:443", "[::1]"]);
        assert!(a.permits("127.0.0.1", 1));
        assert!(a.permits("LOCALHOST", 3000));
        assert!(!a.permits("localhost", 3001));
        assert!(a.permits("api.example.com", 443));
        assert!(a.permits("api.example.com.", 443));
        assert!(!a.permits("example.com", 443));
        assert!(!a.permits("api.example.com", 80));
        assert!(!a.permits("evilexample.com", 443));
        assert!(a.permits("[::1]", 8080));
        assert!(!a.permits("10.0.0.1", 80));
        assert!(list(&["*"]).permits("anything", 1));
    }

    #[test]
    fn invalid_entries() {
        for e in ["a*b", "host:notaport", "", "[::1", "[::1]x", "*.a*.com"] {
            assert!(AllowList::parse(&[e.to_string()]).is_err(), "{e}");
        }
    }
}
