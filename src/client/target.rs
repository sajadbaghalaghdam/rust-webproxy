//! Where a request should go: chosen per request by the local application.

use bytes::Bytes;
use http::request::Parts;
use http::uri::{Authority, PathAndQuery, Scheme};
use http::{StatusCode, Uri, Version};

use crate::net::Reject;
use crate::proto::{TARGET_HEADER, URL_HEADER};

/// Destination base URL, e.g. `http://127.0.0.1:3000` or `https://api.example.com/v2`.
#[derive(Debug)]
pub struct TargetBase {
    scheme: Scheme,
    authority: Authority,
    /// Path prefix without a trailing slash (empty for none).
    prefix: String,
}

/// The resolved destination of one request.
pub struct Route {
    pub uri: Uri,
    pub origin: RouteOrigin,
}

/// How the destination was chosen; decides whether redirects can be pointed back at the client.
pub enum RouteOrigin {
    /// Absolute-form request: the app uses webproxy as its HTTP proxy.
    Proxy,
    /// `X-Tunnel-Url`: an exact URL.
    ExactUrl,
    /// `X-Tunnel-Target`: a base URL.
    Base(TargetBase),
    /// `default_target`.
    Default,
}

fn absolute_http_uri(s: &str) -> Result<Uri, String> {
    let uri: Uri = s.trim().parse().map_err(|_| format!("invalid URL `{s}`"))?;
    if !matches!(uri.scheme_str(), Some("http" | "https")) || uri.authority().is_none() {
        return Err(format!("`{s}` must be an absolute http:// or https:// URL"));
    }
    Ok(uri)
}

impl TargetBase {
    pub fn parse(s: &str) -> Result<Self, String> {
        let parts = absolute_http_uri(s)?.into_parts();
        let (prefix, query) = match &parts.path_and_query {
            Some(pq) => (pq.path().trim_end_matches('/'), pq.query()),
            None => ("", None),
        };
        if query.is_some() {
            return Err(format!("`{s}` must not contain a query string (use {URL_HEADER} for an exact URL)"));
        }
        Ok(Self {
            prefix: prefix.to_owned(),
            scheme: parts.scheme.expect("checked above"),
            authority: parts.authority.expect("checked above"),
        })
    }

    /// The part of a redirect target inside this base, relative to it (`/…`, `?…`, `#…` or
    /// empty). `value` is either an absolute URL with this scheme and authority or, when the
    /// base has a path prefix, an origin-relative path; either way it must lie under the prefix.
    pub fn local_path<'v>(&self, value: &'v str) -> Option<&'v str> {
        let path = if value.starts_with('/') && !value.starts_with("//") {
            // Same origin: only a prefix makes the destination's paths differ from the client's.
            if self.prefix.is_empty() {
                return None;
            }
            value
        } else {
            let rest = strip_prefix_ignore_case(value, self.scheme.as_str())?.strip_prefix("://")?;
            strip_prefix_ignore_case(rest, self.authority.as_str())?
        };
        let rest = path.strip_prefix(self.prefix.as_str())?;
        (rest.is_empty() || rest.starts_with(['/', '?', '#'])).then_some(rest)
    }

    /// The base plus the request's origin-form path and query.
    fn join(&self, path_and_query: Option<&PathAndQuery>) -> Result<Uri, Reject> {
        let invalid = || Reject::new(StatusCode::BAD_REQUEST, "invalid target URL");
        let path_and_query = match (self.prefix.is_empty(), path_and_query) {
            // No prefix: reuse the request's path (a reference-counted handle, no copy).
            (true, Some(pq)) => pq.clone(),
            (true, None) => PathAndQuery::from_static("/"),
            (false, pq) => {
                let rest = pq.map_or("/", PathAndQuery::as_str);
                let mut joined = String::with_capacity(self.prefix.len() + rest.len());
                joined.push_str(&self.prefix);
                joined.push_str(rest);
                PathAndQuery::from_maybe_shared(Bytes::from(joined)).map_err(|_| invalid())?
            }
        };
        Uri::builder()
            .scheme(self.scheme.clone())
            .authority(self.authority.clone())
            .path_and_query(path_and_query)
            .build()
            .map_err(|_| invalid())
    }
}

fn strip_prefix_ignore_case<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    let head = s.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix).then(|| &s[prefix.len()..])
}

fn header_str<'a>(parts: &'a Parts, name: &str) -> Result<Option<&'a str>, Reject> {
    parts
        .headers
        .get(name)
        .map(|v| v.to_str().map_err(|_| Reject::new(StatusCode::BAD_REQUEST, format!("invalid {name} header"))))
        .transpose()
}

/// Picks the destination, in order of precedence:
/// 1. absolute-form request line (the app uses webproxy as its HTTP proxy),
/// 2. `X-Tunnel-Url`: the exact destination URL,
/// 3. `X-Tunnel-Target`: a base URL; the request's path and query are appended,
/// 4. `default_target` from the client config.
pub fn resolve(parts: &mut Parts, default: Option<&TargetBase>) -> Result<Route, Reject> {
    let bad = |msg: String| Reject::new(StatusCode::BAD_REQUEST, msg);
    // HTTP/2 requests always carry an authority, so only HTTP/1 absolute-form counts as proxying.
    if parts.version <= Version::HTTP_11 && parts.uri.scheme().is_some() {
        if !matches!(parts.uri.scheme_str(), Some("http" | "https")) || parts.uri.authority().is_none() {
            return Err(bad("only http:// and https:// targets are supported".into()));
        }
        return Ok(Route { uri: std::mem::take(&mut parts.uri), origin: RouteOrigin::Proxy });
    }
    if parts.uri.path_and_query().is_some_and(|pq| pq.as_str() == "*") {
        return Err(Reject::new(StatusCode::NOT_IMPLEMENTED, "asterisk-form requests (OPTIONS *) are not supported"));
    }
    if let Some(url) = header_str(parts, URL_HEADER)? {
        let uri = absolute_http_uri(url).map_err(|e| bad(format!("{URL_HEADER}: {e}")))?;
        return Ok(Route { uri, origin: RouteOrigin::ExactUrl });
    }
    if let Some(base) = header_str(parts, TARGET_HEADER)? {
        let base = TargetBase::parse(base).map_err(|e| bad(format!("{TARGET_HEADER}: {e}")))?;
        return Ok(Route { uri: base.join(parts.uri.path_and_query())?, origin: RouteOrigin::Base(base) });
    }
    match default {
        Some(base) => Ok(Route { uri: base.join(parts.uri.path_and_query())?, origin: RouteOrigin::Default }),
        None => Err(bad(format!(
            "no destination: send the {URL_HEADER} or {TARGET_HEADER} header, use webproxy as an HTTP proxy, \
             or set default_target in the client config"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::Request;

    fn parts(req: Request<()>) -> Parts {
        req.into_parts().0
    }

    fn base(s: &str) -> TargetBase {
        TargetBase::parse(s).unwrap()
    }

    #[test]
    fn base_parsing_and_join() {
        let pq = |s: &'static str| PathAndQuery::from_static(s);
        assert_eq!(base("http://127.0.0.1:3000").join(Some(&pq("/a?b=1"))).unwrap(), "http://127.0.0.1:3000/a?b=1");
        assert_eq!(base("https://api.example.com/v2/").join(Some(&pq("/users"))).unwrap(), "https://api.example.com/v2/users");
        assert_eq!(base("http://h:1").join(None).unwrap(), "http://h:1/");
        assert_eq!(base("https://api.example.com/v2/").local_path("https://api.example.com/v2/x"), Some("/x"));
        for bad in ["ftp://x", "/relative", "http://x/?q=1", "not a url"] {
            assert!(TargetBase::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn resolution_precedence() {
        let default = base("http://127.0.0.1:9000");
        let resolve_uri = |req: Request<()>| {
            resolve(&mut parts(req), Some(&default)).map(|r| (r.uri.to_string(), matches!(r.origin, RouteOrigin::Default)))
        };
        // Proxy (absolute-form) wins.
        let r = resolve_uri(Request::get("http://10.0.0.1:81/x?y=1").header(TARGET_HEADER, "http://h:1").body(()).unwrap());
        assert_eq!(r.unwrap(), ("http://10.0.0.1:81/x?y=1".into(), false));
        // Exact URL header beats the base URL header.
        let r = resolve_uri(
            Request::get("/ignored").header(URL_HEADER, "https://h/exact?q=1").header(TARGET_HEADER, "http://x").body(()).unwrap(),
        );
        assert_eq!(r.unwrap(), ("https://h/exact?q=1".into(), false));
        // Base URL header beats the default.
        let r = resolve_uri(Request::get("/x?y=1").header(TARGET_HEADER, "https://h:8443/base").body(()).unwrap());
        assert_eq!(r.unwrap(), ("https://h:8443/base/x?y=1".into(), false));
        // Default.
        assert_eq!(resolve_uri(Request::get("/x").body(()).unwrap()).unwrap(), ("http://127.0.0.1:9000/x".into(), true));
        // HTTP/2 authority is not treated as a proxy target.
        let r = resolve_uri(Request::get("http://127.0.0.1:8080/x").version(Version::HTTP_2).body(()).unwrap());
        assert_eq!(r.unwrap(), ("http://127.0.0.1:9000/x".into(), true));
        // Nothing configured, asterisk-form, invalid headers.
        assert!(resolve(&mut parts(Request::get("/x").body(()).unwrap()), None).is_err());
        assert!(resolve_uri(Request::options("*").body(()).unwrap()).is_err());
        assert!(resolve_uri(Request::get("/").header(URL_HEADER, "/relative").body(()).unwrap()).is_err());
    }
}
