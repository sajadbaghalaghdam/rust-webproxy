# webproxy

End-to-end encrypted HTTP tunnel. One binary runs either as the **client** (next to your
applications) or the **server** (next to the services you call). Everything that passes the
CDN in between — URL, query string, headers, cookies, bodies, uploads, responses — is
encrypted, so the CDN only sees opaque `POST` requests to one path.

```
your app ──HTTP──▶ webproxy client ══encrypted══▶ CDN ══encrypted══▶ webproxy server ──HTTP(S)──▶ destination
          plain    (encrypts request,             (sees only            (decrypts, forwards,          (the URL your
                    decrypts response)             ciphertext)           encrypts response)            app chose)
```

## Security design

The CDN is treated as an active attacker: it can read, change, drop, delay, replay and forge traffic.

| Piece | Choice |
|---|---|
| Pairing | 32-byte random pairing key per client, shared once between server and client (`init` / `add-client`) |
| Key exchange | Ephemeral X25519 authenticated with the pairing key (HMAC-SHA256), repeated automatically every `rekey_interval_secs` (default **24 h**): forward secrecy, and a CDN in the middle cannot substitute keys |
| Per-request keys | HKDF-SHA256 from the session secret and a request sequence number; separate keys per direction |
| Encryption | ChaCha20-Poly1305 frames (32 KiB); nonce = frame counter + "last frame" flag, so reordering, truncation and splicing are detected |
| Replay | Handshakes: timestamp window + nonce cache. Requests: anti-replay window per session — a request replayed by the CDN never reaches the destination |
| Delay | The authenticated final frame of every request carries its age on the session clock and always carries the last body bytes. Requests announced with at most 32 KiB of body (or none) are forwarded only after that final frame has been verified; larger and chunked ones are streamed, but the destination receives their last bytes only if the final frame arrived within `max_request_age_secs` (default 300 s), however the CDN holds back or trickles the parts before it. Late requests are refused and never completed |
| Forged errors | Outer status codes are not authenticated, so after a "session unknown" answer or a broken connection only safe requests (GET, HEAD, OPTIONS, TRACE) with small bodies are resent automatically; a POST, PUT or DELETE is never sent twice by webproxy |
| What the CDN learns | that a tunnel exists, the session id, message sizes (heads are padded to a multiple of 256 bytes) and timing. The client's identity is a hint that changes every 10 minutes |

The raw session secrets are wiped from memory when a session ends. Config files holding pairing keys
are created with mode `0600` on Linux; rewriting one (`add-client`) keeps its owner and mode. Client and
server must run the same protocol version (currently 2); a mismatch is reported as such.

## Build

```bash
cargo build --release                       # target/release/webproxy
```

Linux is the primary target. From Windows/macOS a Linux binary (glibc ≥ 2.17) can be built with
[cargo-zigbuild](https://github.com/rust-cross/cargo-zigbuild):
`cargo zigbuild --release --target x86_64-unknown-linux-gnu.2.17`.

The system allocator is the default (measured on Windows: ~10x less memory than mimalloc for the same
throughput); `--features mimalloc` is available.

## Setup

On both machines, install the binary and create the service account and config directory:

```bash
sudo install -m 755 target/release/webproxy /usr/local/bin/webproxy
sudo useradd --system --no-create-home --shell /usr/sbin/nologin webproxy
sudo install -d -o root -g webproxy -m 750 /etc/webproxy
```

On the **server** machine:

```bash
webproxy init --mode server --out /etc/webproxy/server.toml --listen 0.0.0.0:8443
# prints the pairing key for the first client ("client1")
webproxy add-client --config /etc/webproxy/server.toml --name laptop   # one key per client process
```

On the **client** machine, save the pairing key to a file only root can read (`init` copies it into
`client.toml`, so the file can be deleted afterwards), then:

```bash
webproxy init --mode client --out /etc/webproxy/client.toml \
  --server-url https://cdn.example.com/api/v1/stream \
  --key-file /etc/webproxy/client.key \
  --default-target http://127.0.0.1:3000      # optional
```

Point the CDN at the server's `listen` address (HTTP, or HTTPS with `tls_cert`/`tls_key`). The systemd
units run as user `webproxy`, so give it read access: `chown root:webproxy /etc/webproxy/*.toml && chmod 640 /etc/webproxy/*.toml`.
Run either side with the same binary — the role comes from `mode` in the config:

```bash
webproxy run --config /etc/webproxy/server.toml
```

`deploy/webproxy-server.service` and `deploy/webproxy-client.service` are systemd units
(`LimitNOFILE`, hardening). `SIGTERM` stops accepting new connections and lets in-flight requests
finish for up to `shutdown_timeout_secs` (a second signal exits at once; keep `TimeoutStopSec` above it).
Log level: `WEBPROXY_LOG=debug`.

## Choosing the destination from your code

The destination is decided **per request by your application**; client and server just follow it.
In order of precedence:

1. **HTTP proxy mode** — use the client as an HTTP proxy; the full URL in the request is the destination.
2. **`X-Tunnel-Url`** — the exact destination URL (path and query included); the request's own path is ignored.
3. **`X-Tunnel-Target`** — a base URL (`http://host:port` or `https://host/prefix`); the request's path and query are appended.
4. **`default_target`** from the client config.

The control headers are removed before forwarding.

```python
import requests

# 1. proxy mode
requests.post("http://10.0.0.5:3000/api/orders?x=1", json={"id": 7},
              proxies={"http": "http://127.0.0.1:8080"})

# 2. exact URL
requests.get("http://127.0.0.1:8080/", headers={"X-Tunnel-Url": "https://api.internal/v2/users?page=2"})

# 3. base URL: sent to https://api.internal/v2/users?page=2
requests.get("http://127.0.0.1:8080/v2/users?page=2", headers={"X-Tunnel-Target": "https://api.internal"})
```

```bash
curl -x http://127.0.0.1:8080 http://10.0.0.5:3000/health
curl -H 'X-Tunnel-Target: http://10.0.0.5:3000' -F file=@video.mp4 http://127.0.0.1:8080/upload
```

For `https://` destinations send plain HTTP to the client and name the `https://` URL in a header
(the server makes the TLS connection). `CONNECT`, WebSocket and HTTP trailers (gRPC) are not supported.

The server only forwards to destinations matching `allowed_targets` (`"*"`, `"host:port"`,
`"host:*"`, `"*.example.com:443"`, `"[::1]:*"`); the `Host` header is checked as well.

The client only accepts requests addressed to an IP address, `localhost` or a name listed in
`allowed_hosts` — this stops web pages from reaching it through DNS rebinding.

Responses generated by webproxy itself carry `x-webproxy-error` (`1`, or `stale` for a request that
was delayed in transit); the server removes that header from destination responses, so everything
without it is the destination's own answer. A `502`/`503`/`504` from webproxy for a non-safe request
(POST, PUT, …) does not prove the request was not delivered — check before repeating it. A request
that lost bytes on its way through the tunnel gets `502` from the server (`504` if it stopped
arriving) and is never completed at the destination. Rate limits from the CDN arrive as `429` with
their `Retry-After`.

Example clients (set `IMAGE_SERVICE`, `VLLM`, `VLLM_KEY` and the model name at the top first):
[`examples/clients/requests_example.py`](examples/clients/requests_example.py) and
[`examples/clients/aiohttp_example.py`](examples/clients/aiohttp_example.py) (image upload with form fields,
JSON, forms, vLLM chat with and without streaming, proxy mode, the openai SDK).

### Uploads (e.g. images)

All body types pass through unchanged and streamed: `multipart/form-data` (files plus fields, repeated
fields, non-ASCII names), `application/x-www-form-urlencoded`, JSON, raw binary. There is no size limit by
default; set `max_request_body_mb` (client and/or server) to cap uploads — larger requests get `413`.
For 8 MB images plus form fields, `max_request_body_mb = 10` leaves room for the multipart overhead.

### vLLM / OpenAI-compatible APIs

Point the SDK or HTTP client at the webproxy client and name the vLLM server as the target:

```python
from openai import OpenAI
client = OpenAI(base_url="http://127.0.0.1:8080/v1", api_key="KEY",
                default_headers={"X-Tunnel-Target": "http://127.0.0.1:8000"})   # vLLM, seen from the server
```

All paths (`/v1/chat/completions`, `/v1/completions`, `/v1/embeddings`, `/v1/models`, `/health`, …) work,
`Authorization` headers pass through, and `"stream": true` responses (server-sent events) arrive token by
token. For long non-streaming generations raise `response_timeout_secs` (client) and
`upstream_response_timeout_secs` (server) above the longest generation time; for streaming, keep
`stream_idle_timeout_secs` above the longest pause between tokens.

## Status

```bash
webproxy status --config /etc/webproxy/server.toml     # or --addr 127.0.0.1:9901, --json
```

or open `http://127.0.0.1:9901/` (server) / `http://127.0.0.1:9902/` (client) for a live page;
`/status.json` returns the same as JSON: active/total connections, active/total/failed requests,
traffic received/sent, key exchanges, refused requests (unknown session, over `max_requests`, replayed,
delayed), the
current session and its next rotation (client), sessions per paired client (server). Refusals are
also summarized in the log every 30 s.

## Behaviour notes

* Bodies are streamed both ways (uploads, downloads, video, SSE) with back-pressure; memory per request is
  bounded by one frame (HTTP/1.0 responses of unknown length excepted, see below). Chunked uploads move
  chunk by chunk; only the last byte of each chunk waits for the next one, so the end of a request always
  travels in its authenticated final frame. A body that transfers nothing for `stream_idle_timeout_secs` (default 300, `0` = never,
  e.g. for long SSE pauses) is aborted.
* Timeouts for answers start once the request has been sent completely, so long uploads are not cut off;
  an upload that stops moving for `stream_idle_timeout_secs` is aborted. Connection setup (DNS, TCP, TLS)
  is bounded by `connect_timeout_secs`.
* If a destination needs longer than `early_response_secs` (default 20) after the request was sent, the
  server already starts the response and keeps it alive every `early_response_secs`, so CDN read timeouts
  (Cloudflare: 100 s) are not hit.
* Safe requests (GET, HEAD, OPTIONS, TRACE, body ≤ 64 KiB) are retried transparently when the server lost the
  session (e.g. after a restart) or the connection broke; other requests get `503` (session rejected) or `502`
  (connection broke) at once and the application decides, while a new key exchange already runs. When requests fail at the CDN (gateway errors, broken
  connections) with no answer on the session in between, the client re-keys in the background too: the
  server may have lost the session while the CDN hid its `401`.
* Both sides limit concurrent requests (`max_requests`, `503` beyond) and the client buffers at most 16
  HTTP/1.0 responses of unknown length (up to 16 MiB each) at a time.
* A client that wakes up from suspend re-keys before sending (its monotonic clock stopped meanwhile).
* Redirects from base-URL destinations (`default_target`, `X-Tunnel-Target`) are rewritten to point back at
  the client (`rewrite_redirects`), including origin-relative ones under the base's path prefix (which lose
  the prefix); with `X-Tunnel-Url` and in proxy mode they are left alone.
* `Expect: 100-continue` is answered by the client itself; the destination cannot refuse an upload early.
* Streamed responses carry `X-Accel-Buffering: no` so nginx-based intermediaries pass them on immediately;
  intermediaries must not buffer tunnel traffic. A CDN that buffers request bodies delays streamed uploads,
  and an upload whose head waits behind more than 2^20 later requests of the same session is refused.
* With known lengths the outer messages carry an exact `Content-Length` (best for CDNs); otherwise chunked.
* Idle connections are closed after `idle_timeout_secs`; connections that never send a request are dropped.
* Client and server clocks must agree within `max_clock_skew_secs` (default 300 s) — use NTP.
* CDN limits still apply to the outer request (e.g. maximum upload size).

## Configuration reference

Server (`mode = "server"`)

| key | default | meaning |
|---|---|---|
| `listen` | `0.0.0.0:8443` | address the CDN connects to |
| `tunnel_path` | `/api/v1/stream` | only `POST` to this path is tunnel traffic; everything else gets `404` |
| `status_listen` | `127.0.0.1:9901` | status page; `""` disables |
| `rekey_interval_secs` | `86400` | session key lifetime (10 s … 7 days) |
| `max_clock_skew_secs` | `300` | accepted clock difference for key exchange |
| `max_request_age_secs` | `300` | requests delayed longer in transit are refused |
| `allowed_targets` | `["*"]` | destinations clients may reach |
| `tls_cert`, `tls_key` | – | PEM files to serve HTTPS (HTTP/2 via ALPN) |
| `upstream_connect_timeout_secs` | `10` | |
| `upstream_response_timeout_secs` | `300` | time a destination may take to answer after the request was sent |
| `upstream_pool_idle_secs`, `upstream_pool_max_idle` | `60`, `1024` | keep-alive pool to destinations |
| `upstream_ca_file` | – | extra CA bundle for `https://` destinations |
| `max_connections` | `20000` | concurrent inbound connections |
| `max_requests` | `10000` | concurrent tunnelled requests; beyond that `503` |
| `max_request_body_mb` | `0` | largest request body forwarded, in MiB; larger gets `413` (`0` = no limit) |
| `idle_timeout_secs` | `60` | idle keep-alive connections are closed |
| `stream_idle_timeout_secs` | `300` | abort bodies without progress (`0` = never) |
| `early_response_secs` | `20` | start (and keep alive) the response when a destination is slow to answer (`0` = never) |
| `shutdown_timeout_secs` | `30` | drain time on SIGTERM / Ctrl-C |
| `workers` | `0` | worker threads, 0 = CPU cores |
| `[[clients]]` | | `name`, `key` per paired client |

Client (`mode = "client"`)

| key | default | meaning |
|---|---|---|
| `listen` | `127.0.0.1:8080` | where local applications connect |
| `status_listen` | `127.0.0.1:9902` | status page; `""` disables |
| `server_url` | – | tunnel URL through the CDN, e.g. `https://cdn.example.com/api/v1/stream` |
| `key` | – | pairing key |
| `default_target` | – | destination for requests that name none |
| `rewrite_redirects` | `true` | point redirects from base-URL destinations (`default_target`, `X-Tunnel-Target`) back at the client |
| `preserve_host` | `false` | forward the app's `Host` instead of the destination's |
| `allowed_hosts` | `[]` | host names (besides IPs and `localhost`) apps may use to reach the client |
| `ca_file` | – | extra CA bundle for `server_url` |
| `connect_timeout_secs` | `10` | |
| `response_timeout_secs` | `300` | time the server may take to answer after the request was sent |
| `stream_idle_timeout_secs` | `300` | abort bodies without progress (`0` = never) |
| `pool_idle_secs`, `pool_max_idle` | `90`, `1024` | keep-alive pool to the server |
| `max_connections` | `10000` | concurrent local connections |
| `max_requests` | `10000` | concurrent requests in flight; beyond that `503` |
| `max_request_body_mb` | `0` | largest request body accepted from apps, in MiB; larger gets `413` (`0` = no limit) |
| `idle_timeout_secs` | `60` | idle keep-alive connections are closed |
| `shutdown_timeout_secs` | `30` | drain time on SIGTERM / Ctrl-C |
| `workers` | `0` | worker threads, 0 = CPU cores |

## Performance

Measured on one 8-core machine with load generator, client, server and destination all sharing it
(`tests/bench.py`, `oha`), zero errors in every run:

| case | concurrency | requests/s | p50 / p99 |
|---|---|---|---|
| 1 KiB responses through the tunnel | 64 | ~26 000 | 2.4 / 4.3 ms |
| 1 MiB responses through the tunnel | 16 | ~2 570 (≈ 2.5 GiB/s) | 5.5 / 18 ms |

Memory stays flat under sustained load (soak test: 8 rounds of load, no growth); after the benchmark the
server used ~27 MiB and the client ~10 MiB of private memory.

## Tests

```bash
cargo test                                          # unit tests
cargo build --release
uv run --with requests --with psutil --with cryptography --with h11 --with "httpx[http2]" --with aiohttp --with openai python tests/e2e.py
uv run --with requests --with psutil --with cryptography --with h11 --with "httpx[http2]" python tests/soak.py
cargo build --release --example bench_upstream && uv run --with requests --with psutil --with cryptography --with h11 --with "httpx[http2]" python tests/bench.py   # needs `oha`
```

The end-to-end suite (49 tests, `tests/e2e.py` + `tests/e2e_apps.py`) runs the real binaries with a
Python destination service, a passive fake CDN that inspects every byte, and an actively malicious CDN.
It covers methods, query strings, headers, every kind of form field, multipart uploads with 8 MiB
images (requests and aiohttp), upload size limits, 200 MiB downloads, 100 MiB streaming uploads,
chunked and streamed responses, an OpenAI/vLLM-style API (requests, aiohttp, openai SDK, SSE
streaming), status codes, proxy mode, exact and prefixed targets, HTTPS destinations, HTTP/2 and
HTTP/1.0 clients, "the CDN sees no plaintext", replay rejection, forged `401`s, requests held back by
the CDN, requests truncated by the CDN, lost sessions hidden behind gateway errors, chunk-by-chunk
streamed uploads, silent connections, DNS rebinding, preserved Host checks, admission limits on both
sides, redirects (including relative ones under a prefixed base), wrong pairing keys, server restart,
key rotation under load with memory checks, idle gauges, TLS between client and server, and graceful
shutdown.

## License

MIT, see [LICENSE](LICENSE).
