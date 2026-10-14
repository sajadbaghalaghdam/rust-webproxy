"""Core end-to-end tests for webproxy (see harness.py for the topology).

Run:  uv run --with requests --with psutil --with cryptography --with h11 --with "httpx[http2]" --with aiohttp --with openai python tests/e2e.py
"""

import hashlib
import importlib
import os
import random
import re
import signal
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import httpx
import requests

from harness import (BIN, DATA_PREFIX, HELLO_PREFIX, MARKERS, MAX_REQUEST_AGE_SECS, REKEY_SECS, TUNNEL_PATH, Ctx, Env,
                     blob_sha, free_port, load, main, private_mb, test)
from fake_cdn import parse_http_requests
from upstream import blob_chunks


@test
def startup_and_status(c):
    srv, cli = c.env.status("server"), c.env.status("client")
    assert srv["mode"] == "server" and cli["mode"] == "client"
    assert cli["handshakes"]["ok"] >= 1, cli
    assert cli["session"] is not None, cli
    assert {x["name"] for x in srv["clients"]} == {"laptop", "phone"}
    out = c.env.cli("status", "--config", str(c.env.client_cfg))
    assert "next rotation" in out, out
    out = c.env.cli("status", "--config", str(c.env.server_cfg))
    assert "refused" in out and "unknown session" in out and "laptop" in out, out


@test
def get_with_query_and_headers_via_target_header(c):
    r = c.s.get(c.url("/echo/a%20b/c?x=1&y=%C3%BCber-%E6%97%A5%E6%9C%AC&empty="),
                headers={**c.target, "X-Custom": "abc;def=1", "Authorization": "Bearer t0k3n", "Accept-Language": "de-DE"})
    assert r.status_code == 200, r.text
    j = r.json()
    assert j["method"] == "GET" and j["path"] == "/echo/a%20b/c"
    assert j["query"] == {"x": "1", "y": "über-日本", "empty": ""}, j["query"]
    h = {k.lower(): v for k, v in j["headers"]}
    assert h["x-custom"] == "abc;def=1" and h["authorization"] == "Bearer t0k3n" and h["accept-language"] == "de-DE"
    assert "x-tunnel-target" not in h, "control header must not reach the destination"
    assert h["host"] == f"127.0.0.1:{c.env.ports['up']}"


@test
def default_target_routing(c):
    r = c.s.get(c.url("/echo?via=default"))
    assert r.status_code == 200 and r.json()["query"] == {"via": "default"}


@test
def http_proxy_mode(c):
    proxies = {"http": c.base}
    r = c.s.get(f"{c.up}/echo/proxied?p=1", proxies=proxies)
    assert r.status_code == 200, r.text
    assert r.json()["path"] == "/echo/proxied" and r.json()["query"] == {"p": "1"}


@test
def all_methods(c):
    for m in ["POST", "PUT", "PATCH", "DELETE", "OPTIONS"]:
        body = f"{m} body ü".encode()
        r = c.s.request(m, c.url("/echo/m"), data=body, headers=c.target)
        assert r.status_code == 200, (m, r.text)
        j = r.json()
        assert j["method"] == m and j["body_sha256"] == hashlib.sha256(body).hexdigest(), (m, j)
    r = c.s.delete(c.url("/echo/nobody"), headers=c.target)
    assert r.json()["body_len"] == 0
    r = c.s.head(c.url("/blob?size=12345"), headers=c.target)
    assert r.status_code == 200 and r.headers["Content-Length"] == "12345" and r.content == b""


@test
def json_and_form_posts(c):
    r = c.s.post(c.url("/echo/json"), json={"user": "alice", "n": [1, 2, 3]}, headers=c.target)
    assert r.json()["body_sha256"] == hashlib.sha256(b'{"user": "alice", "n": [1, 2, 3]}').hexdigest()
    form = {"name": "Zoë", "email": "a@b.c", "note": "x&y=z"}
    prepared = c.s.prepare_request(requests.Request("POST", c.url("/echo/form"), data=form, headers=c.target))
    r = c.s.send(prepared)
    assert r.json()["body_sha256"] == hashlib.sha256(prepared.body.encode()).hexdigest()


@test
def multipart_upload_with_image(c):
    image = random.Random(5).randbytes(3 * 2**20)
    files = {"photo": ("photo.jpg", image, "image/jpeg"), "doc": ("a.txt", b"hello", "text/plain")}
    prepared = c.s.prepare_request(requests.Request("POST", c.url("/echo/upload"), files=files, data={"caption": "été"}, headers=c.target))
    r = c.s.send(prepared)
    j = r.json()
    assert j["body_len"] == len(prepared.body) and j["body_sha256"] == hashlib.sha256(prepared.body).hexdigest()


@test
def binary_body_roundtrip(c):
    data = bytes(range(256)) * 300 + b"\x00\r\n\r\n0\r\n"
    r = c.s.post(c.url("/raw"), data=data, headers=c.target)
    assert r.content == data


@test
def large_download_200mb(c):
    size = 200 * 2**20
    t = time.time()
    r = c.s.get(c.url(f"/blob?size={size}&seed=7"), headers=c.target, stream=True)
    h = hashlib.sha256()
    n = 0
    for chunk in r.iter_content(1 << 20):
        h.update(chunk)
        n += len(chunk)
    dt = time.time() - t
    assert n == size and h.hexdigest() == blob_sha(size, 7)
    c.note(f"200 MiB download: {size / 2**20 / dt:.0f} MiB/s")


@test
def large_streaming_upload_100mb(c):
    size = 100 * 2**20
    expected = hashlib.sha256()

    def gen():
        for chunk in blob_chunks(size, 11):
            expected.update(chunk)
            yield chunk

    t = time.time()
    r = c.s.post(c.url("/echo/upload-stream"), data=gen(), headers=c.target)
    dt = time.time() - t
    j = r.json()
    assert j["body_len"] == size and j["body_sha256"] == expected.hexdigest()
    c.note(f"100 MiB chunked upload: {size / 2**20 / dt:.0f} MiB/s")


@test
def large_upload_with_content_length(c):
    data = b"".join(blob_chunks(50 * 2**20, 3))
    r = c.s.put(c.url("/echo/upload-len"), data=data, headers=c.target)
    j = r.json()
    assert j["body_len"] == len(data) and j["body_sha256"] == hashlib.sha256(data).hexdigest() and not j["chunked"]


@test
def chunked_response_without_length(c):
    size = 5 * 2**20 + 17
    r = c.s.get(c.url(f"/chunked?size={size}&seed=4"), headers=c.target)
    assert len(r.content) == size and hashlib.sha256(r.content).hexdigest() == blob_sha(size, 4)


@test
def streaming_is_not_buffered(c):
    t = time.time()
    r = c.s.get(c.url("/slow?chunks=5&delay=0.4"), headers=c.target, stream=True)
    first = None
    data = b""
    for chunk in r.iter_content(None):
        if first is None:
            first = time.time() - t
        data += chunk
    total = time.time() - t
    assert data.count(b"tick") == 5
    assert first < 1.0 and total >= 1.6, (first, total)
    c.note(f"streaming: first chunk after {first:.2f}s, all after {total:.2f}s")


@test
def status_codes_and_redirects(c):
    for code in [201, 400, 404, 418, 500, 503]:
        r = c.s.get(c.url(f"/status/{code}"), headers=c.target)
        assert r.status_code == code and r.text == f"status {code}" and "x-webproxy-error" not in r.headers
    r = c.s.get(c.url("/status/302"), headers=c.target, allow_redirects=False)
    assert r.status_code == 302 and r.headers["Location"] == "/elsewhere"
    for code in [204, 304]:
        r = c.s.get(c.url(f"/status/{code}"), headers=c.target)
        assert r.status_code == code and r.content == b""


@test
def duplicate_response_headers(c):
    r = c.s.get(c.url("/cookies"), headers=c.target)
    cookies = r.raw.headers.getlist("Set-Cookie")
    assert cookies == ["a=1; Path=/", "b=2; Path=/"], cookies


@test
def cdn_sees_no_plaintext(c):
    before = c.env.cdn.bytes_c2s
    r = c.s.post(
        c.url(f"/echo/{MARKERS[0]}?q={MARKERS[1]}&echo={MARKERS[4]}"),
        headers={**c.target, "X-Secret": MARKERS[2]},
        data=("payload " + MARKERS[3]).encode(),
    )
    j = r.json()
    assert j["secret_echo"] == MARKERS[4], "response must contain the marker"
    assert c.env.cdn.bytes_c2s > before, "traffic did not go through the CDN"
    assert not c.env.cdn.found, f"CDN saw plaintext: {c.env.cdn.found}"


@test
def replayed_request_is_rejected(c):
    mark = f"replay-{random.randrange(1 << 30)}"
    c.env.cdn.start_capture()
    r = c.s.post(c.url(f"/mark?id={mark}"), data=b"transfer=100", headers=c.target)
    captures = c.env.cdn.stop_capture()
    assert r.status_code == 200
    data_reqs = [raw for buf in captures.values() for raw, line, h, body in parse_http_requests(buf)
                 if line.startswith(f"POST {TUNNEL_PATH}") and body[:2] == DATA_PREFIX]
    assert len(data_reqs) == 1, f"expected one captured request, got {len(data_reqs)}"
    with socket.create_connection(("127.0.0.1", c.env.ports["server"]), timeout=10) as s:
        s.sendall(data_reqs[0])
        status_line = s.recv(4096).split(b"\r\n", 1)[0]
    assert b" 400 " in status_line or b" 401 " in status_line, status_line
    count = c.s.get(f"{c.up}/marks?id={mark}").json()["count"]
    assert count == 1, f"destination saw the request {count} times"


@test
def probing_the_server_reveals_nothing(c):
    srv = f"http://127.0.0.1:{c.env.ports['server']}"
    assert requests.get(srv + "/").status_code == 404
    assert requests.get(srv + TUNNEL_PATH).status_code == 404
    assert requests.post(srv + TUNNEL_PATH, data=b"\x09" + os.urandom(499)).status_code == 426, "other version"
    assert requests.post(srv + TUNNEL_PATH, data=b"\x02\x09" + os.urandom(100)).status_code == 400
    hello = HELLO_PREFIX + os.urandom(112)
    assert requests.post(srv + TUNNEL_PATH, data=hello).status_code == 403
    fake_data = DATA_PREFIX + os.urandom(16) + b"\x00" * 8 + os.urandom(100)
    assert requests.post(srv + TUNNEL_PATH, data=fake_data).status_code == 401
    assert c.s.get(c.url("/echo?still=alive"), headers=c.target).status_code == 200


@test
def disallowed_and_unreachable_targets(c):
    r = c.s.get(c.url("/echo"), headers={"X-Tunnel-Target": "http://10.255.255.1:80"})
    assert r.status_code == 403 and r.headers.get("x-webproxy-error") == "1", (r.status_code, r.text)
    dead = free_port()
    r = c.s.get(c.url("/echo"), headers={"X-Tunnel-Target": f"http://127.0.0.1:{dead}"})
    assert r.status_code == 502 and "upstream error" in r.text, (r.status_code, r.text)
    r = c.s.get(c.url("/echo"), headers={"X-Tunnel-Target": "ftp://x"})
    assert r.status_code == 400
    r = c.s.request("CONNECT", c.url("/"), headers=c.target)
    assert r.status_code in (400, 405)


@test
def wrong_pairing_key_is_refused(c):
    port, status_port = free_port(), free_port()
    cfg = c.env.dir / "bad-client.toml"
    bad_key = c.env.cli("keygen").strip()
    c.env.cli("init", "--mode", "client", "--out", str(cfg), "--listen", f"127.0.0.1:{port}",
              "--server-url", f"http://127.0.0.1:{c.env.ports['cdn']}{TUNNEL_PATH}", "--key", bad_key,
              "--default-target", c.up)
    Env.patch(cfg, status_listen=f'"127.0.0.1:{status_port}"')
    failed_before = c.env.status("server")["handshakes"]["failed"]
    c.env.spawn("bad-client", [str(BIN), "run", "--config", str(cfg)], port)
    try:
        r = c.s.get(f"http://127.0.0.1:{port}/echo")
        assert r.status_code == 502 and "key exchange" in r.text, (r.status_code, r.text)
    finally:
        c.env.stop("bad-client")
    assert c.env.status("server")["handshakes"]["failed"] > failed_before


@test
def forged_401_does_not_duplicate_requests(c):
    """The CDN delivers a POST, then claims the session is unknown: the client must not resend it."""
    base = f"http://127.0.0.1:{c.env.ports['evil_client']}"
    assert c.s.get(f"{base}/echo?warm=1").status_code == 200
    mark = f"forged-{random.randrange(1 << 30)}"
    c.env.evil.arm("forward_then_401")
    r = c.s.post(f"{base}/mark?id={mark}", data=b"transfer=100")
    assert r.status_code == 503 and r.headers.get("x-webproxy-error") == "1", (r.status_code, r.text)
    assert c.s.get(f"{c.up}/marks?id={mark}").json()["count"] == 1, "the POST was executed twice"
    # Idempotent requests are resent transparently on a fresh session.
    c.env.evil.arm("forward_then_401")
    r = c.s.get(f"{base}/echo?idempotent=1")
    assert r.status_code == 200 and r.json()["query"] == {"idempotent": "1"}, r.text


@test
def requests_held_back_by_the_cdn_expire(c):
    base = f"http://127.0.0.1:{c.env.ports['evil_client']}"
    late, prompt = (f"held-{random.randrange(1 << 30)}" for _ in range(2))
    c.env.evil.arm("hold")
    assert c.s.post(f"{base}/mark?id={prompt}", data=b"x").status_code == 503
    assert c.env.evil.deliver_held() == 200, "a held request delivered in time is still accepted"
    stale_before = c.env.status("server")["rejected"]["stale"]
    c.env.evil.arm("hold")
    assert c.s.post(f"{base}/mark?id={late}", data=b"x").status_code == 503
    # A streamed (chunked) upload as well: its last bytes travel in the stamped final frame.
    chunked = f"held-chunked-{random.randrange(1 << 30)}"
    c.env.evil.arm("hold")
    assert c.s.post(f"{base}/mark?id={chunked}", data=(p for p in [b"a" * 70_000, b"b" * 70_000])).status_code == 503
    time.sleep(MAX_REQUEST_AGE_SECS + 1.5)
    c.env.evil.deliver_held()  # answered with an encrypted "stale" error only the client could read
    c.env.evil.deliver_held()
    counts = [c.s.get(f"{c.up}/marks?id={m}").json()["count"] for m in (prompt, late, chunked)]
    assert counts == [1, 0, 0], counts
    assert c.env.status("server")["rejected"]["stale"] == stale_before + 2


@test
def truncated_requests_never_reach_the_destination(c):
    base = f"http://127.0.0.1:{c.env.ports['evil_client']}"
    mark = f"truncated-{random.randrange(1 << 30)}"
    c.env.evil.arm("truncate")
    r = c.s.post(f"{base}/mark?id={mark}", data=b"x" * 3000)
    # Answered (encrypted) by the server: a gateway error, since the tunnel lost part of it.
    assert r.status_code == 502 and r.headers.get("x-webproxy-error") == "1", (r.status_code, r.text)
    assert "did not arrive intact" in r.text, r.text
    assert c.s.get(f"{c.up}/marks?id={mark}").json()["count"] == 0


@test
def gateway_errors_make_the_client_check_its_session(c):
    # A CDN may turn the 401 for a lost session into a gateway error (e.g. by resetting a large
    # upload). With no answer on the session since, the client re-keys in the background.
    env, base = c.env, f"http://127.0.0.1:{c.env.ports['evil_client']}"
    if env.status("evil_client")["session"]["rotates_in_secs"] < 5:
        time.sleep(6)  # keep the scheduled key rotation out of the measured window
    before = env.status("evil_client")["handshakes"]["ok"]
    env.evil.arm("bad_gateway")
    r = c.s.post(f"{base}/echo", data=b"x" * 1000)
    assert r.status_code == 502 and "HTTP 502" in r.text, (r.status_code, r.text)
    deadline = time.time() + 3
    while env.status("evil_client")["handshakes"]["ok"] == before and time.time() < deadline:
        time.sleep(0.1)
    assert env.status("evil_client")["handshakes"]["ok"] == before + 1
    assert c.s.post(f"{base}/echo", data=b"y" * 1000).json()["body_len"] == 1000


@test
def cdn_rate_limits_and_destination_markers_pass_correctly(c):
    base = f"http://127.0.0.1:{c.env.ports['evil_client']}"
    c.env.evil.arm("rate_limit")
    r = c.s.get(f"{base}/echo?limited=1")
    assert r.status_code == 429 and r.headers.get("Retry-After") == "7", (r.status_code, r.headers)
    # A destination cannot impersonate webproxy's own markers (nor trigger a key exchange).
    if c.env.status("client")["session"]["rotates_in_secs"] < 3:
        time.sleep(4)  # keep the scheduled key rotation out of the measured window
    exchanges = c.env.status("client")["handshakes"]["ok"]
    r = c.s.get(c.url("/fake-marker"), headers=c.target)
    assert r.status_code == 503 and "x-webproxy-error" not in r.headers, r.headers
    time.sleep(1)
    assert c.env.status("client")["handshakes"]["ok"] == exchanges


@test
def non_idempotent_requests_are_not_resent_after_restart(c):
    env = c.env
    env.stop("server")
    env.start_server()
    # Larger than the replay buffer and not safe to repeat: the client must not resend it.
    r = c.s.put(c.url("/echo/after-restart"), data=b"p" * 100_000, headers=c.target)
    assert r.status_code == 503 and "not resent" in r.text, (r.status_code, r.text)
    # The session was renewed meanwhile, so the next request goes through.
    assert c.s.put(c.url("/echo/again"), data=b"p" * 100_000, headers=c.target).json()["body_len"] == 100_000


@test
def http10_clients_get_complete_responses(c):
    size = 300_000
    with socket.create_connection(("127.0.0.1", c.env.ports["client"]), timeout=30) as s:
        s.sendall(f"GET /chunked?size={size}&seed=6 HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n".encode())
        raw = b""
        while chunk := s.recv(65536):
            raw += chunk
    head, _, body = raw.partition(b"\r\n\r\n")
    assert head.split(b"\r\n")[0].endswith(b" 200 OK"), head[:80]
    assert f"content-length: {size}".encode() in head.lower(), head
    assert hashlib.sha256(body).hexdigest() == blob_sha(size, 6)


@test
def preserved_host_is_checked_against_allowed_targets(c):
    env = c.env
    port, status_port = free_port(), free_port()
    cfg = env.client_config("host-client", port, status_port, env.ports["cdn"], env.key)
    Env.patch(cfg, preserve_host="true", allowed_hosts='["evil.example"]')
    env.spawn("host-client", [str(BIN), "run", "--config", str(cfg)], port)
    try:
        base = f"http://127.0.0.1:{port}"
        r = c.s.get(f"{base}/echo", headers=c.target)
        host = {k.lower(): v for k, v in r.json()["headers"]}["host"]
        assert r.status_code == 200 and host == f"127.0.0.1:{port}", r.text
        r = c.s.get(f"{base}/echo", headers={**c.target, "Host": "evil.example"})
        assert r.status_code == 403 and "not allowed" in r.text, (r.status_code, r.text)
    finally:
        env.stop("host-client")


@test
def client_admission_limit(c):
    env = c.env
    port, status_port = free_port(), free_port()
    cfg = env.client_config("admission-client", port, status_port, env.ports["cdn"], env.key)
    Env.patch(cfg, max_requests=1)
    env.spawn("admission-client", [str(BIN), "run", "--config", str(cfg)], port)
    try:
        base = f"http://127.0.0.1:{port}"
        with ThreadPoolExecutor(2) as ex:
            slow = ex.submit(Ctx.session().get, f"{base}/sleep?secs=1.5", headers=c.target)
            time.sleep(0.5)
            busy = Ctx.session().get(f"{base}/echo", headers=c.target)
            assert busy.status_code == 503 and "max_requests" in busy.text, (busy.status_code, busy.text)
            assert slow.result().status_code == 200
    finally:
        env.stop("admission-client")


@test
def server_admission_limit(c):
    env = c.env
    port, status_port, client_port = free_port(), free_port(), free_port()
    cfg = env.dir / "admission-server.toml"
    out = env.cli("init", "--mode", "server", "--out", str(cfg), "--listen", f"127.0.0.1:{port}", "--name", "solo")
    key = re.search(r"^\s+(\S{40,})\s*$", out, re.M).group(1)
    Env.patch(cfg, status_listen=f'"127.0.0.1:{status_port}"', max_requests=1, allowed_targets='["127.0.0.1:*"]')
    client_cfg = env.client_config("admission-server-client", client_port, free_port(), port, key)
    env.spawn("admission-server", [str(BIN), "run", "--config", str(cfg)], port)
    env.spawn("admission-server-client", [str(BIN), "run", "--config", str(client_cfg)], client_port)
    try:
        base = f"http://127.0.0.1:{client_port}"
        with ThreadPoolExecutor(2) as ex:
            slow = ex.submit(Ctx.session().get, f"{base}/sleep?secs=1.5", headers=c.target)
            time.sleep(0.5)
            busy = Ctx.session().get(f"{base}/echo", headers=c.target)
            assert busy.status_code == 503 and "HTTP 503" in busy.text, (busy.status_code, busy.text)
            assert slow.result().status_code == 200
        status = requests.get(f"http://127.0.0.1:{status_port}/status.json", timeout=5).json()
        assert status["rejected"]["busy"] == 1, status["rejected"]
    finally:
        env.stop("admission-server-client")
        env.stop("admission-server")


@test
def silent_connections_are_closed(c):
    started = time.time()

    def wait_closed(sock):
        sock.settimeout(40)
        try:
            return sock.recv(1) == b""
        except ConnectionResetError:
            return True

    with socket.create_connection(("127.0.0.1", c.env.ports["server"])) as silent, \
            socket.create_connection(("127.0.0.1", c.env.ports["server"])) as partial:
        partial.sendall(b"PRI * HT")  # unfinished HTTP/2 preface
        assert wait_closed(silent) and wait_closed(partial)
    elapsed = time.time() - started
    assert elapsed < 20, elapsed
    c.note(f"silent and half-preface connections closed after {elapsed:.1f}s (idle_timeout 10s)")


@test
def http2_cleartext_local_clients(c):
    with httpx.Client(http1=False, http2=True, trust_env=False) as h:
        r = h.get(c.url("/echo?h2=1"), headers=c.target)
        assert r.http_version == "HTTP/2" and r.status_code == 200 and r.json()["query"] == {"h2": "1"}
        r = h.post(c.url("/echo/h2"), content=b"x" * 100_000, headers=c.target)
        assert r.json()["body_len"] == 100_000


@test
def dns_rebinding_hosts_are_refused(c):
    r = c.s.get(c.url("/echo"), headers={**c.target, "Host": "attacker.example:8080"})
    assert r.status_code == 421 and r.headers.get("x-webproxy-error") == "1", r.status_code
    assert c.s.get(c.url("/echo"), headers={**c.target, "Host": "localhost"}).status_code == 200


@test
def exact_url_and_prefixed_targets(c):
    r = c.s.get(c.url("/ignored"), headers={"X-Tunnel-Url": f"{c.up}/echo/exact?a=1&b=two"})
    j = r.json()
    assert j["path"] == "/echo/exact" and j["query"] == {"a": "1", "b": "two"}, j
    r = c.s.get(c.url("/x?y=1"), headers={"X-Tunnel-Target": f"{c.up}/echo/prefix"})
    j = r.json()
    assert j["path"] == "/echo/prefix/x" and j["query"] == {"y": "1"}, j


@test
def streamed_uploads_move_chunk_by_chunk(c):
    def parts():
        yield b"a" * 1000
        time.sleep(2)
        yield b"b" * 10

    j = c.s.post(c.url("/arrival"), data=parts(), headers=c.target).json()
    assert j["body_len"] == 1010, j
    # The first chunk is not held back until the next one (only the very last byte waits).
    assert j["first_after"] < 1.0 and j["total_after"] > 1.5, j


@test
def redirects_from_default_target_come_back_through_the_client(c):
    r = c.s.get(c.url("/redirect-abs"), allow_redirects=False)
    assert r.status_code == 302 and r.headers["Location"] == f"{c.base}/echo?from=redirect", r.headers
    # Base-URL targets are rewritten as well (the app resends the header on a same-origin redirect)…
    r = c.s.get(c.url("/redirect-abs"), headers=c.target, allow_redirects=False)
    assert r.headers["Location"] == f"{c.base}/echo?from=redirect", r.headers
    # …exact URLs are not.
    r = c.s.get(c.url("/ignored"), headers={"X-Tunnel-Url": f"{c.up}/redirect-abs"}, allow_redirects=False)
    assert r.headers["Location"] == f"{c.up}/echo?from=redirect", r.headers
    # Origin-relative redirects under a prefixed base lose the prefix (the client adds it back).
    r = c.s.get(c.url("/redirect-rel"), headers={"X-Tunnel-Target": f"{c.up}/api"}, allow_redirects=False)
    assert r.headers["Location"] == f"{c.base}/echo?from=rel", r.headers


@test
def https_destinations(c):
    target = {"X-Tunnel-Target": f"https://localhost:{c.env.ports['up_tls']}"}
    r = c.s.get(c.url("/echo/tls?x=1"), headers=target)
    assert r.status_code == 200 and r.json()["query"] == {"x": "1"}, r.text
    size = 5 * 2**20
    r = c.s.get(c.url(f"/blob?size={size}&seed=8"), headers=target)
    assert hashlib.sha256(r.content).hexdigest() == blob_sha(size, 8)


@test
def slow_destinations_get_an_early_response(c):
    # early_response_secs = 1: the server starts the outer response before the destination answers.
    r = c.s.get(c.url("/sleep?secs=2.5"), headers=c.target)
    assert r.status_code == 200 and r.text == "slept", r.text
    r = c.s.post(c.url("/sleep?secs=1.5"), data=b"z" * 70_000, headers=c.target)
    assert r.status_code == 200 and r.text == "slept", r.text


@test
def load_with_key_rotation_and_memory(c):
    env = c.env
    rot_before = env.status("client")["key_rotations"]
    sid_before = env.status("client")["session"]["id"]
    mem = []
    rounds = 3
    total_reqs, all_errors = 0, []
    for rnd in range(rounds):
        lat, errors = load(c, seconds=25, workers=48)
        total_reqs += len(lat)
        all_errors += errors
        mem.append((private_mb(env.procs["server"].pid), private_mb(env.procs["client"].pid)))
        lat.sort()
        c.note(
            f"load round {rnd + 1}: {len(lat)} req in 25s = {len(lat) / 25:.0f} req/s, "
            f"p50 {lat[len(lat) // 2] * 1000:.1f} ms, p99 {lat[int(len(lat) * 0.99)] * 1000:.1f} ms, "
            f"errors {len(errors)}, private MiB server/client {mem[-1][0]:.1f}/{mem[-1][1]:.1f}"
        )
    cli = env.status("client")
    rotations = cli["key_rotations"] - rot_before
    c.note(f"key rotations during load: {rotations} (session {sid_before} -> {cli['session']['id']})")
    assert not all_errors, f"{len(all_errors)} errors, e.g. {all_errors[:3]}"
    assert rotations >= 2, f"expected >= 2 key rotations in 75s with rekey={REKEY_SECS}s, got {rotations}"
    growth = [mem[-1][i] - mem[1][i] for i in range(2)]
    c.note(f"memory growth round 2 -> 3: server {growth[0]:+.1f} MiB, client {growth[1]:+.1f} MiB")
    assert all(g < 25 for g in growth), f"memory keeps growing: {mem}"


@test
def server_restart_is_transparent(c):
    env = c.env
    env.stop("server")
    env.start_server()
    r = c.s.get(c.url("/echo?after=restart"), headers=c.target)
    assert r.status_code == 200, r.text
    r = c.s.post(c.url("/echo/after-restart"), data=b"small body", headers=c.target)
    assert r.status_code == 200 and r.json()["body_len"] == 10
    status = env.status("server")
    assert status["handshakes"]["ok"] >= 1 and status["rejected"]["unknown_session"] >= 1, status


@test
def gauges_return_to_zero_when_idle(c):
    deadline = time.time() + 40
    while time.time() < deadline:
        srv, cli = c.env.status("server"), c.env.status("client")
        if (srv["requests"]["active"], cli["requests"]["active"], srv["connections"]["active"], cli["connections"]["active"]) == (0, 0, 0, 0):
            c.note(f"server totals: {srv['connections']['total']} connections, {srv['requests']['total']} requests, "
                   f"rx {srv['traffic']['received']}, tx {srv['traffic']['sent']}")
            return
        time.sleep(1)
    raise AssertionError(f"gauges did not drop: server {srv['connections']} {srv['requests']}, client {cli['connections']} {cli['requests']}")


@test
def tls_between_client_and_server(c):
    d = c.env.dir
    tls_port, tls_status, cli_port, cli_status = free_port(), free_port(), free_port(), free_port()
    scfg, ccfg = d / "server-tls.toml", d / "client-tls.toml"
    scfg.write_text(c.env.server_cfg.read_text())
    Env.patch(scfg, listen=f'"127.0.0.1:{tls_port}"', status_listen=f'"127.0.0.1:{tls_status}"',
              tls_cert=f"'{d / 'cert.pem'}'", tls_key=f"'{d / 'key.pem'}'")
    c.env.cli("init", "--mode", "client", "--out", str(ccfg), "--listen", f"127.0.0.1:{cli_port}",
              "--server-url", f"https://localhost:{tls_port}{TUNNEL_PATH}", "--key-file", str(d / "client.key"),
              "--default-target", c.up)
    Env.patch(ccfg, status_listen=f'"127.0.0.1:{cli_status}"', ca_file=f"'{d / 'ca.pem'}'")
    c.env.spawn("server-tls", [str(BIN), "run", "--config", str(scfg)], tls_port)
    c.env.spawn("client-tls", [str(BIN), "run", "--config", str(ccfg)], cli_port)
    try:
        base = f"http://127.0.0.1:{cli_port}"
        size = 20 * 2**20
        r = c.s.get(f"{base}/blob?size={size}&seed=2")
        assert r.status_code == 200 and hashlib.sha256(r.content).hexdigest() == blob_sha(size, 2)

        def one(i):
            s = Ctx.session()
            return s.get(f"{base}/echo?i={i}", timeout=30).json()["query"]["i"] == str(i)

        with ThreadPoolExecutor(64) as ex:
            assert all(ex.map(one, range(500)))
        # The server also speaks HTTP/2 (ALPN) to CDNs that use it towards the origin.
        with httpx.Client(http2=True, verify=str(d / "ca.pem"), trust_env=False) as h:
            r = h.get(f"https://localhost:{tls_port}/")
            assert r.http_version == "HTTP/2" and r.status_code == 404, (r.http_version, r.status_code)
        st = requests.get(f"http://127.0.0.1:{tls_status}/status.json").json()
        c.note(f"TLS: 501 requests over {st['connections']['total']} TCP connection(s); server also accepted HTTP/2")
    finally:
        c.env.stop("client-tls")
        c.env.stop("server-tls")


@test
def graceful_shutdown_finishes_in_flight_requests(c):
    port, status_port = free_port(), free_port()
    cfg = c.env.client_config("drain-client", port, status_port, c.env.ports["cdn"], c.env.key)
    proc = c.env.spawn("drain-client", [str(BIN), "run", "--config", str(cfg)], port, new_group=True)
    result = {}

    def slow_request():
        result["response"] = Ctx.session().get(f"http://127.0.0.1:{port}/sleep?secs=3", headers=c.target, timeout=30)

    worker = threading.Thread(target=slow_request)
    worker.start()
    time.sleep(1)
    proc.send_signal(signal.CTRL_BREAK_EVENT if os.name == "nt" else signal.SIGTERM)
    worker.join(30)
    r = result.get("response")
    assert r is not None and r.status_code == 200 and r.text == "slept", r
    assert proc.wait(15) == 0, "the process did not exit cleanly after draining"
    c.env.procs.pop("drain-client", None)



if __name__ == "__main__":
    importlib.import_module("e2e_apps")  # registers the application-level tests
    main()
