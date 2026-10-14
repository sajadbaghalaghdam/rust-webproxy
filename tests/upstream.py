"""Destination service used by the end-to-end tests.

Endpoints (all methods):
  /echo...            JSON description of the request (method, path, query, headers, body hash)
  /raw                echoes the request body back verbatim
  /blob?size=&seed=   deterministic pseudo-random bytes, Content-Length framed
  /chunked?size=&seed= same bytes, Transfer-Encoding: chunked (no length)
  /slow?chunks=&delay= chunked response flushed piece by piece
  /status/<code>      responds with that status
  /cookies            two Set-Cookie headers
  /mark?id=           counts requests per id;  /marks?id= returns the count
  /sleep?secs=        answers after a delay
  /redirect-abs       302 to an absolute URL built from the Host header
  <prefix>/redirect-rel 302 to the origin-relative path <prefix>/echo?from=rel
  /arrival            when the request body's first bytes and its end arrived (seconds after the head)
  /form               parses url-encoded / multipart / JSON bodies and reports every field and file
  /v1/...             minimal OpenAI-compatible API like vLLM's (models, chat completions with SSE
                      streaming, embeddings); requires `Authorization: Bearer test-key`
"""

import argparse
import hashlib
import json
import random
import re
import ssl
import threading
import time
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

BLOB_CHUNK = 64 * 1024
API_KEY = "test-key"
MARKS = Counter()
MARKS_LOCK = threading.Lock()


def blob_chunks(size, seed):
    rng = random.Random(seed)
    left = size
    while left > 0:
        n = min(BLOB_CHUNK, left)
        yield rng.randbytes(n)
        left -= n


def parse_multipart(body, content_type):
    """Minimal multipart/form-data parser (HTML5 / urllib3 header encoding)."""
    boundary = re.search(r'boundary="?([^";]+)"?', content_type).group(1).encode()
    fields, files = {}, {}
    for part in body.split(b"--" + boundary)[1:]:
        if part.startswith(b"--"):
            break
        head, _, data = part[2:].partition(b"\r\n\r\n")
        data = data[:-2]  # CRLF before the next boundary
        headers = dict(
            (k.strip().lower(), v.strip())
            for k, _, v in (line.partition(":") for line in head.decode("utf-8").split("\r\n"))
        )
        disposition = headers.get("content-disposition", "")
        name = re.search(r'\bname="([^"]*)"', disposition).group(1)
        filename = re.search(r'\bfilename="([^"]*)"', disposition)
        if filename:
            files.setdefault(name, []).append({
                "filename": filename.group(1),
                "content_type": headers.get("content-type", ""),
                "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            })
        else:
            fields.setdefault(name, []).append(data.decode("utf-8"))
    return fields, files


def chat_reply(messages):
    last = next((m["content"] for m in reversed(messages) if m.get("role") == "user"), "")
    return f"echo: {last}"


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    # --- request body -------------------------------------------------
    def iter_body(self):
        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            while True:
                line = self.rfile.readline()
                size = int(line.split(b";")[0].strip(), 16)
                if size == 0:
                    while self.rfile.readline() not in (b"\r\n", b"\n", b""):
                        pass
                    return
                left = size
                while left:
                    data = self.rfile.read(min(left, 1 << 20))
                    if not data:
                        raise ConnectionError("truncated chunk")
                    left -= len(data)
                    yield data
                self.rfile.readline()
        else:
            left = int(self.headers.get("Content-Length") or 0)
            while left:
                data = self.rfile.read(min(left, 1 << 20))
                if not data:
                    raise ConnectionError("truncated body")
                left -= len(data)
                yield data

    # --- response helpers --------------------------------------------
    def send_bytes(self, status, body, ctype="application/octet-stream", extra=()):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in extra:
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def send_json(self, obj, status=200):
        self.send_bytes(status, json.dumps(obj).encode(), "application/json")

    def send_chunked(self, chunks, delay=0.0):
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        for c in chunks:
            self.wfile.write(b"%x\r\n%s\r\n" % (len(c), c))
            self.wfile.flush()
            if delay:
                time.sleep(delay)
        self.wfile.write(b"0\r\n\r\n")

    # --- dispatch -----------------------------------------------------
    def handle_any(self):
        url = urlsplit(self.path)
        q = {k: v[-1] for k, v in parse_qs(url.query, keep_blank_values=True).items()}
        path = url.path

        if path.startswith("/raw"):
            body = b"".join(self.iter_body())
            return self.send_bytes(200, body)
        if path.startswith("/form"):
            return self.handle_form(b"".join(self.iter_body()))
        if path.startswith("/v1/"):
            return self.handle_openai(path, b"".join(self.iter_body()))
        if path.startswith("/arrival"):
            started, first, length = time.monotonic(), None, 0
            for chunk in self.iter_body():
                first = time.monotonic() if first is None else first
                length += len(chunk)
            done = time.monotonic()
            return self.send_json({"body_len": length, "first_after": (first or done) - started, "total_after": done - started})

        sha = hashlib.sha256()
        length = 0
        for chunk in self.iter_body():
            sha.update(chunk)
            length += len(chunk)

        if path.startswith("/blob"):
            size, seed = int(q.get("size", 0)), int(q.get("seed", 1))
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(size))
            self.end_headers()
            if self.command != "HEAD":
                for c in blob_chunks(size, seed):
                    self.wfile.write(c)
            return
        if path.startswith("/chunked"):
            return self.send_chunked(blob_chunks(int(q.get("size", 0)), int(q.get("seed", 1))))
        if path.startswith("/slow"):
            n, delay = int(q.get("chunks", 5)), float(q.get("delay", 0.3))
            return self.send_chunked((b"tick %d\n" % i for i in range(n)), delay)
        if path.startswith("/status/"):
            code = int(path.rsplit("/", 1)[1])
            if code in (204, 304):
                self.send_response(code)
                self.end_headers()
                return
            extra = [("Location", "/elsewhere")] if 300 <= code < 400 else []
            return self.send_bytes(code, b"status %d" % code, "text/plain", extra)
        if path.startswith("/sleep"):
            time.sleep(float(q.get("secs", 1)))
            return self.send_bytes(200, b"slept", "text/plain")
        if path.startswith("/redirect-abs"):
            location = f"http://{self.headers.get('Host')}/echo?from=redirect"
            return self.send_bytes(302, b"moved", "text/plain", [("Location", location)])
        if "/redirect-rel" in path:
            location = f"{path[:path.index('/redirect-rel')]}/echo?from=rel"
            return self.send_bytes(302, b"moved", "text/plain", [("Location", location)])
        if path.startswith("/fake-marker"):
            # A destination trying to pass itself off as webproxy.
            return self.send_bytes(503, b"busy", "text/plain", [("x-webproxy-error", "stale")])
        if path.startswith("/cookies"):
            return self.send_bytes(200, b"ok", "text/plain", [("Set-Cookie", "a=1; Path=/"), ("Set-Cookie", "b=2; Path=/")])
        if path.startswith("/marks"):
            with MARKS_LOCK:
                return self.send_json({"count": MARKS[q.get("id", "")]})
        if path.startswith("/mark"):
            with MARKS_LOCK:
                MARKS[q.get("id", "")] += 1
            return self.send_json({"ok": True})

        info = {
            "method": self.command,
            "path": path,
            "query": q,
            "raw_query": url.query,
            "headers": [[k, v] for k, v in self.headers.items()],
            "body_len": length,
            "body_sha256": sha.hexdigest(),
            "chunked": self.headers.get("Transfer-Encoding", "").lower() == "chunked",
            "secret_echo": q.get("echo", ""),
        }
        self.send_json(info)

    def handle_form(self, body):
        ctype = self.headers.get("Content-Type", "")
        out = {"content_type": ctype.split(";")[0], "fields": {}, "files": {}, "json": None}
        if ctype.startswith("multipart/form-data"):
            out["fields"], out["files"] = parse_multipart(body, ctype)
        elif ctype.startswith("application/x-www-form-urlencoded"):
            out["fields"] = parse_qs(body.decode("utf-8"), keep_blank_values=True)
        elif ctype.startswith("application/json"):
            out["json"] = json.loads(body)
        self.send_json(out)

    def handle_openai(self, path, body):
        if self.headers.get("Authorization") != f"Bearer {API_KEY}":
            return self.send_json({"error": {"message": "invalid api key"}}, 401)
        if path == "/v1/models":
            return self.send_json({"object": "list", "data": [{"id": "mock-llm", "object": "model"}]})
        req = json.loads(body or b"{}")
        if path == "/v1/embeddings":
            inputs = req["input"] if isinstance(req["input"], list) else [req["input"]]
            data = [{"object": "embedding", "index": i, "embedding": [len(t) / 10, 0.5, -0.25]} for i, t in enumerate(inputs)]
            return self.send_json({"object": "list", "data": data, "model": req.get("model")})
        if path != "/v1/chat/completions":
            return self.send_json({"error": {"message": f"unknown path {path}"}}, 404)
        reply = chat_reply(req.get("messages", []))
        created = int(time.time())
        if not req.get("stream"):
            return self.send_json({
                "id": "chatcmpl-mock", "object": "chat.completion", "created": created, "model": req.get("model"),
                "choices": [{"index": 0, "message": {"role": "assistant", "content": reply}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 3, "completion_tokens": len(reply.split()), "total_tokens": 3 + len(reply.split())},
            })
        # Server-sent events, one token per event, like vLLM with "stream": true.
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()

        def event(payload):
            data = f"data: {payload}\n\n".encode()
            self.wfile.write(b"%x\r\n%s\r\n" % (len(data), data))
            self.wfile.flush()

        delay = float(req.get("token_delay", 0.05))
        for token in reply.split(" "):
            chunk = {"id": "chatcmpl-mock", "object": "chat.completion.chunk", "created": created, "model": req.get("model"),
                     "choices": [{"index": 0, "delta": {"content": token + " "}, "finish_reason": None}]}
            event(json.dumps(chunk, ensure_ascii=False))
            time.sleep(delay)
        event("[DONE]")
        self.wfile.write(b"0\r\n\r\n")

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = do_HEAD = handle_any


class Server(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 1024


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--tls-cert")
    ap.add_argument("--tls-key")
    args = ap.parse_args()
    srv = Server(("127.0.0.1", args.port), Handler)
    if args.tls_cert:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(args.tls_cert, args.tls_key)
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    print(f"upstream listening on {args.port}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
