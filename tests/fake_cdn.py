"""A TCP relay standing in for the CDN.

It forwards bytes between the webproxy client and server unchanged, while
  * scanning both directions for plaintext marker strings (it must never find any), and
  * optionally capturing client->server bytes so a test can replay a request.
"""

import asyncio
import itertools
import threading


class FakeCDN:
    def __init__(self, listen_port, server_port, markers):
        self.listen_port = listen_port
        self.server_port = server_port
        self.markers = [m.encode() for m in markers]
        self.overlap = max(len(m) for m in self.markers) - 1
        self.found = set()
        self.bytes_c2s = 0
        self.bytes_s2c = 0
        self.connections = 0
        self.capturing = False
        self.captures = {}
        self._ids = itertools.count()
        self._loop = asyncio.new_event_loop()
        self._ready = threading.Event()

    # --- control (called from test threads) ---------------------------
    def start(self):
        threading.Thread(target=self._run, daemon=True).start()
        if not self._ready.wait(10):
            raise RuntimeError("fake CDN did not start")

    def start_capture(self):
        self.captures = {}
        self.capturing = True

    def stop_capture(self):
        self.capturing = False
        return self.captures

    # --- relay --------------------------------------------------------
    def _run(self):
        asyncio.set_event_loop(self._loop)
        server = self._loop.run_until_complete(asyncio.start_server(self._handle, "127.0.0.1", self.listen_port))
        self._ready.set()
        self._loop.run_until_complete(server.serve_forever())

    async def _handle(self, reader, writer):
        conn_id = next(self._ids)
        self.connections += 1
        try:
            up_reader, up_writer = await asyncio.open_connection("127.0.0.1", self.server_port)
        except OSError:
            writer.close()
            return
        await asyncio.gather(
            self._pump(reader, up_writer, conn_id, True),
            self._pump(up_reader, writer, conn_id, False),
            return_exceptions=True,
        )

    async def _pump(self, reader, writer, conn_id, c2s):
        tail = b""
        try:
            while True:
                data = await reader.read(256 * 1024)
                if not data:
                    break
                window = tail + data
                for m in self.markers:
                    if m in window:
                        self.found.add(m.decode())
                tail = window[-self.overlap:] if self.overlap else b""
                if c2s:
                    self.bytes_c2s += len(data)
                    if self.capturing:
                        self.captures.setdefault(conn_id, bytearray()).extend(data)
                else:
                    self.bytes_s2c += len(data)
                writer.write(data)
                await writer.drain()
        except (ConnectionError, OSError):
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass


def parse_http_requests(buf):
    """Splits captured HTTP/1.1 bytes into (raw_bytes, request_line, headers, body)."""
    out, i = [], 0
    buf = bytes(buf)
    while True:
        end = buf.find(b"\r\n\r\n", i)
        if end < 0:
            return out
        lines = buf[i:end].decode("latin-1").split("\r\n")
        headers = {}
        for line in lines[1:]:
            k, _, v = line.partition(":")
            headers[k.strip().lower()] = v.strip()
        start = end + 4
        if "content-length" in headers:
            stop = start + int(headers["content-length"])
            body = buf[start:stop]
        elif headers.get("transfer-encoding", "").lower() == "chunked":
            body, pos = bytearray(), start
            while True:
                eol = buf.find(b"\r\n", pos)
                size = int(buf[pos:eol].split(b";")[0], 16)
                pos = eol + 2
                if size == 0:
                    stop = buf.find(b"\r\n", pos) + 2
                    break
                body += buf[pos:pos + size]
                pos += size + 2
            body = bytes(body)
        else:
            stop, body = start, b""
        if stop > len(buf):
            return out
        out.append((buf[i:stop], lines[0], headers, body))
        i = stop
