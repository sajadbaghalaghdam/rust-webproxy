"""An actively malicious CDN for security tests (HTTP-aware via h11; small messages only).

`arm(mode)` applies to the next tunnel DATA request:
  "forward_then_401"  forward it to the server (so it executes) but answer the client with a
                      bare 401, pretending the session is unknown;
  "hold"              keep it without forwarding and answer 401 (it can be delivered later);
  "rate_limit"        answer 429 with Retry-After, like a CDN rate-limiting rule;
  "bad_gateway"       answer 502 without forwarding it;
  "truncate"          forward it without its last bytes.
Everything else is relayed unchanged.
"""

import asyncio
import http.client
import threading

import h11

STRIP = {b"content-length", b"transfer-encoding", b"connection", b"keep-alive"}
DATA_PREFIX = b"\x02\x02"  # protocol version 2, DATA message


class EvilCDN:
    def __init__(self, listen_port, server_port):
        self.listen_port = listen_port
        self.server_port = server_port
        self.mode = None
        self.held = []
        self._loop = asyncio.new_event_loop()
        self._ready = threading.Event()

    def start(self):
        threading.Thread(target=self._run, daemon=True).start()
        if not self._ready.wait(10):
            raise RuntimeError("evil CDN did not start")

    def arm(self, mode):
        self.mode = mode

    def deliver_held(self):
        """Sends the oldest held request straight to the server; returns the HTTP status."""
        request, body = self.held.pop(0)
        conn = http.client.HTTPConnection("127.0.0.1", self.server_port, timeout=10)
        headers = {k.decode(): v.decode() for k, v in request.headers if k not in STRIP}
        conn.request(request.method.decode(), request.target.decode(), body=body, headers=headers)
        status = conn.getresponse().status
        conn.close()
        return status

    def _run(self):
        asyncio.set_event_loop(self._loop)
        # Peers closing abruptly are expected here (Windows reports them from the proactor).
        self._loop.set_exception_handler(
            lambda loop, ctx: None if isinstance(ctx.get("exception"), ConnectionError) else loop.default_exception_handler(ctx))
        server =self._loop.run_until_complete(asyncio.start_server(self._handle, "127.0.0.1", self.listen_port))
        self._ready.set()
        self._loop.run_until_complete(server.serve_forever())

    @staticmethod
    async def _read_message(conn, reader, head_type):
        head, body = None, bytearray()
        while True:
            event = conn.next_event()
            if event is h11.NEED_DATA:
                data = await reader.read(65536)
                conn.receive_data(data)
                if not data and head is None:
                    return None
            elif isinstance(event, head_type):
                head = event
            elif isinstance(event, h11.Data):
                body += event.data
            elif isinstance(event, h11.EndOfMessage):
                return head, bytes(body)
            elif isinstance(event, h11.ConnectionClosed):
                return None

    async def _forward(self, request, body):
        reader, writer = await asyncio.open_connection("127.0.0.1", self.server_port)
        conn = h11.Connection(h11.CLIENT)
        headers = [(k, v) for k, v in request.headers if k not in STRIP] + [(b"content-length", str(len(body)).encode())]
        writer.write(conn.send(h11.Request(method=request.method, target=request.target, headers=headers)))
        writer.write(conn.send(h11.Data(data=body)) + conn.send(h11.EndOfMessage()))
        await writer.drain()
        response, rbody = await self._read_message(conn, reader, h11.Response)
        writer.close()
        return response.status_code, [(k, v) for k, v in response.headers if k not in STRIP], rbody

    async def _handle(self, reader, writer):
        conn = h11.Connection(h11.SERVER)
        try:
            while True:
                message = await self._read_message(conn, reader, h11.Request)
                if message is None:
                    break
                request, body = message
                mode = None
                if request.method == b"POST" and body[:2] == DATA_PREFIX:
                    mode, self.mode = self.mode, None
                if mode == "hold":
                    self.held.append((request, body))
                    status, headers, rbody = 401, [], b""
                elif mode == "rate_limit":
                    status, headers, rbody = 429, [(b"retry-after", b"7")], b"slow down"
                elif mode == "bad_gateway":
                    status, headers, rbody = 502, [], b"bad gateway"
                else:
                    if mode == "truncate":
                        body = body[:-5]
                    status, headers, rbody = await self._forward(request, body)
                    if mode == "forward_then_401":
                        status, headers, rbody = 401, [], b""
                headers = headers + [(b"content-length", str(len(rbody)).encode())]
                writer.write(conn.send(h11.Response(status_code=status, headers=headers)))
                writer.write(conn.send(h11.Data(data=rbody)) + conn.send(h11.EndOfMessage()))
                await writer.drain()
                if conn.our_state is h11.MUST_CLOSE:
                    break
                conn.start_next_cycle()
        except (ConnectionError, h11.ProtocolError, OSError):
            pass
        finally:
            writer.close()
