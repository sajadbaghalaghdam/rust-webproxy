"""Application-level end-to-end tests: form fields, image uploads and an OpenAI-compatible
(vLLM-style) API, driven with requests, aiohttp and the official openai SDK."""

import asyncio
import hashlib
import json
import random
import time

import aiohttp
import openai

from harness import BIN, Env, free_port, test
from upstream import API_KEY, chat_reply

MiB = 2**20
# Field set that exercises what form encoders get wrong: repeated names, empty values,
# non-ASCII names and values, reserved characters, newlines and a long value.
FORM_FIELDS = [
    ("name", "Zoë"),
    ("email", "alice@example.com"),
    ("tags", "a"),
    ("tags", "b"),
    ("tags", "três"),
    ("empty", ""),
    ("naïve-ñame", "ünïcödé text with spaces 日本語"),
    ("special", "a&b=c+d%e?f#g/h"),
    ("multiline", "line one\nline two\r\nline three"),
    ("long", "x" * 100_000),
]


def expected_fields(pairs):
    out = {}
    for k, v in pairs:
        out.setdefault(k, []).append(v)
    return out


def file_info(filename, content_type, data):
    return {"filename": filename, "content_type": content_type, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def image_bytes(size, seed):
    # A JPEG header followed by random data is enough for a proxy test.
    return b"\xff\xd8\xff\xe0" + random.Random(seed).randbytes(size - 4)


@test
def post_fields_arrive_exactly(c):
    url = c.url("/form")
    # application/x-www-form-urlencoded
    r = c.s.post(url, data=FORM_FIELDS, headers=c.target)
    j = r.json()
    assert j["content_type"] == "application/x-www-form-urlencoded" and j["fields"] == expected_fields(FORM_FIELDS), j
    # application/json (nested)
    doc = {"user": {"name": "Zoë", "roles": ["admin", "ops"]}, "n": 3.5, "ok": True, "none": None}
    r = c.s.post(url, json=doc, headers=c.target)
    assert r.json()["json"] == doc
    # multipart/form-data: all fields plus several files, one of them an 8 MiB image
    photo = image_bytes(8 * MiB, 1)
    thumb = image_bytes(40_000, 2)
    files = [
        ("photo", ("été.jpg", photo, "image/jpeg")),
        ("gallery", ("a.png", thumb, "image/png")),
        ("gallery", ("b.png", thumb[::-1], "image/png")),
        ("empty_file", ("empty.bin", b"", "application/octet-stream")),
    ]
    started = time.time()
    r = c.s.post(url, data=FORM_FIELDS, files=files, headers=c.target)
    elapsed = time.time() - started
    j = r.json()
    assert j["content_type"] == "multipart/form-data", j["content_type"]
    assert j["fields"] == expected_fields(FORM_FIELDS)
    assert j["files"] == {
        "photo": [file_info("été.jpg", "image/jpeg", photo)],
        "gallery": [file_info("a.png", "image/png", thumb), file_info("b.png", "image/png", thumb[::-1])],
        "empty_file": [file_info("empty.bin", "application/octet-stream", b"")],
    }, j["files"]
    c.note(f"multipart with an 8 MiB image + {len(FORM_FIELDS)} fields + 3 files: {elapsed:.2f}s")


@test
def aiohttp_image_uploads(c):
    images = [image_bytes(random.Random(i).randint(500_000, 8 * MiB), i) for i in range(12)]

    async def upload(session, i, data):
        form = aiohttp.FormData()
        form.add_field("caption", f"photo n°{i} é")
        form.add_field("image", data, filename=f"img-{i}.jpg", content_type="image/jpeg")
        async with session.post(c.url("/form"), data=form, headers=c.target) as resp:
            assert resp.status == 200, await resp.text()
            j = await resp.json()
            assert j["fields"] == {"caption": [f"photo n°{i} é"]}, j["fields"]
            assert j["files"]["image"] == [file_info(f"img-{i}.jpg", "image/jpeg", data)], j["files"]

    async def main():
        async with aiohttp.ClientSession() as session:
            await asyncio.gather(*(upload(session, i, d) for i, d in enumerate(images)))

    started = time.time()
    asyncio.run(main())
    total = sum(map(len, images)) / MiB
    c.note(f"aiohttp: {len(images)} concurrent image uploads ({total:.0f} MiB) in {time.time() - started:.2f}s")


@test
def vllm_style_api_with_requests(c):
    auth = {"Authorization": f"Bearer {API_KEY}"}
    headers = {**c.target, **auth}
    # Any path works: the request path is appended to the X-Tunnel-Target base URL.
    r = c.s.get(c.url("/v1/models"), headers=headers)
    assert r.status_code == 200 and r.json()["data"][0]["id"] == "mock-llm", r.text
    messages = [{"role": "system", "content": "be brief"}, {"role": "user", "content": "héllo wörld 日本 hello"}]
    r = c.s.post(c.url("/v1/chat/completions"), headers=headers, json={"model": "mock-llm", "messages": messages})
    assert r.json()["choices"][0]["message"]["content"] == chat_reply(messages)
    r = c.s.post(c.url("/v1/embeddings"), headers=headers, json={"model": "mock-llm", "input": ["a", "bb"]})
    assert [d["index"] for d in r.json()["data"]] == [0, 1]
    # The destination's own errors pass through untouched.
    r = c.s.get(c.url("/v1/models"), headers={**c.target, "Authorization": "Bearer wrong"})
    assert r.status_code == 401 and "x-webproxy-error" not in r.headers and r.json()["error"]["message"] == "invalid api key"
    # Streaming (SSE): tokens must arrive one by one, not all at the end.
    body = {"model": "mock-llm", "messages": messages, "stream": True, "token_delay": 0.3}
    started = time.time()
    arrivals, text = [], ""
    with c.s.post(c.url("/v1/chat/completions"), headers=headers, json=body, stream=True) as r:
        assert r.headers["Content-Type"].startswith("text/event-stream")
        for line in r.iter_lines():
            if not line.startswith(b"data: "):
                continue
            payload = line[6:]
            if payload == b"[DONE]":
                break
            text += json.loads(payload)["choices"][0]["delta"]["content"]
            arrivals.append(time.time() - started)
    assert text.strip() == chat_reply(messages)
    assert arrivals[0] < arrivals[-1] - 0.5, f"tokens were buffered: {arrivals}"
    c.note(f"SSE: first token after {arrivals[0]:.2f}s, last after {arrivals[-1]:.2f}s ({len(arrivals)} events)")
    # The same API through proxy mode and through default_target (no header).
    r = c.s.get(f"{c.up}/v1/models", headers=auth, proxies={"http": c.base})
    assert r.status_code == 200
    r = c.s.get(c.url("/v1/models"), headers=auth)
    assert r.status_code == 200


@test
def vllm_style_streaming_with_aiohttp(c):
    headers = {**c.target, "Authorization": f"Bearer {API_KEY}"}

    async def chat(session, i):
        messages = [{"role": "user", "content": f"question {i} " + " ".join(["word"] * 20)}]
        body = {"model": "mock-llm", "messages": messages, "stream": True, "token_delay": 0.01}
        text = ""
        async with session.post(c.url("/v1/chat/completions"), json=body, headers=headers) as resp:
            assert resp.status == 200
            async for raw in resp.content:
                line = raw.strip()
                if line.startswith(b"data: ") and line != b"data: [DONE]":
                    text += json.loads(line[6:])["choices"][0]["delta"]["content"]
        assert text.strip() == chat_reply(messages), text

    async def main():
        async with aiohttp.ClientSession() as session:
            await asyncio.gather(*(chat(session, i) for i in range(50)))

    started = time.time()
    asyncio.run(main())
    c.note(f"aiohttp: 50 concurrent streaming chat completions in {time.time() - started:.2f}s")


@test
def vllm_style_api_with_openai_sdk(c):
    client = openai.OpenAI(base_url=c.url("/v1"), api_key=API_KEY, default_headers=c.target, max_retries=0)
    assert [m.id for m in client.models.list()] == ["mock-llm"]
    messages = [{"role": "user", "content": "how are you"}]
    reply = client.chat.completions.create(model="mock-llm", messages=messages)
    assert reply.choices[0].message.content == chat_reply(messages)
    stream = client.chat.completions.create(model="mock-llm", messages=messages, stream=True)
    text = "".join(chunk.choices[0].delta.content or "" for chunk in stream)
    assert text.strip() == chat_reply(messages)

    async def async_calls():
        aclient = openai.AsyncOpenAI(base_url=c.url("/v1"), api_key=API_KEY, default_headers=c.target, max_retries=0)
        replies = await asyncio.gather(*(
            aclient.chat.completions.create(model="mock-llm", messages=[{"role": "user", "content": f"q{i}"}])
            for i in range(20)
        ))
        await aclient.close()
        return [r.choices[0].message.content for r in replies]

    assert asyncio.run(async_calls()) == [chat_reply([{"role": "user", "content": f"q{i}"}]) for i in range(20)]



@test
def upload_size_limits(c):
    """max_request_body_mb on the client (rejected before anything is sent) and on the server."""
    env = c.env
    form = [("user_id", "42"), ("mode", "resize")]

    def upload(base, size, chunked=False):
        image = image_bytes(size, size)
        if chunked:
            return c.s.post(f"{base}/form", data=(image[i:i + 65536] for i in range(0, len(image), 65536)), headers=c.target)
        return c.s.post(f"{base}/form", data=form, files={"image": ("big.jpg", image, "image/jpeg")}, headers=c.target)

    def check_rejected(r, who):
        assert r.status_code == 413 and r.headers.get("x-webproxy-error") == "1", (who, r.status_code, r.text)
        assert "8 MiB" in r.text, r.text

    # Client-side limit.
    port, status_port = free_port(), free_port()
    cfg = env.client_config("limited-client", port, status_port, env.ports["cdn"], env.key)
    Env.patch(cfg, max_request_body_mb=8)
    env.spawn("limited-client", [str(BIN), "run", "--config", str(cfg)], port)
    # Server-side limit: a second server, reached directly by an unlimited client.
    srv_port, srv_status, cli_port, cli_status = free_port(), free_port(), free_port(), free_port()
    scfg = env.dir / "limited-server.toml"
    scfg.write_text(env.server_cfg.read_text())
    Env.patch(scfg, listen=f'"127.0.0.1:{srv_port}"', status_listen=f'"127.0.0.1:{srv_status}"', max_request_body_mb=8)
    env.spawn("limited-server", [str(BIN), "run", "--config", str(scfg)], srv_port)
    ccfg = env.client_config("unlimited-client", cli_port, cli_status, srv_port, env.key)
    env.spawn("unlimited-client", [str(BIN), "run", "--config", str(ccfg)], cli_port)
    try:
        for who, base in (("client limit", f"http://127.0.0.1:{port}"), ("server limit", f"http://127.0.0.1:{cli_port}")):
            ok = upload(base, 8 * MiB - 4096)
            assert ok.status_code == 200 and ok.json()["files"]["image"][0]["size"] == 8 * MiB - 4096, (who, ok.text[:200])
            check_rejected(upload(base, 9 * MiB), who)
            check_rejected(upload(base, 9 * MiB, chunked=True), who)
            assert c.s.get(f"{base}/echo?after=limit", headers=c.target).status_code == 200
    finally:
        for name in ("limited-client", "limited-server", "unlimited-client"):
            env.stop(name)
