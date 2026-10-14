"""Calling services through the webproxy client with `aiohttp` (concurrent requests).

See requests_example.py for how the destination is chosen (X-Tunnel-Target / X-Tunnel-Url /
proxy mode). Destinations are addresses as seen from the *server* machine.

Run:  python examples/clients/aiohttp_example.py photo1.jpg photo2.jpg ...
"""

import asyncio
import json
import sys

import aiohttp

CLIENT = "http://127.0.0.1:8080"
IMAGE_SERVICE = "http://127.0.0.1:5000"
VLLM = "http://127.0.0.1:8000"
VLLM_KEY = "your-vllm-api-key"


async def upload_image(session: aiohttp.ClientSession, path: str) -> dict:
    form = aiohttp.FormData()
    form.add_field("user_id", "42")
    form.add_field("tags", "portrait")
    form.add_field("tags", "hd")                     # repeated field
    with open(path, "rb") as image:
        form.add_field("image", image, filename=path, content_type="image/jpeg")
        async with session.post(f"{CLIENT}/api/v1/process", data=form,
                                headers={"X-Tunnel-Target": IMAGE_SERVICE}) as resp:
            resp.raise_for_status()
            return await resp.json()


async def vllm_chat(session: aiohttp.ClientSession, prompt: str) -> str:
    body = {"model": "your-model", "messages": [{"role": "user", "content": prompt}], "max_tokens": 256}
    headers = {"X-Tunnel-Target": VLLM, "Authorization": f"Bearer {VLLM_KEY}"}
    async with session.post(f"{CLIENT}/v1/chat/completions", json=body, headers=headers) as resp:
        resp.raise_for_status()
        return (await resp.json())["choices"][0]["message"]["content"]


async def vllm_chat_stream(session: aiohttp.ClientSession, prompt: str) -> str:
    """Server-sent events: print tokens as they arrive."""
    body = {"model": "your-model", "messages": [{"role": "user", "content": prompt}], "stream": True}
    headers = {"X-Tunnel-Target": VLLM, "Authorization": f"Bearer {VLLM_KEY}"}
    text = []
    async with session.post(f"{CLIENT}/v1/chat/completions", json=body, headers=headers) as resp:
        resp.raise_for_status()
        async for raw in resp.content:            # one line at a time
            line = raw.strip()
            if line.startswith(b"data: ") and line != b"data: [DONE]":
                delta = json.loads(line[6:])["choices"][0]["delta"].get("content") or ""
                print(delta, end="", flush=True)
                text.append(delta)
    print()
    return "".join(text)


async def main(images: list[str]) -> None:
    timeout = aiohttp.ClientTimeout(total=600)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        results = await asyncio.gather(*(upload_image(session, p) for p in images))
        for path, result in zip(images, results):
            print(path, "->", result)
        answers = await asyncio.gather(*(vllm_chat(session, f"question {i}") for i in range(10)))
        print(answers)
        await vllm_chat_stream(session, "Write one short sentence.")


if __name__ == "__main__":
    asyncio.run(main(sys.argv[1:]))
