"""Calling services through the webproxy client with `requests`.

The webproxy client listens locally (default 127.0.0.1:8080). Each request names its
destination — an address as seen from the *server* machine — in one of three ways:

  * header  X-Tunnel-Target: http://host:port   the request's path and query are appended
  * header  X-Tunnel-Url: http://host:port/exact/path?query
  * proxy mode: requests' `proxies=` with the full destination URL

Run:  python examples/clients/requests_example.py --image photo.jpg
"""

import argparse
import json

import requests

CLIENT = "http://127.0.0.1:8080"          # webproxy client
IMAGE_SERVICE = "http://127.0.0.1:5000"   # image processing service, seen from the server
VLLM = "http://127.0.0.1:8000"            # vLLM OpenAI-compatible server, seen from the server
VLLM_KEY = "your-vllm-api-key"

session = requests.Session()
session.trust_env = False  # do not send these requests through a system-wide proxy


def upload_image(path: str) -> dict:
    """multipart/form-data: one image plus ordinary and repeated form fields."""
    with open(path, "rb") as image:
        r = session.post(
            f"{CLIENT}/api/v1/process",                       # any path; it is kept as is
            headers={"X-Tunnel-Target": IMAGE_SERVICE},
            files={"image": (path, image, "image/jpeg")},
            data={"user_id": "42", "mode": "resize", "tags": ["portrait", "hd"]},
            timeout=120,
        )
    r.raise_for_status()
    return r.json()


def send_form() -> dict:
    """application/x-www-form-urlencoded."""
    r = session.post(f"{CLIENT}/api/v1/login", headers={"X-Tunnel-Target": IMAGE_SERVICE},
                     data={"username": "alice", "password": "secret"}, timeout=30)
    r.raise_for_status()
    return r.json()


def send_json() -> dict:
    """application/json, with query parameters and custom headers."""
    r = session.post(
        f"{CLIENT}/api/v1/jobs",
        params={"priority": "high", "lang": "en"},
        headers={"X-Tunnel-Target": IMAGE_SERVICE, "X-Request-Id": "abc-123"},
        json={"image_id": 7, "operations": [{"op": "crop", "box": [0, 0, 512, 512]}]},
        timeout=30,
    )
    r.raise_for_status()
    return r.json()


def vllm_chat(prompt: str) -> str:
    """vLLM chat completion (non-streaming)."""
    r = session.post(
        f"{CLIENT}/v1/chat/completions",
        headers={"X-Tunnel-Target": VLLM, "Authorization": f"Bearer {VLLM_KEY}"},
        json={"model": "your-model", "messages": [{"role": "user", "content": prompt}], "max_tokens": 256},
        timeout=600,
    )
    r.raise_for_status()
    return r.json()["choices"][0]["message"]["content"]


def vllm_chat_stream(prompt: str):
    """vLLM chat completion with "stream": true — tokens arrive as server-sent events."""
    body = {"model": "your-model", "messages": [{"role": "user", "content": prompt}], "stream": True}
    headers = {"X-Tunnel-Target": VLLM, "Authorization": f"Bearer {VLLM_KEY}"}
    with session.post(f"{CLIENT}/v1/chat/completions", headers=headers, json=body, stream=True, timeout=600) as r:
        r.raise_for_status()
        for line in r.iter_lines():
            if line.startswith(b"data: ") and line != b"data: [DONE]":
                delta = json.loads(line[6:])["choices"][0]["delta"].get("content")
                if delta:
                    yield delta


def proxy_mode() -> int:
    """No special header: the client acts as a normal HTTP proxy."""
    r = session.get(f"{IMAGE_SERVICE}/health", proxies={"http": CLIENT}, timeout=10)
    return r.status_code


def openai_sdk(prompt: str) -> str:
    """The official openai SDK pointed at the webproxy client (pip install openai)."""
    from openai import OpenAI

    client = OpenAI(base_url=f"{CLIENT}/v1", api_key=VLLM_KEY, default_headers={"X-Tunnel-Target": VLLM})
    reply = client.chat.completions.create(model="your-model", messages=[{"role": "user", "content": prompt}])
    return reply.choices[0].message.content


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--image", help="image file to upload")
    args = ap.parse_args()
    if args.image:
        print("upload:", upload_image(args.image))
    print("vLLM:", vllm_chat("Hello! Please introduce yourself."))
    for token in vllm_chat_stream("Write one short sentence."):
        print(token, end="", flush=True)
    print()
