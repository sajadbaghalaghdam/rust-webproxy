"""Shared end-to-end test harness for webproxy: processes, configuration, test registry, runner.

Topology (everything on 127.0.0.1):

    python test client --> webproxy client --> fake CDN --> webproxy server --> python upstream

A second client ("phone" key) talks through an actively malicious CDN (evil_cdn.py).
"""

import argparse
import datetime
import hashlib
import os
import random
import re
import socket
import subprocess
import sys
import tempfile
import time
import traceback
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import psutil
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

sys.path.insert(0, str(Path(__file__).resolve().parent))
from evil_cdn import EvilCDN  # noqa: E402
from fake_cdn import FakeCDN  # noqa: E402
from upstream import blob_chunks  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
BIN = Path(os.environ.get("WEBPROXY_BIN") or ROOT / "target" / "release" / ("webproxy.exe" if os.name == "nt" else "webproxy"))
TUNNEL_PATH = "/api/v1/stream"
# First bytes of tunnel messages: protocol version 2, then HELLO (1) or DATA (2).
HELLO_PREFIX = b"\x02\x01"
DATA_PREFIX = b"\x02\x02"
REKEY_SECS = 20
MAX_REQUEST_AGE_SECS = 5
# Plaintext that must never be visible to the CDN.
MARKERS = ["SeCrEt-PATH-7731", "SeCrEt-QUERY-9182", "SeCrEt-HEADER-4410", "SeCrEt-BODY-5521", "SeCrEt-RESP-8823"]


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_port(port, timeout=15):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError(f"port {port} did not open")


def blob_sha(size, seed):
    h = hashlib.sha256()
    for c in blob_chunks(size, seed):
        h.update(c)
    return h.hexdigest()


def make_certs(directory):
    """A test CA plus a `localhost` leaf certificate: ca.pem, cert.pem (leaf + CA), key.pem."""
    now = datetime.datetime.now(datetime.timezone.utc)

    def cert(subject, issuer, public_key, signing_key, ca):
        b = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(public_key)
             .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
             .not_valid_after(now + datetime.timedelta(days=2))
             .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
        if not ca:
            b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        return b.sign(signing_key, hashes.SHA256())

    ca_key, leaf_key = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "webproxy test CA")])
    leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    ca = cert(ca_name, ca_name, ca_key.public_key(), ca_key, True)
    leaf = cert(leaf_name, ca_name, leaf_key.public_key(), ca_key, False)
    pem = serialization.Encoding.PEM
    (directory / "ca.pem").write_bytes(ca.public_bytes(pem))
    (directory / "cert.pem").write_bytes(leaf.public_bytes(pem) + ca.public_bytes(pem))
    (directory / "key.pem").write_bytes(
        leaf_key.private_bytes(pem, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))


def private_mb(pid):
    mi = psutil.Process(pid).memory_info()
    return getattr(mi, "private", mi.rss) / 2**20


class Env:
    """Owns the processes and their configuration."""

    def __init__(self, workdir):
        self.dir = Path(workdir)
        names = ["up", "up_tls", "server", "server_status", "cdn", "client", "client_status",
                 "evil_cdn", "evil_client", "evil_client_status"]
        self.ports = {k: free_port() for k in names}
        self.procs = {}
        self.cdn = FakeCDN(self.ports["cdn"], self.ports["server"], MARKERS)
        self.evil = EvilCDN(self.ports["evil_cdn"], self.ports["server"])

    # --- configuration through the real CLI ---------------------------
    def cli(self, *args):
        r = subprocess.run([str(BIN), *args], capture_output=True, text=True, timeout=30)
        if r.returncode != 0:
            raise RuntimeError(f"webproxy {' '.join(args)} failed: {r.stderr}")
        return r.stdout

    @staticmethod
    def patch(path, **values):
        text = path.read_text()
        for key, value in values.items():
            line = f"{key} = {value}"
            text, n = re.subn(rf"^#?\s*{key}\s*=.*$", lambda _: line, text, flags=re.M)
            assert n == 1, f"{key} not found in {path}"
        path.write_text(text)

    def write_configs(self):
        p = self.ports
        server_cfg = self.dir / "server.toml"
        out = self.cli("init", "--mode", "server", "--out", str(server_cfg), "--listen", f"127.0.0.1:{p['server']}", "--name", "laptop")
        self.key = re.search(r"^\s+(\S{40,})\s*$", out, re.M).group(1)
        self.patch(
            server_cfg,
            status_listen=f'"127.0.0.1:{p["server_status"]}"',
            rekey_interval_secs=REKEY_SECS,
            max_request_age_secs=MAX_REQUEST_AGE_SECS,
            early_response_secs=1,
            allowed_targets='["127.0.0.1:*", "localhost:*"]',
            upstream_ca_file=f"'{self.dir / 'ca.pem'}'",
            idle_timeout_secs=10,
        )
        added = self.cli("add-client", "--config", str(server_cfg), "--name", "phone")
        self.phone_key = re.search(r"pairing key: (\S+)", added).group(1)
        self.server_cfg = server_cfg
        self.client_cfg = self.client_config("client", p["client"], p["client_status"], p["cdn"], self.key)
        self.evil_client_cfg = self.client_config("evil-client", p["evil_client"], p["evil_client_status"], p["evil_cdn"], self.phone_key)

    def client_config(self, name, port, status_port, cdn_port, key):
        key_file = self.dir / f"{name}.key"
        key_file.write_text(key)
        cfg = self.dir / f"{name}.toml"
        self.cli(
            "init", "--mode", "client", "--out", str(cfg), "--listen", f"127.0.0.1:{port}",
            "--server-url", f"http://127.0.0.1:{cdn_port}{TUNNEL_PATH}", "--key-file", str(key_file),
            "--default-target", f"http://127.0.0.1:{self.ports['up']}",
        )
        self.patch(cfg, status_listen=f'"127.0.0.1:{status_port}"', idle_timeout_secs=10, pool_idle_secs=10)
        return cfg

    # --- processes ------------------------------------------------------
    def spawn(self, name, args, port, new_group=False):
        log = open(self.dir / f"{name}.log", "ab")
        env = dict(os.environ, WEBPROXY_LOG=os.environ.get("WEBPROXY_LOG", "info"))
        # A separate process group lets a test send Ctrl-Break to just this process (Windows).
        flags = subprocess.CREATE_NEW_PROCESS_GROUP if new_group and os.name == "nt" else 0
        self.procs[name] = subprocess.Popen(args, stdout=log, stderr=subprocess.STDOUT, env=env, creationflags=flags)
        wait_port(port)
        return self.procs[name]

    def start(self):
        make_certs(self.dir)
        self.write_configs()
        upstream = [sys.executable, str(ROOT / "tests" / "upstream.py")]
        self.spawn("upstream", upstream + ["--port", str(self.ports["up"])], self.ports["up"])
        self.spawn("upstream-tls", upstream + ["--port", str(self.ports["up_tls"]), "--tls-cert", str(self.dir / "cert.pem"),
                                               "--tls-key", str(self.dir / "key.pem")], self.ports["up_tls"])
        self.cdn.start()
        self.evil.start()
        self.start_server()
        self.spawn("client", [str(BIN), "run", "--config", str(self.client_cfg)], self.ports["client"])
        self.spawn("evil-client", [str(BIN), "run", "--config", str(self.evil_client_cfg)], self.ports["evil_client"])

    def start_server(self):
        self.spawn("server", [str(BIN), "run", "--config", str(self.server_cfg)], self.ports["server"])

    def stop(self, name):
        p = self.procs.pop(name, None)
        if p:
            p.kill()
            p.wait(10)

    def stop_all(self):
        for name in list(self.procs):
            self.stop(name)

    def status(self, which):
        port = self.ports[f"{which}_status"]
        return requests.get(f"http://127.0.0.1:{port}/status.json", timeout=5).json()

    def log_tail(self, name, lines=15):
        path = self.dir / f"{name}.log"
        return "\n".join(path.read_text(errors="replace").splitlines()[-lines:]) if path.exists() else ""


# ---------------------------------------------------------------------------
TESTS = []


def test(fn):
    TESTS.append(fn)
    return fn


class Ctx:
    def __init__(self, env):
        self.env = env
        self.base = f"http://127.0.0.1:{env.ports['client']}"
        self.up = f"http://127.0.0.1:{env.ports['up']}"
        self.target = {"X-Tunnel-Target": self.up}
        self.s = self.session()
        self.notes = []

    @staticmethod
    def session():
        s = requests.Session()
        s.trust_env = False
        return s

    def url(self, path):
        return self.base + path

    def note(self, msg):
        self.notes.append(msg)


def load(c, seconds, workers):
    """Mixed traffic from many threads; every response is verified."""
    deadline = time.time() + seconds
    blob = blob_sha(256 * 1024, 9)
    post_body = random.Random(1).randbytes(8 * 1024)
    post_sha = hashlib.sha256(post_body).hexdigest()

    def worker(wid):
        s = Ctx.session()
        lat, errors, i = [], [], 0
        while time.time() < deadline:
            i += 1
            op = (wid + i) % 10
            t = time.time()
            try:
                if op < 6:
                    r = s.get(c.url(f"/echo?w={wid}&i={i}"), headers=c.target, timeout=30)
                    ok = r.status_code == 200 and r.json()["query"]["i"] == str(i)
                elif op < 9:
                    r = s.post(c.url("/echo/p"), data=post_body, headers=c.target, timeout=30)
                    ok = r.status_code == 200 and r.json()["body_sha256"] == post_sha
                else:
                    r = s.get(c.url("/blob?size=262144&seed=9"), headers=c.target, timeout=30)
                    ok = r.status_code == 200 and hashlib.sha256(r.content).hexdigest() == blob
                if not ok:
                    errors.append(f"{r.status_code} {r.text[:200]}")
            except Exception as e:  # noqa: BLE001
                errors.append(repr(e))
            lat.append(time.time() - t)
        return lat, errors

    with ThreadPoolExecutor(workers) as ex:
        results = list(ex.map(worker, range(workers)))
    lat = [x for r in results for x in r[0]]
    errors = [x for r in results for x in r[1]]
    return lat, errors


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-k", "--filter", default="", help="run tests whose name contains this")
    ap.add_argument("--keep", action="store_true", help="keep the work directory")
    args = ap.parse_args()
    if not BIN.exists():
        sys.exit(f"{BIN} not found; run `cargo build --release` first")

    workdir = tempfile.mkdtemp(prefix="webproxy-e2e-")
    env = Env(workdir)
    results = []
    try:
        env.start()
        ctx = Ctx(env)
        for fn in TESTS:
            if args.filter not in fn.__name__:
                continue
            t = time.time()
            ctx.notes = []
            try:
                fn(ctx)
                ok, err = True, ""
            except Exception as e:  # noqa: BLE001
                ok, err = False, f"{type(e).__name__}: {e}\n{traceback.format_exc(limit=3)}"
            results.append((fn.__name__, ok, time.time() - t, err, list(ctx.notes)))
            mark = "PASS" if ok else "FAIL"
            print(f"[{mark}] {fn.__name__} ({time.time() - t:.1f}s)", flush=True)
            for n in ctx.notes:
                print(f"       {n}", flush=True)
            if not ok:
                print("       " + err.replace("\n", "\n       "), flush=True)
    finally:
        env.stop_all()
        failed = [r for r in results if not r[1]]
        if failed:
            for name in ["server", "client"]:
                print(f"--- {name}.log (tail) ---\n{env.log_tail(name)}")
        if not args.keep and not failed:
            import shutil
            shutil.rmtree(workdir, ignore_errors=True)
        else:
            print(f"work directory: {workdir}")
    passed = sum(1 for r in results if r[1])
    print(f"\n{passed}/{len(results)} tests passed")
    sys.exit(0 if results and not failed else 1)


