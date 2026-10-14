"""Benchmark of the tunnel itself (no Python in the data path).

oha --> webproxy client --> webproxy server --> bench_upstream (examples/bench_upstream.rs),
compared with oha --> bench_upstream directly. Requires `oha` in PATH and
`cargo build --release --example bench_upstream`.

Run:  uv run --with requests --with psutil --with cryptography --with h11 python tests/bench.py
"""

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import psutil

sys.path.insert(0, str(Path(__file__).resolve().parent))
from harness import BIN, TUNNEL_PATH, Env, free_port, make_certs  # noqa: E402


def oha(url, seconds, conns, headers=()):
    args = ["oha", "-z", f"{seconds}s", "-c", str(conns), "--no-tui", "--output-format", "json"]
    for h in headers:
        args += ["-H", h]
    out = subprocess.run(args + [url], capture_output=True, text=True, check=True).stdout
    j = json.loads(out)
    s = j["summary"]
    codes = j.get("statusCodeDistribution", {})
    lat = j.get("latencyPercentiles", {})
    return s["requestsPerSec"], lat.get("p50", 0) * 1000, lat.get("p99", 0) * 1000, codes


def mem(pid):
    mi = psutil.Process(pid).memory_info()
    return getattr(mi, "private", mi.rss) / 2**20


def main():
    upstream_bin = BIN.parent / "examples" / BIN.name.replace("webproxy", "bench_upstream")
    workdir = tempfile.mkdtemp(prefix="webproxy-bench-")
    env = Env(workdir)
    try:
        make_certs(env.dir)
        env.write_configs()
        p = env.ports
        Env.patch(env.client_cfg, server_url=f'"http://127.0.0.1:{p["server"]}{TUNNEL_PATH}"')
        env.start_server()
        env.spawn("client", [str(BIN), "run", "--config", str(env.client_cfg)], p["client"])
        small, large = free_port(), free_port()
        env.spawn("up-small", [str(upstream_bin), f"127.0.0.1:{small}", "1024"], small)
        env.spawn("up-large", [str(upstream_bin), f"127.0.0.1:{large}", str(1 << 20)], large)

        client = f"http://127.0.0.1:{p['client']}/"
        oha(client, 3, 32, [f"X-Tunnel-Target: http://127.0.0.1:{small}"])  # warm-up
        print(f"{'case':<34} {'conns':>5} {'req/s':>9} {'MiB/s':>8} {'p50 ms':>8} {'p99 ms':>8}  status codes")
        cases = [("1 KiB", small, 1024, (16, 64, 256)), ("1 MiB", large, 1 << 20, (4, 16))]
        for label, port, size, conn_list in cases:
            target = f"http://127.0.0.1:{port}"
            for conns in conn_list:
                for name, url, h in ((f"{label} direct", target + "/", ()),
                                     (f"{label} through tunnel", client, [f"X-Tunnel-Target: {target}"])):
                    rps, p50, p99, codes = oha(url, 10, conns, h)
                    print(f"{name:<34} {conns:>5} {rps:>9.0f} {rps * size / 2**20:>8.0f} {p50:>8.2f} {p99:>8.2f}  {codes}", flush=True)
        print(f"private memory after load: server {mem(env.procs['server'].pid):.1f} MiB, client {mem(env.procs['client'].pid):.1f} MiB")
    finally:
        env.stop_all()
        shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    main()
