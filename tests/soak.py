"""Memory soak test: repeated load rounds, then idle; prints memory per round.

Run:  uv run --with requests --with psutil --with cryptography --with h11 python tests/soak.py --rounds 8 --seconds 20
"""

import argparse
import shutil
import sys
import tempfile
import time
from pathlib import Path

import psutil

sys.path.insert(0, str(Path(__file__).resolve().parent))
from harness import Ctx, Env, load  # noqa: E402


def mem(pid):
    mi = psutil.Process(pid).memory_info()
    return getattr(mi, "private", mi.rss) / 2**20, mi.rss / 2**20


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rounds", type=int, default=8)
    ap.add_argument("--seconds", type=int, default=20)
    ap.add_argument("--workers", type=int, default=48)
    ap.add_argument("--idle", type=int, default=25)
    args = ap.parse_args()

    workdir = tempfile.mkdtemp(prefix="webproxy-soak-")
    env = Env(workdir)
    try:
        env.start()
        c = Ctx(env)
        pids = {n: env.procs[n].pid for n in ("server", "client")}
        print(f"{'round':>5} {'req/s':>7} {'errors':>6}   {'server priv/rss MiB':>20}   {'client priv/rss MiB':>20}")
        rows = []
        for r in range(1, args.rounds + 1):
            lat, errors = load(c, args.seconds, args.workers)
            s, cl = mem(pids["server"]), mem(pids["client"])
            rows.append((s[0], cl[0]))
            print(f"{r:>5} {len(lat) / args.seconds:>7.0f} {len(errors):>6}   {s[0]:>9.1f} / {s[1]:>8.1f}   {cl[0]:>9.1f} / {cl[1]:>8.1f}", flush=True)
        time.sleep(args.idle)
        s, cl = mem(pids["server"]), mem(pids["client"])
        print(f"{'idle':>5} {'':>7} {'':>6}   {s[0]:>9.1f} / {s[1]:>8.1f}   {cl[0]:>9.1f} / {cl[1]:>8.1f}")
        half = len(rows) // 2
        for i, name in enumerate(("server", "client")):
            print(f"{name}: growth over the second half {rows[-1][i] - rows[half][i]:+.1f} MiB, peak {max(x[i] for x in rows):.1f} MiB")
    finally:
        env.stop_all()
        shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    main()
