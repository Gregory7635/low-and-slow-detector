"""Нагрузочный тест REST API: параллельные запросы POST /api/analyze.

Запуск (API должен быть запущен):
    uvicorn api.main:app --port 8000
    python scripts/load_test.py data/demo/demo_access.log --requests 40 --concurrency 1 2 4 8
"""

import argparse
import statistics
import time
from concurrent.futures import ThreadPoolExecutor

import httpx


def one_request(client, url, payload, filename):
    t0 = time.perf_counter()
    r = client.post(url, params={"dns_offline": True},
                    files={"file": (filename, payload, "text/plain")})
    return time.perf_counter() - t0, r.status_code


def run(base, payload, filename, n, concurrency):
    url = base.rstrip("/") + "/api/analyze"
    with httpx.Client(timeout=300) as client:
        one_request(client, url, payload, filename)       # прогрев (загрузка моделей)
        t0 = time.perf_counter()
        with ThreadPoolExecutor(max_workers=concurrency) as pool:
            res = list(pool.map(lambda _: one_request(client, url, payload, filename), range(n)))
        total = time.perf_counter() - t0
    times = sorted(t for t, _ in res)
    ok = sum(code == 200 for _, code in res)
    return {"concurrency": concurrency, "requests": n, "ok": ok,
            "rps": round(n / total, 2),
            "p50_s": round(statistics.median(times), 3),
            "p95_s": round(times[max(0, int(0.95 * len(times)) - 1)], 3),
            "max_s": round(times[-1], 3)}


def main():
    p = argparse.ArgumentParser(description="Нагрузочный тест POST /api/analyze")
    p.add_argument("logfile")
    p.add_argument("--url", default="http://127.0.0.1:8000")
    p.add_argument("--requests", type=int, default=40)
    p.add_argument("--concurrency", type=int, nargs="+", default=[1, 2, 4, 8])
    args = p.parse_args()

    with open(args.logfile, "rb") as f:
        payload = f.read()
    lines = payload.count(b"\n")
    print(f"Файл: {args.logfile}, {lines} строк, {len(payload) / 1e6:.1f} МБ")
    print(f"{'потоков':>8} {'запросов':>9} {'успешно':>8} {'запр/с':>7} "
          f"{'p50, с':>7} {'p95, с':>7} {'max, с':>7}")
    for c in args.concurrency:
        r = run(args.url, payload, args.logfile, args.requests, c)
        print(f"{r['concurrency']:>8} {r['requests']:>9} {r['ok']:>8} {r['rps']:>7} "
              f"{r['p50_s']:>7} {r['p95_s']:>7} {r['max_s']:>7}")


if __name__ == "__main__":
    main()
