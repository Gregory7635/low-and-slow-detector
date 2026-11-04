"""Поведенческие признаки IP-адресов для ML-моделей.

Признаки описывают не содержимое User-Agent (это делают правила), а то,
как IP ведёт себя во времени и что запрашивает. Благодаря этому модель
может находить ботов, которые правильно подделали UA.
"""

import math
import re
from collections import Counter
from urllib.parse import urlsplit

import numpy as np
import pandas as pd

from .rules import subnet_of, visit_starts
from .useragent import analyze_ua

STATIC_EXT_RE = re.compile(
    r"\.(?:jpe?g|png|gif|webp|avif|svg|ico|css|js|mjs|map|woff2?|ttf|eot|otf|mp4|webm)$", re.I)
STATIC_PREFIXES = ("/productImage", "/images", "/catImage", "/icon", "/sliderImage",
                   "/fonts", "/menu-icons", "/css_cache", "/bs/", "/vue/", "/static",
                   "/assets")
BURST_GAP = 1.0

FEATURE_NAMES = [
    "log_requests",          # число запросов
    "log_visits",            # число визитов (пачки запросов склеены)
    "log_duration",          # длительность активности, с
    "log_req_per_visit",     # запросов в одном визите
    "log_median_interval",   # медианный интервал между визитами
    "interval_cv",           # коэффициент вариации интервалов
    "interval_entropy",      # энтропия интервалов (логарифмические корзины)
    "max_gap_share",         # самый длинный перерыв / вся длительность
    "static_share",          # доля статики
    "error_share",           # доля ответов 4xx
    "server_error_share",    # доля ответов 5xx
    "redirect_share",        # доля ответов 3xx
    "post_share",            # доля POST
    "empty_referer_share",   # доля запросов без Referer
    "external_referer_share",  # доля Referer с чужих сайтов
    "unique_path_ratio",     # уникальных путей / запросов
    "query_share",           # доля запросов с параметрами
    "log_mean_size",         # средний размер ответа
    "log_user_agents",       # число разных User-Agent
    "n_browser_os",          # число разных пар (браузер, ОС)
    "log_subnet_ips",        # сколько IP этой /24 (/64) встречается в журнале
]


def is_static(path):
    p = path.split("?", 1)[0]
    return p.startswith(STATIC_PREFIXES) or bool(STATIC_EXT_RE.search(p))


def site_host(log):
    """Самый частый хост в Referer - считаем его своим сайтом."""
    hosts = Counter()
    for records in log.by_ip.values():
        for r in records[:20]:
            if r.referer not in ("", "-"):
                hosts[urlsplit(r.referer).netloc.lower()] += 1
    return hosts.most_common(1)[0][0] if hosts else ""


def interval_stats(times):
    """Медиана, CV, энтропия интервалов и доля самого длинного перерыва."""
    starts = visit_starts(times, BURST_GAP)
    duration = times[-1] - times[0]
    if len(starts) < 3:
        return len(starts), 0.0, 1.0, 0.0, 1.0
    iv = np.diff(starts)
    med = float(np.median(iv))
    cv = float(iv.std() / iv.mean()) if iv.mean() > 0 else 0.0
    bins = np.floor(np.log2(np.maximum(iv, 1.0))).astype(int)
    p = np.bincount(bins - bins.min()) / len(bins)
    p = p[p > 0]
    entropy = float(-(p * np.log2(p)).sum())
    max_gap = float(iv.max() / duration) if duration > 0 else 1.0
    return len(starts), med, min(cv, 5.0), entropy, max_gap


def ip_features(records, host, subnet_count):
    n = len(records)
    times = [r.ts for r in records]
    n_visits, med, cv, entropy, max_gap = interval_stats(times)
    paths = [r.path for r in records]
    statuses = [r.status for r in records]
    refs = [r.referer for r in records]
    uas = {r.ua for r in records}
    pairs = set()
    for ua in uas:
        u = analyze_ua(ua)
        if u.browser and u.os:
            pairs.add((u.browser, u.os))
    empty_ref = sum(x in ("", "-") for x in refs)
    external = sum(1 for x in refs if x not in ("", "-")
                   and urlsplit(x).netloc.lower() != host)
    return [
        math.log1p(n),
        math.log1p(n_visits),
        math.log1p(times[-1] - times[0]),
        math.log1p(n / max(n_visits, 1)),
        math.log1p(med),
        cv,
        entropy,
        max_gap,
        sum(map(is_static, paths)) / n,
        sum(400 <= s < 500 for s in statuses) / n,
        sum(s >= 500 for s in statuses) / n,
        sum(300 <= s < 400 for s in statuses) / n,
        sum(r.method == "POST" for r in records) / n,
        empty_ref / n,
        external / n,
        len(set(paths)) / n,
        sum("?" in p for p in paths) / n,
        math.log1p(sum(r.size for r in records) / n),
        math.log1p(len(uas)),
        float(len(pairs)),
        math.log1p(subnet_count),
    ]


def extract_features(log, min_requests=5):
    """ParsedLog -> DataFrame (индекс - IP, колонки - FEATURE_NAMES).

    IP с числом запросов меньше min_requests пропускаются: по нескольким
    запросам поведение не оценить, такие IP проверяют только правила.
    """
    host = site_host(log)
    subnets = Counter(subnet_of(ip) for ip in log.by_ip)
    rows, index = [], []
    for ip, records in log.by_ip.items():
        if len(records) < min_requests:
            continue
        rows.append(ip_features(records, host, subnets[subnet_of(ip)]))
        index.append(ip)
    return pd.DataFrame(rows, index=pd.Index(index, name="ip"), columns=FEATURE_NAMES)
