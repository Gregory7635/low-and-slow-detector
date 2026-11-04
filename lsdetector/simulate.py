"""Генератор синтетических low-and-slow ботов.

Настоящей разметки «бот / человек» в журнале нет, поэтому для оценки
качества в реальный журнал внедряются боты с известным поведением.
Пути страниц и User-Agent берутся из того же журнала, чтобы боты не
выделялись тем, чего у них не может быть.

IP ботов выделяются из диапазона 198.18.0.0/15 (RFC 2544, зарезервирован
для тестирования), поэтому они не пересекаются с реальными адресами.

Типы ботов:
  timer       - визиты по таймеру с небольшим разбросом, только HTML;
  random_slow - случайные (пуассоновские) интервалы, обход каталога без статики;
  distributed - группа IP одной /24, каждый делает несколько запросов;
  mimic       - подгружает часть статики и ставит Referer, как браузер.
"""

import ipaddress
import random
import time
from dataclasses import dataclass, field

from .features import is_static
from .parser import LogRecord, ParsedLog
from .useragent import analyze_ua

BOT_NETWORK = ipaddress.ip_network("198.18.0.0/15")
DEFAULT_MIX = {"timer": 100, "random_slow": 100, "distributed": 25, "mimic": 100}


@dataclass
class SimulationResult:
    log: ParsedLog
    bot_ips: dict = field(default_factory=dict)   # ip -> тип бота


class BotSimulator:
    def __init__(self, log, seed=42):
        self.rng = random.Random(seed)
        self.log = log
        self.start, self.end = log.time_range()
        self.tz = next(iter(log.by_ip.values()))[0].tz_offset
        self.page_size, self.static_size, self.uas, self.host = self._collect(log)
        self.pages, self.static = sorted(self.page_size), sorted(self.static_size)
        self._subnets = iter(BOT_NETWORK.subnets(new_prefix=24))

    @staticmethod
    def _collect(log):
        """Страницы (с реальным размером ответа), статика, популярные UA, хост."""
        pages, static, ua_ips = {}, {}, {}
        host = ""
        for ip, records in log.by_ip.items():
            for r in records:
                if r.method != "GET" or r.status != 200:
                    continue
                if is_static(r.path):
                    static[r.path] = r.size
                elif r.size > 15_000 and "?" not in r.path:   # HTML-страница
                    pages[r.path] = r.size
                u = analyze_ua(r.ua)
                if u.bot is None and u.browser and u.os and not u.rule3:
                    ua_ips.setdefault(r.ua, set()).add(ip)
                if not host and r.referer.startswith("http"):
                    host = r.referer.split("/")[2]
        # только UA, которые встречаются хотя бы у трёх IP - реальные браузеры
        uas = sorted(ua for ua, ips in ua_ips.items() if len(ips) >= 3)
        return pages, static, uas, host

    # --- вспомогательные функции -------------------------------------------

    def _new_subnet(self):
        return list(next(self._subnets).hosts())

    def _record(self, ip, ts, path, ua, referer="-", static=False):
        size = (self.static_size if static else self.page_size)[path]
        return LogRecord(ip, ts, self.tz, "GET", path, 200, size, referer, ua)

    def _page_visits(self, ip, times, ua, crawl=True, with_static=False, referer_mode="empty"):
        out = []
        pages = self.rng.sample(self.pages, min(len(times), len(self.pages))) if crawl \
            else [self.rng.choice(self.pages) for _ in times]
        prev = None
        for ts, path in zip(times, pages):
            ref = "-"
            if referer_mode == "site":
                ref = f"https://{self.host}{prev}" if prev else f"https://{self.host}/"
            out.append(self._record(ip, ts, path, ua, ref))
            if with_static and self.static:
                for k in range(self.rng.randint(1, 4)):
                    out.append(self._record(ip, ts + 0.1 + 0.2 * k, self.rng.choice(self.static),
                                            ua, f"https://{self.host}{path}", static=True))
            prev = path
        return out

    def _times_regular(self, period, cv):
        t = self.start + self.rng.uniform(0, period)
        times = []
        while t < self.end:
            times.append(t)
            t += max(2.0, self.rng.gauss(period, period * cv))
        return times

    def _times_poisson(self, mean_gap, start=None, end=None):
        t = (start or self.start) + self.rng.expovariate(1 / mean_gap)
        end = end or self.end
        times = []
        while t < end:
            times.append(t)
            t += max(2.0, self.rng.expovariate(1 / mean_gap))
        return times

    # --- типы ботов --------------------------------------------------------

    def timer(self, ip):
        times = self._times_regular(self.rng.uniform(30, 400), self.rng.uniform(0.02, 0.25))
        return self._page_visits(ip, times, self.rng.choice(self.uas))

    def random_slow(self, ip):
        times = self._times_poisson(self.rng.uniform(60, 600))
        return self._page_visits(ip, times, self.rng.choice(self.uas))

    def mimic(self, ip):
        times = self._times_poisson(self.rng.uniform(90, 600))
        return self._page_visits(ip, times, self.rng.choice(self.uas), crawl=True,
                                 with_static=True, referer_mode="site")

    def distributed_group(self):
        """-> {ip: records} для группы из 6-12 IP одной подсети."""
        hosts = self._new_subnet()
        group = {}
        window = self.rng.uniform(600, 3600)
        g_start = self.rng.uniform(self.start, max(self.start, self.end - window))
        for host in self.rng.sample(hosts, self.rng.randint(6, 12)):
            ip = str(host)
            times = []
            while len(times) < 5:
                times = sorted(self.rng.uniform(g_start, g_start + window)
                               for _ in range(self.rng.randint(5, 15)))
            group[ip] = self._page_visits(ip, times, self.rng.choice(self.uas))
        return group

    # -----------------------------------------------------------------------

    def generate(self, mix=None):
        """Вернуть {ip: (тип, записи)} синтетических ботов."""
        mix = mix or DEFAULT_MIX
        bots = {}
        single = []
        for kind in ("timer", "random_slow", "mimic"):
            single += [kind] * mix.get(kind, 0)
        for kind in single:
            ip = str(self._new_subnet()[0])   # у каждого одиночного бота своя /24
            records = getattr(self, kind)(ip)
            if len(records) >= 5:
                bots[ip] = (kind, records)
        for _ in range(mix.get("distributed", 0)):
            for ip, records in self.distributed_group().items():
                bots[ip] = ("distributed", records)
        return bots


def inject_bots(log, mix=None, seed=42):
    """Вернуть новый ParsedLog с внедрёнными ботами и их разметку."""
    bots = BotSimulator(log, seed).generate(mix)
    by_ip = dict(log.by_ip)
    for ip, (_, records) in bots.items():
        by_ip[ip] = sorted(records, key=lambda r: r.ts)
    stats = log.stats.copy()
    stats["synthetic_records"] = sum(len(r) for _, r in bots.values())
    return SimulationResult(ParsedLog(by_ip, stats), {ip: k for ip, (k, _) in bots.items()})


def format_record(r):
    """LogRecord -> строка журнала Apache combined."""
    t = time.gmtime(r.ts + r.tz_offset)
    sign = "+" if r.tz_offset >= 0 else "-"
    off = abs(r.tz_offset)
    zone = f"{sign}{off // 3600:02d}{off % 3600 // 60:02d}"
    stamp = time.strftime("%d/%b/%Y:%H:%M:%S", t) + " " + zone
    return (f'{r.ip} - - [{stamp}] "{r.method} {r.path} HTTP/1.1" {r.status} {r.size} '
            f'"{r.referer}" "{r.ua}"')
