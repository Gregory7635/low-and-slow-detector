"""Разбор журнала Apache в формате combined."""

import calendar
import ipaddress
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import NamedTuple

APACHE_LOG_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<request>(?:[^"\\]|\\.)*)" (?P<status>\d{3}) (?P<size>\S+) '
    r'"(?P<referer>(?:[^"\\]|\\.)*)" "(?P<ua>(?:[^"\\]|\\.)*)"'
)
MONTHS = {m: i for i, m in enumerate(
    ("Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), 1)}


class LogRecord(NamedTuple):
    ip: str
    ts: float        # epoch-секунды UTC
    tz_offset: int   # смещение часового пояса сервера, секунд
    method: str
    path: str
    status: int
    size: int
    referer: str
    ua: str


@dataclass
class ParsedLog:
    """Записи, сгруппированные по IP (каждый список отсортирован по времени)."""
    by_ip: dict = field(default_factory=dict)
    stats: Counter = field(default_factory=Counter)

    @property
    def n_records(self):
        return sum(len(v) for v in self.by_ip.values())

    def time_range(self):
        if not self.by_ip:
            return None, None
        return (min(r[0].ts for r in self.by_ip.values()),
                max(r[-1].ts for r in self.by_ip.values()))


def parse_apache_time(raw):
    """'09/Sep/2026:10:00:00 +0300' -> (epoch UTC, смещение) или None."""
    try:
        day, month, year = int(raw[0:2]), MONTHS[raw[3:6]], int(raw[7:11])
        hh, mm, ss = int(raw[12:14]), int(raw[15:17]), int(raw[18:20])
        sign = 1 if raw[21] == "+" else -1
        tz = sign * (int(raw[22:24]) * 3600 + int(raw[24:26]) * 60)
        return calendar.timegm((year, month, day, hh, mm, ss)) - tz, tz
    except (KeyError, ValueError, IndexError):
        return None


def normalize_ip(raw):
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError:
        return None


def split_request(request):
    """'GET /a?b=1 HTTP/1.1' -> ('GET', '/a?b=1'); мусор -> ('-', request)."""
    parts = request.split(" ")
    if len(parts) == 3 and parts[0].isalpha():
        return parts[0].upper(), parts[1]
    return "-", request


def parse_line(line):
    """Строка журнала -> LogRecord, 'format' или 'time_or_ip' при ошибке."""
    m = APACHE_LOG_RE.match(line)
    if not m:
        return "format"
    t = parse_apache_time(m.group("time"))
    ip = normalize_ip(m.group("ip"))
    if t is None or ip is None:
        return "time_or_ip"
    method, path = split_request(m.group("request"))
    size = m.group("size")
    return LogRecord(ip, t[0], t[1], method, path, int(m.group("status")),
                     int(size) if size.isdigit() else 0,
                     m.group("referer"), m.group("ua"))


def parse_lines(lines):
    """Разобрать итерируемый набор строк в ParsedLog."""
    by_ip = defaultdict(list)
    stats = Counter()
    for line in lines:
        if not line.strip():
            continue
        stats["lines"] += 1
        rec = parse_line(line)
        if isinstance(rec, str):
            stats["skipped_" + rec] += 1
            continue
        stats["parsed"] += 1
        by_ip[rec.ip].append(rec)
    for records in by_ip.values():
        if any(records[i].ts < records[i - 1].ts for i in range(1, len(records))):
            records.sort(key=lambda r: r.ts)
    return ParsedLog(dict(by_ip), stats)


def load_log(path):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return parse_lines(f)
