#!/usr/bin/env python3
"""
bot_detector.py - детектор low-and-slow ботов по журналам Apache (combined).

Запуск:
    python bot_detector.py access.log
    python bot_detector.py access.log --all-rules --analytics report.json
    python bot_detector.py access.log --dns-cache dns.json --whitelist white.txt

Правила (нумерация сохранена от прежней версии, правило 4 удалено):
  1 - заявленный поисковый бот не подтверждён reverse+forward DNS;
  2 - на одном IP несколько разных пар (браузер, ОС) - слабый сигнал;
  3 - невозможный User-Agent: несуществующая версия или внутренне
      противоречивая строка (см. подпроверки 3a-3g);
  5 - аномально равномерные интервалы между "визитами" (пачки запросов
      при загрузке одной страницы склеиваются в один визит);
  6 - много разных IP одной подсети внутри скользящего окна времени.

Подтверждённые DNS поисковые боты исключаются из ВСЕХ правил.
IP, по которым DNS не дал ответа (тайм-аут/сбой), не считаются
поддельными ботами, а учитываются отдельно (dns_unknown).
"""

import argparse
import calendar
import ipaddress
import json
import os
import re
import socket
import sys
import time
from collections import Counter, defaultdict, namedtuple
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache
from itertools import combinations
from statistics import mean, pstdev

# ===========================================================================
# КОНФИГУРАЦИЯ (все значения попадают в аналитический отчёт)
# ===========================================================================

# --- Правило 1 ---
# Домены, в которые должен разрешаться PTR-запрос (по документации поисковиков).
# gae.googleusercontent.com - только этот поддомен (пользовательские фетчеры
# Google); весь googleusercontent.com добавлять НЕЛЬЗЯ - там облачные ВМ клиентов.
BOT_DOMAINS = {
    "Google": ("googlebot.com", "google.com", "gae.googleusercontent.com"),
    "Bing": ("search.msn.com",),
    "Yandex": ("yandex.ru", "yandex.net", "yandex.com"),
}
BOT_UA_PATTERNS = {
    "Google": re.compile(
        r"Googlebot|Mediapartners-Google|AdsBot-Google|APIs-Google|"
        r"FeedFetcher-Google|Google-InspectionTool|Storebot-Google|GoogleOther"),
    "Bing": re.compile(r"bingbot|adidxbot|BingPreview|MicrosoftPreview", re.I),
    # Только роботы Яндекса ("compatible; YandexXxx/..." или YaDirectFetcher),
    # чтобы не задеть Яндекс.Браузер и мобильные приложения Яндекса.
    "Yandex": re.compile(r"compatible; Yandex\w*/|YaDirectFetcher"),
}
DNS_MAX_WORKERS = 50
DNS_RETRIES = 1  # повторов при временной ошибке DNS

# --- Правило 2 ---
RULE2_MIN_DISTINCT = 2  # сколько разных пар (браузер, ОС) на IP считать сигналом

# --- Правило 3 ---
VERSION_TABLE_DATE = "2026-09-09"  # дата актуальности таблицы версий
MAX_STABLE_VERSIONS = {"Chrome": 153, "Firefox": 155, "Safari": 27, "Edge": 152}
# Запас на beta/dev/canary/nightly (они опережают стабильную ветку на 1-2 версии)
VERSION_GRACE = {"Chrome": 2, "Firefox": 2, "Safari": 1, "Edge": 2}
# Номер сборки Chrome (3-е число в Chrome/X.0.BUILD.Y) однозначно связан с
# мажорной версией. Опорные точки: мажорная версия -> номер ветки сборки.
CHROME_BUILD_ANCHORS = [
    (70, 3538), (75, 3770), (80, 3987), (85, 4183), (90, 4430), (95, 4638),
    (100, 4896), (105, 5195), (110, 5481), (115, 5790), (120, 6099),
    (125, 6422), (130, 6723), (135, 7049), (136, 7103), (137, 7151),
    (138, 7204), (139, 7258), (140, 7339), (141, 7390), (142, 7444), (143, 7499),
] 
CHROME_BUILD_TOLERANCE = 150  # ~ 3 мажорные версии
VALID_WINDOWS_NT = {"5.0", "5.1", "5.2", "6.0", "6.1", "6.2", "6.3", "6.4", "10.0"}
LAST_ON_WIN7_8 = {"Chrome": 109, "Edge": 109, "Firefox": 115}  # NT 6.1-6.3
LAST_ON_WINXP = {"Chrome": 49, "Firefox": 52, "Edge": 0}                  # NT 5.x
# Форки, официально работающие на старых Windows с новым движком
LEGACY_OS_EXEMPT = ("YaBrowser", "Supermium", "Thorium", "Mypal", "Kafan")
GECKO_FORKS = ("PaleMoon", "Goanna", "Waterfox", "SeaMonkey", "Basilisk", "K-Meleon")

# --- Правило 5 ---
RULE5_BURST_GAP = 1.0     # запросы с разрывом <= 1 с - одна загрузка страницы
RULE5_MIN_VISITS = 5      # минимум визитов (т.е. 4 интервала) для расчёта CV
RULE5_CV_THRESHOLD = 0.15

# --- Правило 6 ---
SUBNET_PREFIX_V4 = 24
SUBNET_PREFIX_V6 = 64
SUBNET_IP_THRESHOLD = 5
SUBNET_WINDOW = 600.0     # секунд; 0 = весь журнал целиком (старое поведение)

# Порядок для "основного" правила: каждый IP учитывается ровно один раз,
# поэтому сумма распределения всегда равна числу подозрительных IP.
PRIMARY_ORDER = (1, 3, 5, 6, 2)

RULE_NAMES = {
    1: "неподтверждённый поисковый бот",
    2: "разные браузеры/ОС на одном IP",
    3: "невозможный User-Agent",
    5: "аномально равномерные интервалы",
    6: "много IP одной подсети в коротком окне",
}
RULE3_REASONS = {
    "3a_version_too_high": "версия выше существующей",
    "3b_chrome_build_mismatch": "номер сборки Chrome не соответствует версии",
    "3c_invalid_windows_nt": "несуществующая версия Windows NT",
    "3d_browser_on_legacy_windows": "версия браузера не поддерживает эту Windows",
    "3e_edge_chrome_mismatch": "версии Edg/ и Chrome/ не совпадают",
    "3f_firefox_rv_mismatch": "rv: не совпадает с версией Firefox",
    "3g_modern_safari_on_windows": "современный Safari на Windows",
    "3h_unreduced_chrome_ua": "полная сборка в Chrome, который урезает UA",
    "3i_android_ua_not_reduced": "Chrome на Android без урезанного 'Android 10; K'",
    "3j_browser_on_legacy_android": "версия Chrome не поддерживает этот Android",
    "3k_mac_version_impossible": "невозможная версия macOS для браузера",
    "3m_ios_safari_mismatch": "версия Safari не соответствует iOS",
    "3l_automation_ua": "UA средства автоматизации или пустой UA",
}

# ===========================================================================
# РАЗБОР ЖУРНАЛА
# ===========================================================================

APACHE_LOG_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?:[^"\\]|\\.)*" (?P<status>\d{3}) \S+ '
    r'"(?:[^"\\]|\\.)*" "(?P<ua>(?:[^"\\]|\\.)*)"'
)
MONTHS = {m: i for i, m in enumerate(
    ("Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), 1)}


def parse_apache_time(raw):
    """'09/Sep/2026:10:00:00 +0300' -> epoch-секунды UTC или None."""
    try:
        day, month, year = int(raw[0:2]), MONTHS[raw[3:6]], int(raw[7:11])
        hh, mm, ss = int(raw[12:14]), int(raw[15:17]), int(raw[18:20])
        sign = 1 if raw[21] == "+" else -1
        tz = sign * (int(raw[22:24]) * 3600 + int(raw[24:26]) * 60)
        return calendar.timegm((year, month, day, hh, mm, ss)) - tz
    except (KeyError, ValueError, IndexError):
        return None


def normalize_ip(raw):
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError:
        return None


# ===========================================================================
# РАЗБОР USER-AGENT (кэшируется по строке)
# ===========================================================================

UAInfo = namedtuple("UAInfo", ["bot", "browser", "os", "rule3"])
RE_CHROME_FULL = re.compile(r"(?<![A-Za-z])(?:Chrome|CriOS)/(\d+)\.(\d+)\.(\d+)\.(\d+)")
RE_CHROME = re.compile(r"(?<![A-Za-z])(?:Chrome|CriOS)/(\d+)")
RE_FIREFOX = re.compile(r"(?:Firefox|FxiOS)/(\d+)")
RE_FIREFOX_RV = re.compile(r"rv:(\d+)\.\d+\)")
RE_EDGE = re.compile(r"Edg(?:A|iOS)?/(\d+)")
RE_SAFARI_VER = re.compile(r"Version/(\d+)[.\d]* (?:Mobile/\S+ )?Safari/")
RE_WIN_NT = re.compile(r"Windows NT (\d+\.\d+)")
RE_HEADLESS = re.compile(r"HeadlessChrome/(\d+)")

def detect_bot(ua):
    for name, pat in BOT_UA_PATTERNS.items():
        if pat.search(ua):
            return name
    return None


def detect_browser(ua):
    if "Edg/" in ua or "EdgA/" in ua or "EdgiOS/" in ua:
        return "Edge"
    if "OPR/" in ua or "Opera" in ua:
        return "Opera"
    if "YaBrowser/" in ua:
        return "YaBrowser"
    if "Chrome/" in ua or "CriOS/" in ua:
        return "Chrome"
    if "Firefox/" in ua or "FxiOS/" in ua:
        return "Firefox"
    if "Safari/" in ua and "Version/" in ua:
        return "Safari"
    return None


def detect_os(ua):
    if "Windows" in ua:
        return "Windows"
    if "Android" in ua:
        return "Android"
    if "iPhone" in ua or "iPad" in ua:
        return "iOS"
    if "Macintosh" in ua or "Mac OS X" in ua:
        return "macOS"
    if "CrOS" in ua:
        return "ChromeOS"
    if "Linux" in ua:
        return "Linux"
    return None


def expected_chrome_build(major):
    """-> (ожидаемая сборка, допуск) или None."""
    a = CHROME_BUILD_ANCHORS
    if major < a[0][0]:
        return None
    for (m1, b1), (m2, b2) in zip(a, a[1:]):
        if m1 <= major <= m2:
            return b1 + (b2 - b1) * (major - m1) / (m2 - m1), CHROME_BUILD_TOLERANCE
    (m1, b1), (m2, b2) = a[-5], a[-1]          # наклон по последним точкам
    k = (b2 - b1) / (m2 - m1)
    extra = major - m2
    return b2 + k * extra, CHROME_BUILD_TOLERANCE + 15 * extra

def rule3_checks(ua, browser):
    """Вернуть кортеж кодов причин правила 3 (пустой - UA правдоподобен)."""
    reasons = []
    chrome = RE_CHROME.search(ua)
    chrome_major = int(chrome.group(1)) if chrome else None

    # 3a: версия выше максимально существующей (+ запас на beta/canary)
    checks = []
    if browser in ("Chrome", "Edge", "Opera", "YaBrowser") and chrome_major:
        checks.append(("Chrome", chrome_major))
    if browser == "Edge":
        m = RE_EDGE.search(ua)
        if m:
            checks.append(("Edge", int(m.group(1))))
    if browser == "Firefox":
        m = RE_FIREFOX.search(ua)
        if m:
            checks.append(("Firefox", int(m.group(1))))
    if browser == "Safari":
        m = RE_SAFARI_VER.search(ua)
        if m:
            checks.append(("Safari", int(m.group(1))))
    for fam, ver in checks:
        if ver > MAX_STABLE_VERSIONS[fam] + VERSION_GRACE[fam]:
            reasons.append("3a_version_too_high")
            break

    # 3b: номер сборки Chrome не соответствует мажорной версии
    full = RE_CHROME_FULL.search(ua)
    if full:
        major, build = int(full.group(1)), int(full.group(3))
        if build != 0:  # "Chrome/120.0.0.0" - урезанный UA, это норма
            res = expected_chrome_build(major)
            if res and abs(build - res[0]) > res[1]:
                reasons.append("3b_chrome_build_mismatch")

    # 3c, 3d: версия Windows
    nt = RE_WIN_NT.search(ua)
    if nt:
        ntv = nt.group(1)
        if ntv not in VALID_WINDOWS_NT:
            reasons.append("3c_invalid_windows_nt")
        elif not any(t in ua for t in LEGACY_OS_EXEMPT):
            limits = None
            if ntv in ("6.1", "6.2", "6.3"):
                limits = LAST_ON_WIN7_8
            elif ntv.startswith("5."):
                limits = LAST_ON_WINXP
            if limits:
                ver = None
                fam = browser if browser in limits else None
                if fam == "Firefox":
                    m = RE_FIREFOX.search(ua)
                    ver = int(m.group(1)) if m else None
                elif fam == "Edge":
                    m = RE_EDGE.search(ua)
                    ver = int(m.group(1)) if m else None
                elif browser in ("Chrome", "Opera") and chrome_major:
                    fam, ver = "Chrome", chrome_major
                if fam and ver and ver > limits[fam]:
                    reasons.append("3d_browser_on_legacy_windows")

    # 3e: Edge на Chromium всегда совпадает по мажорной версии с Chrome/
    if browser == "Edge" and chrome_major:
        m = RE_EDGE.search(ua)
        if m and abs(int(m.group(1)) - chrome_major) > 1:
            reasons.append("3e_edge_chrome_mismatch")

    # 3f: Firefox: rv:X должен равняться Firefox/X
    # (исключение: в версиях 110-119 rv был заморожен на 109)
    if browser == "Firefox" and not any(t in ua for t in GECKO_FORKS):
        rv, ff = RE_FIREFOX_RV.search(ua), RE_FIREFOX.search(ua)
        if rv and ff:
            rv, ff = int(rv.group(1)), int(ff.group(1))
            if rv != ff and not (110 <= ff <= 119 and rv == 109):
                reasons.append("3f_firefox_rv_mismatch")

    # 3g: Safari для Windows закончился на версии 5.1
    if browser == "Safari" and "Windows" in ua:
        m = RE_SAFARI_VER.search(ua)
        if m and int(m.group(1)) >= 6:
            reasons.append("3g_modern_safari_on_windows")

    return tuple(reasons)

    # 3h: полная сборка в Chrome, который обязан слать урезанный UA
    full = RE_CHROME_FULL.search(ua)
    if full and browser in ("Chrome", "Edge", "Opera") \
            and not any(t in ua for t in UNREDUCED_OK):
        major, mi, b, p = map(int, full.groups())
        if major >= (110 if "Android" in ua else 101) and (mi, b, p) != (0, 0, 0):
            reasons.append("3h_unreduced_chrome_ua")

    # 3i: Chrome на Android >= 110 обязан показывать "Android 10; K"
    if browser == "Chrome" and "Android" in ua and chrome_major and chrome_major >= 110 \
            and "Android 10; K)" not in ua and not any(t in ua for t in UNREDUCED_OK):
        reasons.append("3i_android_ua_not_reduced")

    # 3j: Chrome новее, чем поддерживает заявленный Android
    a = RE_ANDROID.search(ua)
    if a and browser == "Chrome" and chrome_major:
        lim = LAST_CHROME_ON_ANDROID.get(int(a.group(1)))
        if lim and chrome_major > lim:
            reasons.append("3j_browser_on_legacy_android")

    # 3k: macOS. Chrome/Edge/Safari заморожены на 10_15_7, Firefox на 10.15,
    # поэтому "Mac OS X 11+" в таких UA невозможна; на 10.12-10.14
    # последние версии: Chrome/Edge 116, Firefox 115.
    mac = RE_MAC.search(ua)
    if mac and browser in ("Chrome", "Edge", "Firefox", "Safari", "Opera"):
        mj, mn = int(mac.group(1)), int(mac.group(2))
        if mj >= 11:
            reasons.append("3k_mac_version_impossible")
        elif mj == 10 and mn < 15:
            ff = RE_FIREFOX.search(ua)
            if (browser == "Firefox" and ff and int(ff.group(1)) > 115) or \
               (browser != "Firefox" and chrome_major and chrome_major > 116):
                reasons.append("3k_mac_version_impossible")

    # 3m: iOS Safari - Version/ совпадает с мажорной версией iOS (до 18);
    # с Safari 26 ОС в UA заморожена на 18_x (проверьте на своих логах).
    ios, sv = RE_IOS.search(ua), RE_SAFARI_VER.search(ua)
    if browser == "Safari" and ios and sv:
        o, v = int(ios.group(1)), int(sv.group(1))
        if (v <= 18 and v != o) or (19 <= v <= 25) or (v >= 26 and o not in (18, v)):
            reasons.append("3m_ios_safari_mismatch")

    # 3l: признаки автоматизации, headless, пустой или голый UA
    if AUTOMATION_RE.search(ua) or ua.strip() in ("", "-", "Mozilla/5.0"):
        reasons.append("3l_automation_ua")



@lru_cache(maxsize=200_000)
def analyze_ua(ua):
    bot = detect_bot(ua)
    browser = detect_browser(ua)
    r3 = rule3_checks(ua, browser)
    if bot:
        # У настоящего Googlebot smartphone в UA "Android 6.0.1 + Chrome/14x" -
        # это норма, поэтому проверки совместимости с ОС для ботов отбрасываем.
        r3 = tuple(r for r in r3 if r[:2] in ("3a", "3b", "3l"))
        return UAInfo(bot, None, None, r3)
    return UAInfo(None, browser, detect_os(ua), r3)


# ===========================================================================
# ЗАГРУЗКА
# ===========================================================================

def load_history(path):
    """ip -> отсортированный список (время, UAInfo); плюс статистика разбора."""
    history = defaultdict(list)
    stats = Counter()
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            stats["lines"] += 1
            m = APACHE_LOG_RE.match(line)
            if not m:
                stats["skipped_format"] += 1
                continue
            ts = parse_apache_time(m.group("time"))
            ip = normalize_ip(m.group("ip"))
            if ts is None or ip is None:
                stats["skipped_time_or_ip"] += 1
                continue
            stats["parsed"] += 1
            history[ip].append((ts, analyze_ua(m.group("ua"))))
    for entries in history.values():
        if any(entries[i][0] < entries[i - 1][0] for i in range(1, len(entries))):
            entries.sort(key=lambda e: e[0])
    return history, stats


# ===========================================================================
# ПРАВИЛО 1: DNS-верификация
# ===========================================================================

# Коды "записи нет" (это ответ, а не сбой):
# Linux: 1 HOST_NOT_FOUND, 4 NO_DATA; Windows: 11001 WSAHOST_NOT_FOUND, 11004 WSANO_DATA
NX_ERRNOS = {1, 4, 11001, 11004}
NX_GAI = {socket.EAI_NONAME, getattr(socket, "EAI_NODATA", None), 11001, 11004} - {None}


def _reverse(ip):
    """('ok', host) | ('nx', None) - записи нет | ('temp', None) - сбой."""
    for _ in range(DNS_RETRIES + 1):
        try:
            return "ok", socket.gethostbyaddr(ip)[0]
        except socket.herror as e:
            if e.errno in NX_ERRNOS:
                return "nx", None
        except socket.gaierror as e:
            if e.errno in NX_GAI:
                return "nx", None
        except OSError:
            pass
        time.sleep(0.2)
    return "temp", None


def _forward(host):
    """('ok', {ip,...}) | ('nx', set()) | ('temp', set())."""
    for _ in range(DNS_RETRIES + 1):
        try:
            addrs = set()
            for item in socket.getaddrinfo(host, None):
                addrs.add(str(ipaddress.ip_address(item[4][0].split("%")[0])))
            return "ok", addrs
        except socket.gaierror as e:
            if e.errno in NX_GAI:
                return "nx", set()
        except OSError:
            pass
        time.sleep(0.2)
    return "temp", set()


def verify_ip(item):
    """Вернуть (ip, {'status': verified|fake|unknown, 'hostname': ...})."""
    ip, bots = item
    st, host = _reverse(ip)
    if st == "temp":
        return ip, {"status": "unknown", "hostname": None, "detail": "ptr_timeout"}
    if st == "nx":
        return ip, {"status": "fake", "hostname": None, "detail": "no_ptr"}
    host = host.rstrip(".").lower()
    domain_ok = any(host == d or host.endswith("." + d)
                    for b in bots for d in BOT_DOMAINS[b])
    if not domain_ok:
        return ip, {"status": "fake", "hostname": host, "detail": "foreign_domain"}
    st, addrs = _forward(host)
    if st == "temp":
        return ip, {"status": "unknown", "hostname": host, "detail": "a_timeout"}
    if ip in addrs:
        return ip, {"status": "verified", "hostname": host, "detail": "ok"}
    return ip, {"status": "fake", "hostname": host, "detail": "forward_mismatch"}


def resolve_bots(bots_by_ip, cache):
    """Проверить IP, которых нет в кэше. cache: ip -> результат."""
    todo = [(ip, sorted(b)) for ip, b in bots_by_ip.items()
            if ip not in cache or cache[ip]["status"] == "unknown"]
    if todo:
        print(f"[инфо] DNS-проверка {len(todo)} IP...", file=sys.stderr)
        with ThreadPoolExecutor(max_workers=DNS_MAX_WORKERS) as pool:
            for ip, res in pool.map(verify_ip, todo):
                cache[ip] = res
    return cache


# ===========================================================================
# ПРАВИЛО 2
# ===========================================================================

def rule2_mixed_browsers(entries):
    pairs = {(u.browser, u.os) for _, u in entries
             if u.bot is None and u.browser and u.os}
    return len(pairs) >= RULE2_MIN_DISTINCT, sorted(f"{b}/{o}" for b, o in pairs)


# ===========================================================================
# ПРАВИЛО 5
# ===========================================================================

def visit_starts(times):
    """Склеить запросы с разрывом <= RULE5_BURST_GAP в один визит."""
    starts, prev = [], None
    for t in times:
        if prev is None or t - prev > RULE5_BURST_GAP:
            starts.append(t)
        prev = t
    return starts


def rule5_cv(entries):
    """Коэффициент вариации интервалов между визитами или None (мало данных)."""
    starts = visit_starts([t for t, _ in entries])
    if len(starts) < RULE5_MIN_VISITS:
        return None
    iv = [b - a for a, b in zip(starts, starts[1:])]
    avg = mean(iv)
    return pstdev(iv) / avg if avg > 0 else None


# ===========================================================================
# ПРАВИЛО 6: скользящее окно по подсети
# ===========================================================================

def subnet_of(ip):
    addr = ipaddress.ip_address(ip)
    p = SUBNET_PREFIX_V4 if addr.version == 4 else SUBNET_PREFIX_V6
    return str(ipaddress.ip_network(f"{ip}/{p}", strict=False))


def load_whitelist(path):
    nets = []
    if path:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.split("#")[0].strip()
                if line:
                    nets.append(ipaddress.ip_network(line, strict=False))
    return nets


def in_whitelist(ip, nets):
    if not nets:
        return False
    a = ipaddress.ip_address(ip)
    return any(a.version == n.version and a in n for n in nets)


def rule6_scan(history, eligible_ips):
    """Вернуть (помеченные IP, отчёт по подсетям).
    IP помечается, только если был активен в окне, где число разных IP
    подсети достигло порога, а не за то, что его подсеть 'плохая' вообще."""
    by_subnet = defaultdict(list)
    for ip in eligible_ips:
        by_subnet[subnet_of(ip)].append(ip)

    flagged, report = set(), {}
    for subnet, ips in by_subnet.items():
        if len(ips) < SUBNET_IP_THRESHOLD:
            continue
        if not SUBNET_WINDOW:
            flagged.update(ips)
            report[subnet] = {"unique_ips_total": len(ips),
                              "max_ips_in_window": len(ips), "flagged_ips": len(ips)}
            continue
        events = sorted((t, ip) for ip in ips
                        for t in sorted({int(t) for t, _ in history[ip]}))
        window, left, peak, hit = Counter(), 0, 0, set()
        for t, ip in events:
            window[ip] += 1
            while events[left][0] < t - SUBNET_WINDOW:
                old = events[left][1]
                window[old] -= 1
                if not window[old]:
                    del window[old]
                left += 1
            peak = max(peak, len(window))
            if len(window) >= SUBNET_IP_THRESHOLD:
                hit.update(window)
        if hit:
            flagged |= hit
            report[subnet] = {"unique_ips_total": len(ips),
                              "max_ips_in_window": peak, "flagged_ips": len(hit)}
    return flagged, report


# ===========================================================================
# ОСНОВНОЙ АНАЛИЗ
# ===========================================================================

def analyze(history, dns_cache, whitelist, rule1_priority=True,
            dns_unknown_as_fake=False):
    bots_by_ip = {}
    for ip, entries in history.items():
        names = {u.bot for _, u in entries if u.bot}
        if names:
            bots_by_ip[ip] = names
    resolve_bots(bots_by_ip, dns_cache)

    def status(ip):
        return dns_cache[ip]["status"] if ip in bots_by_ip else None

    verified = {ip for ip in bots_by_ip if status(ip) == "verified"}
    unknown = {ip for ip in bots_by_ip if status(ip) == "unknown"}
    fake = {ip for ip in bots_by_ip if status(ip) == "fake"}
    if dns_unknown_as_fake:
        fake |= unknown

    # Правило 6: подтверждённые боты, белый список и (в режиме приоритета)
    # IP правила 1 в подсчёт не входят.
    eligible = [ip for ip in history
                if ip not in verified and not in_whitelist(ip, whitelist)
                and not (rule1_priority and ip in fake)]
    r6_flagged, r6_report = rule6_scan(history, eligible)

    results, details = {}, {}
    for ip, entries in history.items():
        if ip in verified:
            continue
        rules, det = set(), {}
        if ip in fake:
            rules.add(1)
            det["dns"] = dns_cache[ip]
            if rule1_priority:
                results[ip], details[ip] = rules, det
                continue
        r3 = sorted({r for _, u in entries for r in u.rule3})
        if r3:
            rules.add(3)
            det["rule3"] = r3
        hit2, pairs = rule2_mixed_browsers(entries)
        if hit2:
            rules.add(2)
            det["rule2_pairs"] = pairs
        cv = rule5_cv(entries)
        if cv is not None and cv < RULE5_CV_THRESHOLD:
            rules.add(5)
            det["rule5_cv"] = round(cv, 4)
        if ip in r6_flagged:
            rules.add(6)
            det["rule6_subnet"] = subnet_of(ip)
        if rules:
            results[ip], details[ip] = rules, det

    meta = {"verified_bots": len(verified), "dns_unknown": len(unknown),
            "claimed_bots": len(bots_by_ip), "rule6_subnets": r6_report}
    return results, details, meta


def primary_rule(rules):
    return next(r for r in PRIMARY_ORDER if r in rules)


# ===========================================================================
# ВЫВОД
# ===========================================================================

def write_txt(results, details, path):
    with open(path, "w", encoding="utf-8") as f:
        for ip in sorted(results):
            reasons = []
            for r in sorted(results[ip]):
                s = RULE_NAMES[r]
                if r == 3:
                    s += " (" + "; ".join(RULE3_REASONS[c] for c in details[ip]["rule3"]) + ")"
                if r == 5:
                    s += f" (CV={details[ip]['rule5_cv']})"
                reasons.append(s)
            f.write(f"{ip} - {', '.join(reasons)}\n")


def summarize(history, stats, results, details, meta, args):
    total = len(results)
    rule_ids = sorted(RULE_NAMES)
    primary = Counter(primary_rule(r) for r in results.values())
    combos = Counter("+".join(map(str, sorted(r))) for r in results.values())
    r3_reasons = Counter(c for d in details.values() for c in d.get("rule3", []))
    return {
        "mode": "rule1_priority" if args.priority else "all_rules",
        "parse_stats": dict(stats),
        "unique_ips": len(history),
        "suspicious_ips": total,
        "claimed_search_bots": meta["claimed_bots"],
        "verified_search_bots_excluded": meta["verified_bots"],
        "dns_unknown_not_counted": meta["dns_unknown"],
        "rule_counts_non_exclusive": {str(r): sum(r in s for s in results.values())
                                      for r in rule_ids},
        "primary_rule_distribution": {
            "order": list(PRIMARY_ORDER),
            "counts": {str(r): primary.get(r, 0) for r in PRIMARY_ORDER},
            "sum_check": sum(primary.values()) == total,
        },
        "rule_combinations": dict(combos.most_common()),
        "pairwise_intersections": {f"{a}&{b}": sum(a in s and b in s for s in results.values())
                                   for a, b in combinations(rule_ids, 2)},
        "rule3_reasons": {k: r3_reasons.get(k, 0) for k in RULE3_REASONS},
        "rule6_subnets": meta["rule6_subnets"],
        "config": {
            "bot_domains": BOT_DOMAINS, "version_table_date": VERSION_TABLE_DATE,
            "max_stable_versions": MAX_STABLE_VERSIONS, "version_grace": VERSION_GRACE,
            "chrome_build_tolerance": CHROME_BUILD_TOLERANCE,
            "rule2_min_distinct": RULE2_MIN_DISTINCT,
            "rule5_burst_gap_s": RULE5_BURST_GAP, "rule5_min_visits": RULE5_MIN_VISITS,
            "rule5_cv_threshold": RULE5_CV_THRESHOLD,
            "subnet_prefix_v4": SUBNET_PREFIX_V4, "subnet_prefix_v6": SUBNET_PREFIX_V6,
            "subnet_ip_threshold": SUBNET_IP_THRESHOLD, "subnet_window_s": SUBNET_WINDOW,
            "dns_unknown_as_fake": args.dns_unknown_as_fake,
            "whitelist": args.whitelist,
        },
        "ip_details": {ip: {"rules": sorted(results[ip]), **details[ip]}
                       for ip in sorted(results)},
    }


def main():
    global SUBNET_WINDOW, SUBNET_IP_THRESHOLD, SUBNET_PREFIX_V4, RULE5_CV_THRESHOLD
    p = argparse.ArgumentParser(description="Детектор low-and-slow ботов по логам Apache")
    p.add_argument("logfile")
    p.add_argument("-o", "--output", default="suspicious_ips.txt")
    p.add_argument("--analytics", metavar="JSON", help="подробный JSON-отчёт")
    p.add_argument("--all-rules", action="store_true",
                   help="проверять все правила даже при срабатывании правила 1")
    p.add_argument("--dns-cache", metavar="JSON",
                   help="файл кэша DNS: повторные прогоны дают те же результаты")
    p.add_argument("--dns-unknown-as-fake", action="store_true",
                   help="считать IP без ответа DNS поддельными ботами")
    p.add_argument("--whitelist", metavar="FILE", help="CIDR-диапазоны, исключаемые из правила 6")
    p.add_argument("--subnet-window", type=float, default=SUBNET_WINDOW,
                   help=f"окно правила 6, с (0 = весь журнал), по умолчанию {SUBNET_WINDOW}")
    p.add_argument("--subnet-threshold", type=int, default=SUBNET_IP_THRESHOLD)
    p.add_argument("--subnet-prefix", type=int, default=SUBNET_PREFIX_V4)
    p.add_argument("--cv-threshold", type=float, default=RULE5_CV_THRESHOLD)
    args = p.parse_args()
    SUBNET_WINDOW, SUBNET_IP_THRESHOLD = args.subnet_window, args.subnet_threshold
    SUBNET_PREFIX_V4, RULE5_CV_THRESHOLD = args.subnet_prefix, args.cv_threshold
    args.priority = not args.all_rules

    history, stats = load_history(args.logfile)
    if stats["skipped_format"] or stats["skipped_time_or_ip"]:
        print(f"[инфо] пропущено строк: {stats['skipped_format'] + stats['skipped_time_or_ip']}"
              f" из {stats['lines']}", file=sys.stderr)
    if history:
        last = max(e[-1][0] for e in history.values())
        table = calendar.timegm(time.strptime(VERSION_TABLE_DATE, "%Y-%m-%d"))
        if last > table + 28 * 86400:
            print("[внимание] журнал новее таблицы версий более чем на 4 недели - "
                  "обновите MAX_STABLE_VERSIONS", file=sys.stderr)

    dns_cache = {}
    if args.dns_cache and os.path.exists(args.dns_cache):
        with open(args.dns_cache, encoding="utf-8") as f:
            dns_cache = json.load(f)
    results, details, meta = analyze(history, dns_cache, load_whitelist(args.whitelist),
                                     args.priority, args.dns_unknown_as_fake)
    if args.dns_cache:
        with open(args.dns_cache, "w", encoding="utf-8") as f:
            json.dump(dns_cache, f, ensure_ascii=False, indent=1)

    write_txt(results, details, args.output)
    s = summarize(history, stats, results, details, meta, args)
    if args.analytics:
        with open(args.analytics, "w", encoding="utf-8") as f:
            json.dump(s, f, ensure_ascii=False, indent=2)

    print(f"Режим: {s['mode']}")
    print(f"Строк: {stats['lines']}, разобрано: {stats['parsed']}")
    print(f"Уникальных IP: {s['unique_ips']}")
    print(f"Заявленных поисковых ботов: {s['claimed_search_bots']} "
          f"(подтверждено и исключено: {s['verified_search_bots_excluded']}, "
          f"DNS не ответил: {s['dns_unknown_not_counted']})")
    print(f"Подозрительных IP: {s['suspicious_ips']}")
    print("Распределение по основному правилу (каждый IP один раз):")
    for r in PRIMARY_ORDER:
        n = s["primary_rule_distribution"]["counts"][str(r)]
        pct = 100 * n / s["suspicious_ips"] if s["suspicious_ips"] else 0
        print(f"  {r}: {RULE_NAMES[r]:<42} {n:>6}  ({pct:.1f}%)")
    print(f"  сумма сходится: {s['primary_rule_distribution']['sum_check']}")
    if not args.priority:
        print("Срабатывания без учёта приоритета (IP может попасть в несколько):")
        for r, n in s["rule_counts_non_exclusive"].items():
            print(f"  {r}: {n}")
    print(f"Результат: {args.output}" + (f", отчёт: {args.analytics}" if args.analytics else ""))


if __name__ == "__main__":
    main()
