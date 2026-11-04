"""Разбор User-Agent: поисковый бот, браузер, ОС и проверки правила 3."""

import re
from functools import lru_cache
from typing import NamedTuple

# --- Поисковые роботы (для правила 1) ---
BOT_UA_PATTERNS = {
    "Google": re.compile(
        r"Googlebot|Mediapartners-Google|AdsBot-Google|APIs-Google|"
        r"FeedFetcher-Google|Google-InspectionTool|Storebot-Google|GoogleOther"),
    "Bing": re.compile(r"bingbot|adidxbot|BingPreview|MicrosoftPreview", re.I),
    # Только роботы Яндекса ("compatible; YandexXxx/..." или YaDirectFetcher),
    # чтобы не задеть Яндекс.Браузер и мобильные приложения Яндекса.
    "Yandex": re.compile(r"compatible; Yandex\w*/|YaDirectFetcher"),
}

# --- Таблица версий (правило 3) ---
VERSION_TABLE_DATE = "2026-09-09"
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
LAST_ON_WIN7_8 = {"Chrome": 109, "Edge": 109, "Firefox": 115}   # NT 6.1-6.3
LAST_ON_WINXP = {"Chrome": 49, "Firefox": 52, "Edge": 0}        # NT 5.x
# Последняя версия Chrome для старых Android (мажорная версия Android -> Chrome)
LAST_CHROME_ON_ANDROID = {4: 81, 5: 95, 6: 106, 7: 119}
# Форки, официально работающие на старых Windows с новым движком
LEGACY_OS_EXEMPT = ("YaBrowser", "Supermium", "Thorium", "Mypal", "Kafan")
GECKO_FORKS = ("PaleMoon", "Goanna", "Waterfox", "SeaMonkey", "Basilisk", "K-Meleon")
# Браузеры и WebView на Chromium, которые не урезают UA (полная сборка и
# настоящая версия Android - это норма)
UNREDUCED_OK = ("YaBrowser", "YaApp", "YaSearch", "SamsungBrowser", "MiuiBrowser",
                "HeyTapBrowser", "OPR/", "Edg", "UCBrowser", "Vivaldi", "wv)",
                "Electron", "HuaweiBrowser", "VivoBrowser", "Instagram", "FBAV",
                "BitrixDesktop", "Version/4.0")
# Подпроверки, которые на реальном трафике дают много ложных срабатываний
# (встроенные браузеры приложений): попадают в отчёт, но сами по себе
# правило 3 не включают.
WEAK_RULE3 = {"3i_android_ua_not_reduced"}
AUTOMATION_RE = re.compile(
    r"HeadlessChrome|PhantomJS|Selenium|puppeteer|playwright|python-requests|"
    r"python-urllib|aiohttp|httpx|curl/|Wget/|Go-http-client|okhttp|Java/|"
    r"libwww-perl|Scrapy|node-fetch|axios", re.I)

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
    "3l_automation_ua": "UA средства автоматизации или пустой UA",
    "3m_ios_safari_mismatch": "версия Safari не соответствует iOS",
}

RE_CHROME_FULL = re.compile(r"(?<![A-Za-z])(?:Chrome|CriOS)/(\d+)\.(\d+)\.(\d+)\.(\d+)")
RE_CHROME = re.compile(r"(?<![A-Za-z])(?:Chrome|CriOS)/(\d+)")
RE_FIREFOX = re.compile(r"(?:Firefox|FxiOS)/(\d+)")
RE_FIREFOX_RV = re.compile(r"rv:(\d+)\.\d+\)")
RE_EDGE = re.compile(r"Edg(?:A|iOS)?/(\d+)")
RE_SAFARI_VER = re.compile(r"Version/(\d+)[.\d]* (?:Mobile/\S+ )?Safari/")
RE_WIN_NT = re.compile(r"Windows NT (\d+\.\d+)")
RE_ANDROID = re.compile(r"Android (\d+)")
RE_MAC = re.compile(r"Mac OS X (\d+)[_.](\d+)")
RE_IOS = re.compile(r"(?:iPhone|CPU) OS (\d+)_")


class UAInfo(NamedTuple):
    bot: str | None       # Google / Yandex / Bing или None
    browser: str | None
    os: str | None
    rule3: tuple          # коды причин правила 3


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


def _first_int(regex, ua):
    m = regex.search(ua)
    return int(m.group(1)) if m else None


def rule3_checks(ua, browser):
    """Вернуть кортеж кодов причин правила 3 (пустой - UA правдоподобен)."""
    reasons = []
    chrome_major = _first_int(RE_CHROME, ua)
    unreduced_ok = any(t in ua for t in UNREDUCED_OK)

    # 3a: версия выше максимально существующей (+ запас на beta/canary)
    checks = []
    if browser in ("Chrome", "Edge", "Opera", "YaBrowser") and chrome_major:
        checks.append(("Chrome", chrome_major))
    if browser == "Edge":
        checks.append(("Edge", _first_int(RE_EDGE, ua)))
    if browser == "Firefox":
        checks.append(("Firefox", _first_int(RE_FIREFOX, ua)))
    if browser == "Safari":
        checks.append(("Safari", _first_int(RE_SAFARI_VER, ua)))
    if any(v and v > MAX_STABLE_VERSIONS[f] + VERSION_GRACE[f] for f, v in checks):
        reasons.append("3a_version_too_high")

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
                fam, ver = None, None
                if browser == "Firefox":
                    fam, ver = "Firefox", _first_int(RE_FIREFOX, ua)
                elif browser == "Edge":
                    fam, ver = "Edge", _first_int(RE_EDGE, ua)
                elif browser in ("Chrome", "Opera") and chrome_major:
                    fam, ver = "Chrome", chrome_major
                if fam and ver and ver > limits[fam]:
                    reasons.append("3d_browser_on_legacy_windows")

    # 3e: Edge на Chromium всегда совпадает по мажорной версии с Chrome/
    if browser == "Edge" and chrome_major:
        edge = _first_int(RE_EDGE, ua)
        if edge and abs(edge - chrome_major) > 1:
            reasons.append("3e_edge_chrome_mismatch")

    # 3f: Firefox: rv:X должен равняться Firefox/X
    # (исключение: в версиях 110-119 rv был заморожен на 109)
    if browser == "Firefox" and not any(t in ua for t in GECKO_FORKS):
        rv, ff = _first_int(RE_FIREFOX_RV, ua), _first_int(RE_FIREFOX, ua)
        if rv and ff and rv != ff and not (110 <= ff <= 119 and rv == 109):
            reasons.append("3f_firefox_rv_mismatch")

    # 3g: Safari для Windows закончился на версии 5.1
    if browser == "Safari" and "Windows" in ua:
        sv = _first_int(RE_SAFARI_VER, ua)
        if sv and sv >= 6:
            reasons.append("3g_modern_safari_on_windows")

    # 3h: полная сборка в Chrome, который обязан слать урезанный UA
    # (desktop с версии 101, Android с 110; Chrome на iOS - CriOS - не урезает)
    if full and browser == "Chrome" and "CriOS/" not in ua and not unreduced_ok:
        major, mi, b, p = map(int, full.groups())
        if major >= (110 if "Android" in ua else 101) and (mi, b, p) != (0, 0, 0):
            reasons.append("3h_unreduced_chrome_ua")

    # 3i: Chrome на Android >= 110 обязан показывать "Android 10; K"
    if browser == "Chrome" and "Android" in ua and chrome_major and chrome_major >= 110 \
            and "Android 10; K)" not in ua and not unreduced_ok:
        reasons.append("3i_android_ua_not_reduced")

    # 3j: Chrome новее, чем поддерживает заявленный Android
    android = _first_int(RE_ANDROID, ua)
    if android and browser == "Chrome" and chrome_major:
        lim = LAST_CHROME_ON_ANDROID.get(android)
        if lim and chrome_major > lim:
            reasons.append("3j_browser_on_legacy_android")

    # 3k: macOS. Chrome/Edge/Safari заморожены на 10_15_7, Firefox на 10.15,
    # поэтому "Mac OS X 11+" в таких UA невозможна; на 10.12-10.14
    # последние версии: Chrome/Edge 116, Firefox 115.
    mac = RE_MAC.search(ua)
    if mac and browser in ("Chrome", "Edge", "Firefox", "Safari", "Opera") \
            and "iPhone" not in ua and "iPad" not in ua:
        mj, mn = int(mac.group(1)), int(mac.group(2))
        if mj >= 11:
            reasons.append("3k_mac_version_impossible")
        elif mj == 10 and mn < 15:
            ff = _first_int(RE_FIREFOX, ua)
            if (browser == "Firefox" and ff and ff > 115) or \
               (browser != "Firefox" and chrome_major and chrome_major > 116):
                reasons.append("3k_mac_version_impossible")

    # 3l: признаки автоматизации, headless, пустой или голый UA
    if AUTOMATION_RE.search(ua) or ua.strip() in ("", "-", "Mozilla/5.0"):
        reasons.append("3l_automation_ua")

    # 3m: iOS Safari - Version/ совпадает с мажорной версией iOS (до 18);
    # с Safari 26 ОС в UA заморожена на 18_x.
    ios, sv = _first_int(RE_IOS, ua), _first_int(RE_SAFARI_VER, ua)
    if browser == "Safari" and ios and sv:
        if (sv <= 18 and sv != ios) or (19 <= sv <= 25) or (sv >= 26 and ios not in (18, sv)):
            reasons.append("3m_ios_safari_mismatch")

    return tuple(reasons)


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
