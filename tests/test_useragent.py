import pytest

from lsdetector.useragent import analyze_ua, detect_browser, detect_os, expected_chrome_build

GOOD = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/150.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:152.0) Gecko/20100101 Firefox/152.0",
    "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/150.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/26.1 Safari/605.1.15",
    # Яндекс.Браузер не урезает UA - это норма
    "Mozilla/5.0 (Linux; arm_64; Android 12; SM-A525F) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/148.0.7778.12 YaBrowser/26.8.1.110.00 Mobile Safari/537.36",
    # Chrome на iOS (CriOS) показывает полную сборку
    "Mozilla/5.0 (iPhone; CPU iPhone OS 26_3_1 like Mac OS X) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) CriOS/152.0.7977.64 Mobile/15E148 Safari/604.1",
]


@pytest.mark.parametrize("ua", GOOD)
def test_plausible_ua_has_no_reasons(ua):
    assert analyze_ua(ua).rule3 == ()


@pytest.mark.parametrize("ua, code", [
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
     "Chrome/190.0.0.0 Safari/537.36", "3a_version_too_high"),
    ("Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) "
     "Chrome/120.0.3000.10 Safari/537.36", "3b_chrome_build_mismatch"),
    ("Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
     "Chrome/150.0.0.0 Safari/537.36", "3c_invalid_windows_nt"),
    ("Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
     "Chrome/140.0.0.0 Safari/537.36", "3d_browser_on_legacy_windows"),
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
     "Chrome/150.0.0.0 Safari/537.36 Edg/120.0.0.0", "3e_edge_chrome_mismatch"),
    ("Mozilla/5.0 (Windows NT 10.0; rv:100.0) Gecko/20100101 Firefox/150.0",
     "3f_firefox_rv_mismatch"),
    ("Mozilla/5.0 (Windows NT 10.0) AppleWebKit/605.1.15 (KHTML, like Gecko) "
     "Version/17.0 Safari/605.1.15", "3g_modern_safari_on_windows"),
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
     "Chrome/146.0.7680.165 Safari/537.36", "3h_unreduced_chrome_ua"),
    ("Mozilla/5.0 (Linux; Android 5.1; X) AppleWebKit/537.36 (KHTML, like Gecko) "
     "Chrome/120.0.0.0 Mobile Safari/537.36", "3j_browser_on_legacy_android"),
    ("Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/537.36 (KHTML, like Gecko) "
     "Chrome/150.0.0.0 Safari/537.36", "3k_mac_version_impossible"),
    ("python-requests/2.32.3", "3l_automation_ua"),
    ("-", "3l_automation_ua"),
    ("Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 "
     "(KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1", "3m_ios_safari_mismatch"),
])
def test_impossible_ua(ua, code):
    assert code in analyze_ua(ua).rule3


def test_search_bot_keeps_only_version_checks():
    ua = ("Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 "
          "(KHTML, like Gecko) Chrome/151.0.7922.173 Mobile Safari/537.36 "
          "(compatible; Googlebot/2.1; +http://www.google.com/bot.html)")
    info = analyze_ua(ua)
    assert info.bot == "Google"
    assert info.rule3 == ()   # Android 6 + Chrome 151 у Googlebot - норма


def test_yandex_browser_is_not_search_bot():
    ua = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
          "Chrome/150.0.0.0 YaBrowser/26.8.0.0 Safari/537.36")
    assert analyze_ua(ua).bot is None
    assert detect_browser(ua) == "YaBrowser"


def test_detect_os():
    assert detect_os("Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X)") == "iOS"
    assert detect_os("Mozilla/5.0 (X11; Linux x86_64)") == "Linux"


def test_expected_chrome_build_interpolation():
    build, tol = expected_chrome_build(120)
    assert build == 6099 and tol == 150
    assert expected_chrome_build(60) is None
