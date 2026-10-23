from conftest import CHROME_UA, FakeResolver
from lsdetector.config import DetectorConfig
from lsdetector.parser import LogRecord, ParsedLog
from lsdetector.rules import RuleEngine, default_rules, interval_cv, primary_rule, visit_starts

GOOGLEBOT = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
T0 = 1_788_850_000.0


def rec(ip, ts, ua=CHROME_UA, path="/"):
    return LogRecord(ip, ts, 10800, "GET", path, 200, 1000, "-", ua)


def make_log(by_ip):
    return ParsedLog({ip: sorted(r, key=lambda x: x.ts) for ip, r in by_ip.items()})


def run(log, resolver=None, **cfg):
    resolver = resolver or FakeResolver()
    return RuleEngine(default_rules(resolver.verifier()), DetectorConfig(**cfg)).run(log)


def test_visit_starts_merges_bursts():
    assert visit_starts([0, 0.3, 0.8, 10, 10.5, 30], 1.0) == [0, 10, 30]


def test_interval_cv():
    assert interval_cv([0, 60, 120, 180, 240], 1.0, 5) == 0
    assert interval_cv([0, 60, 120], 1.0, 5) is None


def test_rule1_fake_and_verified_bots():
    log = make_log({
        "66.249.66.1": [rec("66.249.66.1", T0, GOOGLEBOT)],
        "5.5.5.5": [rec("5.5.5.5", T0, GOOGLEBOT)],
        "6.6.6.6": [rec("6.6.6.6", T0, GOOGLEBOT)],
    })
    resolver = FakeResolver(
        ptr={"66.249.66.1": "crawl-66-249-66-1.googlebot.com.", "6.6.6.6": "evil.example."},
        a={"crawl-66-249-66-1.googlebot.com": {"66.249.66.1"}})
    res = run(log, resolver)
    assert res.verified == {"66.249.66.1"}
    assert res.hits["5.5.5.5"]["details"]["dns"]["detail"] == "no_ptr"
    assert res.hits["6.6.6.6"]["details"]["dns"]["detail"] == "foreign_domain"
    assert "66.249.66.1" not in res.hits


def test_rule1_forward_mismatch():
    log = make_log({"7.7.7.7": [rec("7.7.7.7", T0, GOOGLEBOT)]})
    resolver = FakeResolver(ptr={"7.7.7.7": "x.googlebot.com"}, a={"x.googlebot.com": {"8.8.8.8"}})
    assert run(log, resolver).hits["7.7.7.7"]["details"]["dns"]["detail"] == "forward_mismatch"


def test_rule1_offline_is_unknown_not_fake():
    log = make_log({"5.5.5.5": [rec("5.5.5.5", T0, GOOGLEBOT)]})
    from lsdetector.dns_verify import DnsVerifier
    res = RuleEngine(default_rules(DnsVerifier(offline=True)), DetectorConfig()).run(log)
    assert res.unknown == {"5.5.5.5"} and not res.hits


def test_rule2_mixed_browsers():
    ff = "Mozilla/5.0 (X11; Linux x86_64; rv:152.0) Gecko/20100101 Firefox/152.0"
    log = make_log({"1.1.1.1": [rec("1.1.1.1", T0), rec("1.1.1.1", T0 + 5, ff)]})
    assert run(log).hits["1.1.1.1"]["rules"] == {2}


def test_rule3_impossible_ua():
    log = make_log({"1.1.1.1": [rec("1.1.1.1", T0, "curl/8.0")]})
    assert run(log).hits["1.1.1.1"]["rules"] == {3}


def test_rule5_regular_intervals():
    regular = [rec("2.2.2.2", T0 + 120 * i + (i % 2)) for i in range(10)]
    human = [rec("3.3.3.3", T0 + t) for t in (0, 15, 200, 230, 900, 1000, 2500, 2600)]
    res = run(make_log({"2.2.2.2": regular, "3.3.3.3": human}))
    assert res.hits["2.2.2.2"]["rules"] == {5}
    assert "3.3.3.3" not in res.hits


def test_rule6_subnet_window():
    burst = {f"9.9.9.{i}": [rec(f"9.9.9.{i}", T0 + 30 * i)] for i in range(1, 7)}
    spread = {f"8.8.8.{i}": [rec(f"8.8.8.{i}", T0 + 3600 * i)] for i in range(1, 7)}
    res = run(make_log({**burst, **spread}))
    assert all(res.hits[ip]["rules"] == {6} for ip in burst)
    assert not any(ip in res.hits for ip in spread)
    assert res.rule6_report["9.9.9.0/24"]["max_ips_in_window"] == 6


def test_rule6_whitelist():
    burst = {f"9.9.9.{i}": [rec(f"9.9.9.{i}", T0 + 30 * i)] for i in range(1, 7)}
    assert not run(make_log(burst), whitelist=["9.9.9.0/24"]).hits


def test_rule1_priority_skips_other_rules():
    log = make_log({"5.5.5.5": [rec("5.5.5.5", T0, GOOGLEBOT), rec("5.5.5.5", T0 + 1, "curl/8")]})
    assert run(log).hits["5.5.5.5"]["rules"] == {1}
    assert run(log, rule1_priority=False).hits["5.5.5.5"]["rules"] == {1, 3}


def test_primary_rule_order():
    assert primary_rule({2, 5, 3}) == 3
    assert primary_rule({2}) == 2
