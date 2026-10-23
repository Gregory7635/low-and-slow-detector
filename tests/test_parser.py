from conftest import line
from lsdetector.parser import parse_apache_time, parse_line, parse_lines, split_request
from lsdetector.simulate import format_record


def test_parse_time_with_timezone():
    ts, tz = parse_apache_time("08/Sep/2026:10:00:00 +0300")
    assert tz == 3 * 3600
    assert ts == parse_apache_time("08/Sep/2026:07:00:00 +0000")[0]


def test_parse_time_invalid():
    assert parse_apache_time("32/Foo/2026:10:00:00 +0300") is None


def test_parse_line_fields():
    r = parse_line(line(req="POST /cart/add?x=1 HTTP/2.0", status=404, size=16,
                        ref="https://shop.example/"))
    assert (r.ip, r.method, r.path) == ("1.2.3.4", "POST", "/cart/add?x=1")
    assert (r.status, r.size) == (404, 16)
    assert r.referer == "https://shop.example/"


def test_parse_line_dash_size_and_garbage_request():
    r = parse_line(line(req="\\x16\\x03\\x01", size="-"))
    assert r.size == 0 and r.method == "-"


def test_split_request():
    assert split_request("GET /a HTTP/1.1") == ("GET", "/a")
    assert split_request("garbage") == ("-", "garbage")


def test_ipv6_normalized():
    r = parse_line(line(ip="2001:0db8:0000:0000:0000:0000:0000:0001"))
    assert r.ip == "2001:db8::1"


def test_parse_lines_stats_and_sorting():
    lines = [line(time="08/Sep/2026:10:00:05 +0300"), "мусор",
             line(time="08/Sep/2026:10:00:01 +0300"), line(ip="999.1.1.1"), ""]
    log = parse_lines(lines)
    assert log.stats["lines"] == 4
    assert log.stats["parsed"] == 2
    assert log.stats["skipped_format"] == 1
    assert log.stats["skipped_time_or_ip"] == 1
    ts = [r.ts for r in log.by_ip["1.2.3.4"]]
    assert ts == sorted(ts)


def test_format_record_roundtrip():
    r = parse_line(line(req="GET /p/1 HTTP/1.1", ref="https://shop.example/"))
    assert parse_line(format_record(r)) == r
