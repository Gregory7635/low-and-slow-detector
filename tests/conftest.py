import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from lsdetector.config import DetectorConfig  # noqa: E402
from lsdetector.demo import demo_log  # noqa: E402
from lsdetector.dns_verify import DnsVerifier  # noqa: E402

CHROME_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
             "(KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36")


def line(ip="1.2.3.4", time="08/Sep/2026:10:00:00 +0300", req="GET / HTTP/1.1",
         status=200, size=1234, ref="-", ua=CHROME_UA):
    return f'{ip} - - [{time}] "{req}" {status} {size} "{ref}" "{ua}"'


@pytest.fixture(scope="session")
def demo():
    """Небольшой синтетический журнал с разметкой ботов."""
    return demo_log(seed=3, humans=120)


@pytest.fixture
def config():
    return DetectorConfig(dns_offline=True)


class FakeResolver:
    """Подменяет DNS: таблицы PTR и A задаются в тесте."""

    def __init__(self, ptr=None, a=None):
        self.ptr, self.a = ptr or {}, a or {}

    def reverse(self, ip):
        return ("ok", self.ptr[ip]) if ip in self.ptr else ("nx", None)

    def forward(self, host):
        return ("ok", self.a[host]) if host in self.a else ("nx", set())

    def verifier(self):
        return DnsVerifier(reverse=self.reverse, forward=self.forward, max_workers=2)
