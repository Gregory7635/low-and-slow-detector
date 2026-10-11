"""Полностью синтетический демонстрационный журнал.

Реальный журнал содержит IP-адреса и историю посещений покупателей,
поэтому в репозиторий он не попадает. Для примеров, тестов и демонстрации
веб-интерфейса генерируется журнал вымышленного магазина shop.example:
посетители-люди (сессии со статикой, корзиной, переходами), заявленные
поисковые боты и внедрённые low-and-slow боты (см. simulate.py).
"""

import random

from .parser import LogRecord, ParsedLog
from .simulate import inject_bots

HOST = "shop.example"
START = 1_788_850_000.0          # 08.09.2026, 09:46 МСК
TZ = 3 * 3600

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/150.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/149.0.0.0 YaBrowser/26.8.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:152.0) Gecko/20100101 Firefox/152.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/150.0.0.0 Safari/537.36 Edg/150.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) "
    "Version/26.1 Safari/605.1.15",
    "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/150.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/26.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/148.0.0.0 Safari/537.36",
]
SEARCH_BOT_UAS = [
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
]
CATEGORIES = [f"/catalog/{c}" for c in (
    "pens", "paper", "notebooks", "folders", "office", "art", "school", "gifts")]


def _product(rng):
    return f"/product/{rng.randint(1000, 9999)}-{rng.choice(['red', 'blue', 'a4', 'set', 'pro'])}"


class DemoLogGenerator:
    def __init__(self, seed=7, duration=3 * 3600):
        self.rng = random.Random(seed)
        self.duration = duration

    def _ip(self):
        r = self.rng
        return f"10.{r.randint(0, 255)}.{r.randint(0, 255)}.{r.randint(1, 254)}"

    def _rec(self, ip, ts, path, status, size, ref, ua, method="GET"):
        return LogRecord(ip, ts, TZ, method, path, status, size, ref, ua)

    def human(self, ip):
        """Одна-три сессии: страницы со статикой, переходы, иногда корзина."""
        r = self.rng
        ua = r.choice(USER_AGENTS)
        out = []
        for _ in range(r.choice((1, 1, 1, 2, 3))):
            t = START + r.uniform(0, self.duration)
            ref = r.choice(["-", "https://yandex.ru/", "https://www.google.com/",
                            f"https://{HOST}/"])
            for _ in range(r.randint(2, 15)):
                page = r.choice(CATEGORIES) if r.random() < 0.35 else _product(r)
                status = 404 if r.random() < 0.03 else 200
                out.append(self._rec(ip, t, page, status, r.randint(25_000, 90_000), ref, ua))
                for k in range(r.randint(0, 5)):
                    img = f"/img/{r.randint(1, 5000)}.webp"
                    out.append(self._rec(ip, t + 0.05 * (k + 1), img, r.choice((200, 200, 304)),
                                         r.randint(3_000, 60_000), f"https://{HOST}{page}", ua))
                if r.random() < 0.2:
                    out.append(self._rec(ip, t + r.uniform(2, 20), "/cart/add", 200, 16,
                                         f"https://{HOST}{page}", ua, "POST"))
                if r.random() < 0.15:
                    q = r.choice(["ручка", "бумага", "тетрадь"])
                    out.append(self._rec(ip, t + r.uniform(1, 5), f"/search?q={q}", 200,
                                         r.randint(2_000, 5_000), f"https://{HOST}{page}", ua))
                ref = f"https://{HOST}{page}"
                t += r.lognormvariate(3.3, 1.0)   # чтение страницы: от секунд до минут
        return out

    def search_bot(self, ip):
        r = self.rng
        ua = r.choice(SEARCH_BOT_UAS)
        t = START + r.uniform(0, 600)
        out = []
        while t < START + self.duration:
            out.append(self._rec(ip, t, _product(r), 200, r.randint(25_000, 90_000), "-", ua))
            t += r.expovariate(1 / 120)
        return out

    def generate(self, humans=400, search_bots=15):
        by_ip = {}
        for _ in range(humans):
            ip = self._ip()
            by_ip[ip] = sorted(self.human(ip), key=lambda x: x.ts)
        for _ in range(search_bots):
            ip = self._ip()
            by_ip[ip] = self.search_bot(ip)
        return ParsedLog(by_ip)


DEMO_BOT_MIX = {"timer": 12, "random_slow": 12, "distributed": 3, "mimic": 12}


def demo_log(seed=7, humans=300):
    """Журнал с людьми, заявленными поисковиками и разметкой low-and-slow ботов."""
    base = DemoLogGenerator(seed).generate(humans)
    return inject_bots(base, DEMO_BOT_MIX, seed=seed)
