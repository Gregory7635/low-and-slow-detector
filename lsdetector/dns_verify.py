"""Правило 1: проверка поисковых роботов через reverse + forward DNS.

Робот считается настоящим, если PTR-запись его IP лежит в домене поисковика,
а A/AAAA-запись этого имени возвращает тот же IP (так рекомендуют
Google, Yandex и Bing). IP, по которым DNS не ответил, получают статус
unknown и не считаются поддельными.
"""

import ipaddress
import json
import os
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor

# Домены, в которые должен разрешаться PTR-запрос (по документации поисковиков).
# gae.googleusercontent.com - только этот поддомен (пользовательские фетчеры
# Google); весь googleusercontent.com добавлять НЕЛЬЗЯ - там облачные ВМ клиентов.
BOT_DOMAINS = {
    "Google": ("googlebot.com", "google.com", "gae.googleusercontent.com"),
    "Bing": ("search.msn.com",),
    "Yandex": ("yandex.ru", "yandex.net", "yandex.com"),
}

# Коды "записи нет" (это ответ, а не сбой):
# Linux: 1 HOST_NOT_FOUND, 4 NO_DATA; Windows: 11001 WSAHOST_NOT_FOUND, 11004 WSANO_DATA
NX_ERRNOS = {1, 4, 11001, 11004}
NX_GAI = {socket.EAI_NONAME, getattr(socket, "EAI_NODATA", None), 11001, 11004} - {None}


def system_reverse(ip, retries=1):
    """('ok', host) | ('nx', None) - записи нет | ('temp', None) - сбой."""
    for _ in range(retries + 1):
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


def system_forward(host, retries=1):
    """('ok', {ip,...}) | ('nx', set()) | ('temp', set())."""
    for _ in range(retries + 1):
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


class DnsVerifier:
    """Проверяет IP заявленных ботов и хранит результаты в кэше.

    Функции reverse/forward можно подменить (в тестах или для другого
    резолвера), не трогая логику проверки.
    """

    def __init__(self, cache=None, reverse=system_reverse, forward=system_forward,
                 max_workers=50, offline=False):
        self.cache = cache if cache is not None else {}
        self.reverse = reverse
        self.forward = forward
        self.max_workers = max_workers
        self.offline = offline

    @classmethod
    def from_file(cls, path, **kwargs):
        cache = {}
        if path and os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                cache = json.load(f)
        return cls(cache, **kwargs)

    def save(self, path):
        if path:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(self.cache, f, ensure_ascii=False, indent=1)

    def verify_one(self, ip, bots):
        """Вернуть {'status': verified|fake|unknown, 'hostname', 'detail'}."""
        st, host = self.reverse(ip)
        if st == "temp":
            return {"status": "unknown", "hostname": None, "detail": "ptr_timeout"}
        if st == "nx":
            return {"status": "fake", "hostname": None, "detail": "no_ptr"}
        host = host.rstrip(".").lower()
        domain_ok = any(host == d or host.endswith("." + d)
                        for b in bots for d in BOT_DOMAINS[b])
        if not domain_ok:
            return {"status": "fake", "hostname": host, "detail": "foreign_domain"}
        st, addrs = self.forward(host)
        if st == "temp":
            return {"status": "unknown", "hostname": host, "detail": "a_timeout"}
        if ip in addrs:
            return {"status": "verified", "hostname": host, "detail": "ok"}
        return {"status": "fake", "hostname": host, "detail": "forward_mismatch"}

    def verify(self, bots_by_ip):
        """bots_by_ip: ip -> {имя поисковика}. Возвращает ip -> результат."""
        if self.offline:
            return {ip: self.cache.get(ip, {"status": "unknown", "hostname": None,
                                            "detail": "offline"})
                    for ip in bots_by_ip}
        todo = [(ip, sorted(b)) for ip, b in bots_by_ip.items()
                if ip not in self.cache or self.cache[ip]["status"] == "unknown"]
        if todo:
            print(f"[инфо] DNS-проверка {len(todo)} IP...", file=sys.stderr)
            with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
                for (ip, _), res in zip(todo, pool.map(lambda t: self.verify_one(*t), todo)):
                    self.cache[ip] = res
        return {ip: self.cache[ip] for ip in bots_by_ip}
