"""Эвристические правила поиска low-and-slow ботов.

Каждое правило - отдельный класс с общим интерфейсом Rule (шаблон
«Стратегия»), поэтому новое правило добавляется без изменения движка.
Нумерация правил сохранена от прототипа (правило 4 было удалено).

  1 - заявленный поисковый бот не подтверждён reverse+forward DNS;
  2 - на одном IP несколько разных пар (браузер, ОС) - слабый сигнал;
  3 - невозможный User-Agent;
  5 - аномально равномерные интервалы между визитами;
  6 - много разных IP одной подсети внутри скользящего окна времени.
"""

import ipaddress
from abc import ABC, abstractmethod
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from statistics import mean, pstdev

from .useragent import WEAK_RULE3, analyze_ua

RULE_NAMES = {
    1: "неподтверждённый поисковый бот",
    2: "разные браузеры/ОС на одном IP",
    3: "невозможный User-Agent",
    5: "аномально равномерные интервалы",
    6: "много IP одной подсети в коротком окне",
}
# Порядок для «основного» правила: каждый IP учитывается ровно один раз
PRIMARY_ORDER = (1, 3, 5, 6, 2)
# Правила, срабатывание которых само по себе означает «бот»
STRONG_RULES = {1, 3, 5, 6}


@dataclass
class RuleContext:
    """Общие данные, которые правила готовят в prepare() и читают в check()."""
    config: object
    log: object
    dns: dict = field(default_factory=dict)        # ip -> результат DNS
    verified: set = field(default_factory=set)     # подтверждённые поисковики
    fake: set = field(default_factory=set)
    unknown: set = field(default_factory=set)
    rule6_flagged: set = field(default_factory=set)
    rule6_report: dict = field(default_factory=dict)
    whitelist: list = field(default_factory=list)  # ip_network


class Rule(ABC):
    id: int
    name: str

    def prepare(self, ctx):
        """Глобальная подготовка по всему журналу (по умолчанию не нужна)."""

    @abstractmethod
    def check(self, ip, records, ctx):
        """Вернуть словарь с подробностями, если правило сработало, иначе None."""


# ---------------------------------------------------------------------------

def claimed_bots(log):
    """ip -> множество поисковиков, которыми IP представлялся в User-Agent."""
    res = {}
    for ip, records in log.by_ip.items():
        names = {analyze_ua(r.ua).bot for r in records} - {None}
        if names:
            res[ip] = names
    return res


class FakeSearchBotRule(Rule):
    id, name = 1, RULE_NAMES[1]

    def __init__(self, verifier):
        self.verifier = verifier

    def prepare(self, ctx):
        ctx.dns = self.verifier.verify(claimed_bots(ctx.log))
        for ip, res in ctx.dns.items():
            {"verified": ctx.verified, "fake": ctx.fake,
             "unknown": ctx.unknown}[res["status"]].add(ip)
        if ctx.config.dns_unknown_as_fake:
            ctx.fake |= ctx.unknown

    def check(self, ip, records, ctx):
        return {"dns": ctx.dns[ip]} if ip in ctx.fake else None


class MixedBrowsersRule(Rule):
    id, name = 2, RULE_NAMES[2]

    def check(self, ip, records, ctx):
        pairs = set()
        for r in records:
            u = analyze_ua(r.ua)
            if u.bot is None and u.browser and u.os:
                pairs.add((u.browser, u.os))
        if len(pairs) >= ctx.config.rule2_min_distinct:
            return {"rule2_pairs": sorted(f"{b}/{o}" for b, o in pairs)}
        return None


class ImpossibleUARule(Rule):
    id, name = 3, RULE_NAMES[3]

    def check(self, ip, records, ctx):
        reasons = sorted({c for ua in {r.ua for r in records} for c in analyze_ua(ua).rule3})
        if reasons and not set(reasons) <= WEAK_RULE3:
            return {"rule3": reasons}
        return None


def visit_starts(times, burst_gap):
    """Склеить запросы с разрывом <= burst_gap в один визит."""
    starts, prev = [], None
    for t in times:
        if prev is None or t - prev > burst_gap:
            starts.append(t)
        prev = t
    return starts


def interval_cv(times, burst_gap, min_visits):
    """Коэффициент вариации интервалов между визитами или None (мало данных)."""
    starts = visit_starts(times, burst_gap)
    if len(starts) < min_visits:
        return None
    iv = [b - a for a, b in zip(starts, starts[1:])]
    avg = mean(iv)
    return pstdev(iv) / avg if avg > 0 else None


class RegularIntervalsRule(Rule):
    id, name = 5, RULE_NAMES[5]

    def check(self, ip, records, ctx):
        c = ctx.config
        cv = interval_cv([r.ts for r in records], c.rule5_burst_gap, c.rule5_min_visits)
        if cv is not None and cv < c.rule5_cv_threshold:
            return {"rule5_cv": round(cv, 4)}
        return None


def subnet_of(ip, prefix_v4=24, prefix_v6=64):
    addr = ipaddress.ip_address(ip)
    p = prefix_v4 if addr.version == 4 else prefix_v6
    return str(ipaddress.ip_network(f"{ip}/{p}", strict=False))


def in_whitelist(ip, nets):
    if not nets:
        return False
    a = ipaddress.ip_address(ip)
    return any(a.version == n.version and a in n for n in nets)


class SubnetBurstRule(Rule):
    """IP помечается, только если был активен в окне, где число разных IP
    подсети достигло порога, а не за то, что его подсеть «плохая» вообще."""
    id, name = 6, RULE_NAMES[6]

    def prepare(self, ctx):
        c = ctx.config
        eligible = [ip for ip in ctx.log.by_ip
                    if ip not in ctx.verified and not in_whitelist(ip, ctx.whitelist)
                    and not (c.rule1_priority and ip in ctx.fake)]
        by_subnet = defaultdict(list)
        for ip in eligible:
            by_subnet[subnet_of(ip, c.subnet_prefix_v4, c.subnet_prefix_v6)].append(ip)

        for subnet, ips in by_subnet.items():
            if len(ips) < c.subnet_ip_threshold:
                continue
            if not c.subnet_window:
                ctx.rule6_flagged.update(ips)
                ctx.rule6_report[subnet] = {"unique_ips_total": len(ips),
                                            "max_ips_in_window": len(ips),
                                            "flagged_ips": len(ips)}
                continue
            events = sorted((t, ip) for ip in ips
                            for t in sorted({int(r.ts) for r in ctx.log.by_ip[ip]}))
            window, left, peak, hit = Counter(), 0, 0, set()
            for t, ip in events:
                window[ip] += 1
                while events[left][0] < t - c.subnet_window:
                    old = events[left][1]
                    window[old] -= 1
                    if not window[old]:
                        del window[old]
                    left += 1
                peak = max(peak, len(window))
                if len(window) >= c.subnet_ip_threshold:
                    hit.update(window)
            if hit:
                ctx.rule6_flagged |= hit
                ctx.rule6_report[subnet] = {"unique_ips_total": len(ips),
                                            "max_ips_in_window": peak,
                                            "flagged_ips": len(hit)}

    def check(self, ip, records, ctx):
        if ip in ctx.rule6_flagged:
            c = ctx.config
            return {"rule6_subnet": subnet_of(ip, c.subnet_prefix_v4, c.subnet_prefix_v6)}
        return None


# ---------------------------------------------------------------------------

@dataclass
class RuleResults:
    hits: dict           # ip -> {'rules': set, 'details': dict}
    verified: set        # подтверждённые поисковые роботы (исключены из всех правил)
    unknown: set         # заявленные боты без ответа DNS
    claimed: int         # сколько IP представлялись поисковиками
    rule6_report: dict

    def rules_of(self, ip):
        hit = self.hits.get(ip)
        return hit["rules"] if hit else set()


def default_rules(verifier):
    return [FakeSearchBotRule(verifier), ImpossibleUARule(), MixedBrowsersRule(),
            RegularIntervalsRule(), SubnetBurstRule()]


class RuleEngine:
    def __init__(self, rules, config):
        self.rules = rules
        self.config = config

    def run(self, log):
        ctx = RuleContext(self.config, log, whitelist=[
            ipaddress.ip_network(n, strict=False) for n in self.config.whitelist])
        # правило 1 готовится первым: от его результата зависят остальные
        for rule in sorted(self.rules, key=lambda r: r.id):
            rule.prepare(ctx)

        hits = {}
        for ip, records in log.by_ip.items():
            if ip in ctx.verified:
                continue
            rules, details = set(), {}
            for rule in sorted(self.rules, key=lambda r: r.id):
                det = rule.check(ip, records, ctx)
                if det is None:
                    continue
                rules.add(rule.id)
                details.update(det)
                if rule.id == 1 and self.config.rule1_priority:
                    break
            if rules:
                hits[ip] = {"rules": rules, "details": details}
        return RuleResults(hits, ctx.verified, ctx.unknown, len(ctx.dns), ctx.rule6_report)


def primary_rule(rules):
    return next(r for r in PRIMARY_ORDER if r in rules)
