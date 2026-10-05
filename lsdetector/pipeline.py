"""DetectionService - единая точка входа для CLI и API.

Собирает вместе разбор журнала, правила, признаки и ML-модели и выдаёт
по каждому IP итоговое решение с объяснением.
"""

import time
from dataclasses import dataclass, field

from .config import DetectorConfig
from .dns_verify import DnsVerifier
from .features import extract_features
from .rules import STRONG_RULES, RuleEngine, default_rules, primary_rule


@dataclass
class IPVerdict:
    ip: str
    requests: int
    rules: list
    details: dict
    scores: dict = field(default_factory=dict)       # имя модели -> оценка
    anomalous: dict = field(default_factory=dict)    # имя модели -> выше порога
    top_features: list = field(default_factory=list)
    is_bot: bool = False
    reason: str = ""

    def to_dict(self):
        return {"ip": self.ip, "requests": self.requests, "rules": self.rules,
                "details": self.details, "scores": {k: round(v, 5) for k, v in self.scores.items()},
                "anomalous": self.anomalous, "top_features": self.top_features,
                "is_bot": self.is_bot, "reason": self.reason}


@dataclass
class DetectionReport:
    verdicts: dict                 # ip -> IPVerdict
    rule_results: object
    stats: dict
    config: dict
    models: list

    def bots(self):
        return [v for v in self.verdicts.values() if v.is_bot]

    def summary(self):
        bots = self.bots()
        by_reason = {}
        for v in bots:
            by_reason[v.reason] = by_reason.get(v.reason, 0) + 1
        rr = self.rule_results
        return {
            **self.stats,
            "unique_ips": len(self.verdicts) + len(rr.verified),
            "claimed_search_bots": rr.claimed,
            "verified_search_bots_excluded": len(rr.verified),
            "dns_unknown": len(rr.unknown),
            "suspicious_ips": len(bots),
            "by_reason": by_reason,
            "rule_counts": {str(r): sum(r in v.rules for v in self.verdicts.values())
                            for r in (1, 2, 3, 5, 6)},
            "models": self.models,
        }


class DetectionService:
    """Правила + модели. Модель-«решатель» (decision_model) определяет
    итоговое решение, остальные модели только добавляют оценки в отчёт."""

    def __init__(self, config=None, verifier=None, detectors=None, decision_model=None):
        self.config = config or DetectorConfig()
        self.verifier = verifier or DnsVerifier(offline=self.config.dns_offline)
        self.detectors = detectors or {}
        self.decision_model = decision_model or (
            "autoencoder" if "autoencoder" in self.detectors else next(iter(self.detectors), None))

    def run(self, log):
        t0 = time.time()
        rule_results = RuleEngine(default_rules(self.verifier), self.config).run(log)
        t_rules = time.time() - t0

        verdicts = {}
        for ip, records in log.by_ip.items():
            if ip in rule_results.verified:
                continue
            hit = rule_results.hits.get(ip, {"rules": set(), "details": {}})
            verdicts[ip] = IPVerdict(ip, len(records), sorted(hit["rules"]), hit["details"])

        if self.detectors:
            feats = extract_features(log, self.config.min_requests)
            feats = feats[feats.index.isin(list(verdicts))]
            if len(feats):
                for name, det in self.detectors.items():
                    scores = det.score(feats)
                    flags = scores > det.threshold
                    for ip, s, f in zip(feats.index, scores, flags):
                        verdicts[ip].scores[name] = float(s)
                        verdicts[ip].anomalous[name] = bool(f)
                if self.decision_model:
                    explained = self.detectors[self.decision_model].explain(feats)
                    for ip, top in zip(feats.index, explained):
                        verdicts[ip].top_features = top

        for v in verdicts.values():
            strong = set(v.rules) & STRONG_RULES
            if strong:
                v.is_bot, v.reason = True, f"rule{primary_rule(strong)}"
            elif self.decision_model and v.anomalous.get(self.decision_model):
                v.is_bot, v.reason = True, f"model:{self.decision_model}"

        stats = {"lines": log.stats.get("lines", 0), "parsed": log.stats.get("parsed", 0),
                 "skipped": log.stats.get("lines", 0) - log.stats.get("parsed", 0),
                 "seconds_rules": round(t_rules, 2),
                 "seconds_total": round(time.time() - t0, 2)}
        return DetectionReport(verdicts, rule_results, stats, self.config.to_dict(),
                               list(self.detectors))
