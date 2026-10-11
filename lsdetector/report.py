"""Выгрузка результатов в TXT и JSON."""

import json

from .rules import RULE_NAMES
from .useragent import RULE3_REASONS


def describe(v):
    """Человекочитаемое описание причин для одного IP."""
    parts = []
    for r in v.rules:
        s = RULE_NAMES[r]
        if r == 3:
            s += " (" + "; ".join(RULE3_REASONS[c] for c in v.details["rule3"]) + ")"
        elif r == 5:
            s += f" (CV={v.details['rule5_cv']})"
        elif r == 6:
            s += f" ({v.details['rule6_subnet']})"
        parts.append(s)
    flagged = [f"{name}={v.scores[name]:.3f}" for name, flag in v.anomalous.items() if flag]
    if flagged:
        parts.append(f"аномалия {', '.join(flagged)} (признаки: {', '.join(v.top_features)})")
    return ", ".join(parts)


def write_txt(report, path):
    with open(path, "w", encoding="utf-8") as f:
        for v in sorted(report.bots(), key=lambda v: v.ip):
            f.write(f"{v.ip} - {describe(v)}\n")


def report_to_dict(report, only_bots=False):
    verdicts = report.bots() if only_bots else report.verdicts.values()
    return {"summary": report.summary(), "config": report.config,
            "rule6_subnets": report.rule_results.rule6_report,
            "ips": [v.to_dict() for v in sorted(verdicts, key=lambda v: v.ip)]}


def write_json(report, path, only_bots=False):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report_to_dict(report, only_bots), f, ensure_ascii=False, indent=1)
