"""Командная строка: python -m lsdetector <команда>.

  detect    - найти подозрительные IP (правила + обученные модели)
  train     - обучить модели на журнале с синтетическими ботами и оценить качество
  simulate  - записать журнал с внедрёнными ботами и их разметку
  sample    - сделать небольшой обезличенный фрагмент журнала
"""

import argparse
import csv
import hashlib
import ipaddress
import os
import sys

from .config import DetectorConfig
from .dns_verify import DnsVerifier
from .parser import load_log
from .rules import RULE_NAMES

DEFAULT_MODELS_DIR = os.path.join("models", "pretrained")


def add_config_args(p):
    d = DetectorConfig()
    p.add_argument("--dns-cache", metavar="JSON", default="dns_cache.json",
                   help="файл кэша DNS: повторные прогоны дают те же результаты")
    p.add_argument("--dns-offline", action="store_true", help="не обращаться к DNS")
    p.add_argument("--dns-unknown-as-fake", action="store_true",
                   help="считать IP без ответа DNS поддельными ботами")
    p.add_argument("--all-rules", action="store_true",
                   help="проверять все правила даже при срабатывании правила 1")
    p.add_argument("--whitelist", metavar="FILE", help="CIDR-диапазоны, исключаемые из правила 6")
    p.add_argument("--subnet-window", type=float, default=d.subnet_window,
                   help=f"окно правила 6, с (0 = весь журнал), по умолчанию {d.subnet_window}")
    p.add_argument("--subnet-threshold", type=int, default=d.subnet_ip_threshold)
    p.add_argument("--subnet-prefix", type=int, default=d.subnet_prefix_v4)
    p.add_argument("--cv-threshold", type=float, default=d.rule5_cv_threshold)
    p.add_argument("--min-requests", type=int, default=d.min_requests,
                   help="минимум запросов IP для оценки моделью")


def config_from_args(args):
    whitelist = []
    if args.whitelist:
        with open(args.whitelist, encoding="utf-8") as f:
            whitelist = [s.split("#")[0].strip() for s in f if s.split("#")[0].strip()]
    return DetectorConfig(
        rule5_cv_threshold=args.cv_threshold, subnet_prefix_v4=args.subnet_prefix,
        subnet_ip_threshold=args.subnet_threshold, subnet_window=args.subnet_window,
        rule1_priority=not args.all_rules, dns_unknown_as_fake=args.dns_unknown_as_fake,
        dns_offline=args.dns_offline, min_requests=args.min_requests, whitelist=whitelist)


def load_detectors(models_dir, names=("iforest", "autoencoder")):
    from .models import AnomalyDetector
    dets = {}
    for name in names:
        path = os.path.join(models_dir, f"{name}.joblib")
        if os.path.exists(path):
            dets[name] = AnomalyDetector.load(path)
    return dets


# ---------------------------------------------------------------------------

def cmd_detect(args):
    from .pipeline import DetectionService
    from .report import write_json, write_txt

    config = config_from_args(args)
    verifier = DnsVerifier.from_file(args.dns_cache, offline=config.dns_offline)
    detectors = {} if args.no_ml else load_detectors(args.models_dir)
    if not detectors and not args.no_ml:
        print(f"[внимание] модели не найдены в {args.models_dir}, работают только правила",
              file=sys.stderr)
    service = DetectionService(config, verifier, detectors, args.decision_model)
    report = service.run(load_log(args.logfile))
    verifier.save(args.dns_cache)

    write_txt(report, args.output)
    if args.json:
        write_json(report, args.json, only_bots=not args.json_all)

    s = report.summary()
    print(f"Строк: {s['lines']}, разобрано: {s['parsed']}, уникальных IP: {s['unique_ips']}")
    print(f"Заявленных поисковых ботов: {s['claimed_search_bots']} "
          f"(подтверждено и исключено: {s['verified_search_bots_excluded']}, "
          f"DNS не ответил: {s['dns_unknown']})")
    print(f"Модели: {', '.join(s['models']) or 'нет'}")
    print(f"Подозрительных IP: {s['suspicious_ips']}")
    for reason, n in sorted(s["by_reason"].items(), key=lambda kv: -kv[1]):
        title = (RULE_NAMES[int(reason[4:])] if reason.startswith("rule")
                 else "аномальное поведение (модель)")
        print(f"  {reason:<18} {title:<42} {n:>6}")
    print(f"Время: {s['seconds_total']} с. Результат: {args.output}"
          + (f", {args.json}" if args.json else ""))


def cmd_train(args):
    from .evaluation import METHOD_TITLES, evaluate
    from .rules import RuleEngine, default_rules
    from .simulate import inject_bots
    from .training import build_dataset, train_detector

    config = config_from_args(args)
    verifier = DnsVerifier.from_file(args.dns_cache, offline=config.dns_offline)
    log = load_log(args.logfile)
    sim = inject_bots(log, seed=args.seed)
    print(f"[инфо] внедрено синтетических ботов: {len(sim.bot_ips)}", file=sys.stderr)
    rules = RuleEngine(default_rules(verifier), config).run(sim.log)
    verifier.save(args.dns_cache)
    dataset = build_dataset(sim.log, rules, sim.bot_ips, config)

    os.makedirs(args.models_dir, exist_ok=True)
    detectors = {}
    for name in args.models:
        det = train_detector(dataset, name, config)
        det.save(os.path.join(args.models_dir, f"{name}.joblib"))
        detectors[name] = det
        print(f"{name}: обучено на {det.meta['n_train']} IP, порог {det.threshold:.4f}, "
              f"F1 на validation {det.meta['val_f1']:.3f}")

    res = evaluate(dataset, detectors, args.report_dir)
    print(f"\nТестовая выборка: {res['n_test']} IP, из них ботов {res['n_bots']}")
    print(f"{'метод':<30}{'Precision':>10}{'Recall':>8}{'F1':>8}{'ROC-AUC':>9}")
    for m, v in res["methods"].items():
        auc = f"{v['roc_auc']:.3f}" if "roc_auc" in v else "-"
        print(f"{METHOD_TITLES[m]:<30}{v['precision']:>10.3f}{v['recall']:>8.3f}"
              f"{v['f1']:>8.3f}{auc:>9}")
    print(f"Совпадение с правилами на {res['n_rule_flagged_real']} реальных IP: "
          + ", ".join(f"{k} {v:.1%}" for k, v in res["agreement_with_rules"].items()))
    print(f"Графики и метрики: {args.report_dir}")


def cmd_simulate(args):
    from .simulate import format_record, inject_bots

    sim = inject_bots(load_log(args.logfile), seed=args.seed)
    records = sorted((r for recs in sim.log.by_ip.values() for r in recs), key=lambda r: r.ts)
    with open(args.output, "w", encoding="utf-8", newline="\n") as f:
        for r in records:
            f.write(format_record(r) + "\n")
    with open(args.labels, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["ip", "kind"])
        w.writerows(sorted(sim.bot_ips.items()))
    print(f"Записано {len(records)} строк, ботов: {len(sim.bot_ips)} -> {args.output}, {args.labels}")


def anonymize_ip(ip, salt):
    """Сохраняет структуру подсетей: адреса одной /24 остаются в одной /24."""
    a = ipaddress.ip_address(ip)
    if a.version == 6:
        h = hashlib.sha256((salt + ip).encode()).digest()
        return str(ipaddress.IPv6Address(b"\xfd" + h[:15]))
    net = str(ipaddress.ip_network(f"{ip}/24", strict=False))
    h = hashlib.sha256((salt + net).encode()).digest()
    return f"10.{h[0]}.{h[1]}.{a.packed[3]}"


def cmd_sample(args):
    import random

    from .simulate import format_record

    log = load_log(args.logfile)
    rng = random.Random(args.seed)
    ips = rng.sample(sorted(log.by_ip), min(args.ips, len(log.by_ip)))
    salt = os.urandom(8).hex()
    records = sorted((r._replace(ip=anonymize_ip(r.ip, salt))
                      for ip in ips for r in log.by_ip[ip]), key=lambda r: r.ts)
    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "w", encoding="utf-8", newline="\n") as f:
        for r in records:
            f.write(format_record(r) + "\n")
    print(f"Записано {len(records)} строк от {len(ips)} IP -> {args.output}")


# ---------------------------------------------------------------------------

def build_parser():
    p = argparse.ArgumentParser(prog="lsdetector",
                                description="Детектор low-and-slow ботов по логам Apache")
    sub = p.add_subparsers(dest="command", required=True)

    d = sub.add_parser("detect", help="найти подозрительные IP")
    d.add_argument("logfile")
    d.add_argument("-o", "--output", default="suspicious_ips.txt")
    d.add_argument("--json", metavar="FILE", help="подробный JSON-отчёт")
    d.add_argument("--json-all", action="store_true", help="включить в JSON все IP, а не только ботов")
    d.add_argument("--models-dir", default=DEFAULT_MODELS_DIR)
    d.add_argument("--decision-model", choices=["autoencoder", "iforest"], default=None)
    d.add_argument("--no-ml", action="store_true", help="только правила")
    add_config_args(d)
    d.set_defaults(func=cmd_detect)

    t = sub.add_parser("train", help="обучить модели и оценить качество")
    t.add_argument("logfile")
    t.add_argument("--models", nargs="+", default=["iforest", "autoencoder"],
                   choices=["iforest", "autoencoder"])
    t.add_argument("--models-dir", default=DEFAULT_MODELS_DIR)
    t.add_argument("--report-dir", default=os.path.join("output", "evaluation"))
    t.add_argument("--seed", type=int, default=42)
    add_config_args(t)
    t.set_defaults(func=cmd_train)

    s = sub.add_parser("simulate", help="журнал с внедрёнными синтетическими ботами")
    s.add_argument("logfile")
    s.add_argument("-o", "--output", default="output/simulated.log")
    s.add_argument("--labels", default="output/simulated_labels.csv")
    s.add_argument("--seed", type=int, default=42)
    s.set_defaults(func=cmd_simulate)

    a = sub.add_parser("sample", help="обезличенный фрагмент журнала")
    a.add_argument("logfile")
    a.add_argument("-o", "--output", default="data/sample/access_sample.log")
    a.add_argument("--ips", type=int, default=400, help="сколько IP взять")
    a.add_argument("--seed", type=int, default=1)
    a.set_defaults(func=cmd_sample)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
