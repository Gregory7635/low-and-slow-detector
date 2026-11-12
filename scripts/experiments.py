"""Эксперименты для обоснования выбора модели и гиперпараметров.

1. Сравнение моделей (Isolation Forest, автоэнкодер, One-Class SVM, LOF)
   на нескольких вариантах внедрения синтетических ботов (разные seed):
   среднее и разброс метрик, время обучения и оценки, размер модели.
2. Подбор архитектуры автоэнкодера по F1 на validation.

Запуск:  python scripts/experiments.py access.log --out docs/experiments
Результат: CSV-таблицы и experiments.md с готовыми таблицами.
"""

import argparse
import itertools
import os
import sys
import tempfile
import time

import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lsdetector.config import DetectorConfig  # noqa: E402
from lsdetector.dns_verify import DnsVerifier  # noqa: E402
from lsdetector.evaluation import METHOD_TITLES, binary_metrics  # noqa: E402
from lsdetector.parser import load_log  # noqa: E402
from lsdetector.rules import RuleEngine, default_rules  # noqa: E402
from lsdetector.simulate import inject_bots  # noqa: E402
from lsdetector.training import build_dataset, train_detector  # noqa: E402

MODELS = ["iforest", "autoencoder", "ocsvm", "lof"]
AE_GRID = {
    "hidden": [(16, 8), (32, 16), (64, 32)],
    "latent": [3, 6, 10],
    "dropout": [0.0, 0.1],
}


def make_dataset(log, verifier, config, seed):
    sim = inject_bots(log, seed=seed)
    rules = RuleEngine(default_rules(verifier), config).run(sim.log)
    return build_dataset(sim.log, rules, sim.bot_ips, config)


def test_metrics(det, dataset):
    test = dataset.part("test", clean_only=True)
    t0 = time.perf_counter()
    scores = det.score(test)
    score_ms = (time.perf_counter() - t0) * 1000
    m = binary_metrics(test["label"].to_numpy(), scores > det.threshold, scores)
    hybrid = (scores > det.threshold) | test["rule_flag"].to_numpy().astype(bool)
    m["hybrid_f1"] = binary_metrics(test["label"].to_numpy(), hybrid)["f1"]
    m["score_ms_per_1000"] = round(score_ms / len(test) * 1000, 2)
    return m


def model_size_kb(det):
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "m.joblib")
        det.save(path)
        return round(os.path.getsize(path) / 1024, 1)


def compare_models(log, verifier, config, seeds):
    rows = []
    for seed in seeds:
        ds = make_dataset(log, verifier, config, seed)
        for name in MODELS:
            det = train_detector(ds, name, config)
            m = test_metrics(det, ds)
            rows.append({"seed": seed, "model": name, "fit_s": det.meta["fit_seconds"],
                         "size_kb": model_size_kb(det), **m})
            print(f"seed={seed} {name:<12} F1={m['f1']:.3f} AUC={m['roc_auc']:.3f}",
                  file=sys.stderr)
    return pd.DataFrame(rows)


def tune_autoencoder(log, verifier, config, seed):
    ds = make_dataset(log, verifier, config, seed)
    rows = []
    for hidden, latent, dropout in itertools.product(*AE_GRID.values()):
        det = train_detector(ds, "autoencoder", config, hidden=hidden, latent=latent,
                             dropout=dropout)
        m = test_metrics(det, ds)
        rows.append({"hidden": "-".join(map(str, hidden)), "latent": latent,
                     "dropout": dropout, "val_f1": round(det.meta["val_f1"], 4),
                     "epochs": len(det.model.history["val_loss"]),
                     "test_f1": m["f1"], "test_roc_auc": m["roc_auc"]})
        print(f"AE {hidden} latent={latent} dropout={dropout}: val F1={det.meta['val_f1']:.3f}",
              file=sys.stderr)
    return pd.DataFrame(rows).sort_values("val_f1", ascending=False)


def to_markdown(df):
    cols = list(df.columns)
    lines = ["| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
    for _, r in df.iterrows():
        lines.append("| " + " | ".join(str(r[c]) for c in cols) + " |")
    return "\n".join(lines)


def summarize(cmp):
    agg = cmp.groupby("model").agg(
        precision=("precision", "mean"), recall=("recall", "mean"),
        f1=("f1", "mean"), f1_std=("f1", "std"), roc_auc=("roc_auc", "mean"),
        roc_auc_std=("roc_auc", "std"), hybrid_f1=("hybrid_f1", "mean"),
        fit_s=("fit_s", "mean"), score_ms_per_1000=("score_ms_per_1000", "mean"),
        size_kb=("size_kb", "mean"))
    agg = agg.reindex(MODELS)
    out = pd.DataFrame({
        "Модель": [METHOD_TITLES[m] for m in agg.index],
        "Precision": agg["precision"].round(3),
        "Recall": agg["recall"].round(3),
        "F1": [f"{a:.3f} ± {b:.3f}" for a, b in zip(agg["f1"], agg["f1_std"])],
        "ROC-AUC": [f"{a:.3f} ± {b:.3f}" for a, b in zip(agg["roc_auc"], agg["roc_auc_std"])],
        "F1 с правилами": agg["hybrid_f1"].round(3),
        "Обучение, с": agg["fit_s"].round(2),
        "Оценка 1000 IP, мс": agg["score_ms_per_1000"].round(1),
        "Размер, КБ": agg["size_kb"].round(0).astype(int),
    })
    return out


def main():
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("logfile")
    p.add_argument("--out", default="docs/experiments")
    p.add_argument("--seeds", type=int, nargs="+", default=[1, 2, 3, 4, 5])
    p.add_argument("--dns-cache", default="dns_cache.json")
    args = p.parse_args()

    os.makedirs(args.out, exist_ok=True)
    config = DetectorConfig()
    verifier = DnsVerifier.from_file(args.dns_cache)
    log = load_log(args.logfile)

    cmp = compare_models(log, verifier, config, args.seeds)
    cmp.to_csv(os.path.join(args.out, "model_comparison.csv"), index=False)
    tune = tune_autoencoder(log, verifier, config, seed=42)
    tune.to_csv(os.path.join(args.out, "autoencoder_tuning.csv"), index=False)

    with open(os.path.join(args.out, "experiments.md"), "w", encoding="utf-8") as f:
        f.write(f"## Сравнение моделей ({len(args.seeds)} вариантов внедрения ботов, "
                f"среднее ± ст. отклонение)\n\n{to_markdown(summarize(cmp))}\n\n")
        f.write("## Подбор архитектуры автоэнкодера (seed = 42, сортировка по F1 "
                f"на validation)\n\n{to_markdown(tune)}\n")
    print(open(os.path.join(args.out, "experiments.md"), encoding="utf-8").read())


if __name__ == "__main__":
    np.set_printoptions(precision=4)
    main()
