"""Подготовка выборок, обучение моделей и подбор порога."""

import time
from dataclasses import dataclass

import numpy as np
import pandas as pd
from sklearn.metrics import precision_recall_curve
from sklearn.model_selection import train_test_split

from .features import FEATURE_NAMES, extract_features
from .models import AnomalyDetector, create_model
from .rules import STRONG_RULES


@dataclass
class Dataset:
    """Признаки IP с разметкой.

    label      - 1 для синтетических ботов, 0 для реальных IP;
    rule_flag  - сработало ли надёжное правило (1, 3, 5, 6);
    kind       - тип синтетического бота или 'real';
    split      - train / val / test.
    """
    frame: pd.DataFrame

    def part(self, split, clean_only=False):
        df = self.frame[self.frame["split"] == split]
        if clean_only:
            # «чистые» - реальные IP, на которых не сработало ни одно надёжное
            # правило: на них измеряются ложные срабатывания
            df = df[(df["label"] == 1) | (df["rule_flag"] == 0)]
        return df

    def normal_train(self):
        df = self.part("train")
        return df[(df["label"] == 0) & (df["rule_flag"] == 0)]


def _split(index, strata, labels, test_size, seed):
    """train_test_split со стратификацией, устойчивый к маленьким группам.

    Редкие группы (на маленьких журналах) объединяются по метке; если и
    этого мало, разбиение делается без стратификации.
    """
    s = strata[index]
    s = s.where(s.map(s.value_counts()) >= 5, labels[index].astype(str))
    if s.value_counts().min() < 2:
        s = None
    return train_test_split(index, test_size=test_size, stratify=s, random_state=seed)


def build_dataset(log, rule_results, bot_ips, config, val_size=0.2, test_size=0.2):
    feats = extract_features(log, config.min_requests)
    df = feats.copy()
    df["label"] = df.index.isin(list(bot_ips)).astype(int)
    df["kind"] = [bot_ips.get(ip, "real") for ip in df.index]
    df["rule_flag"] = [int(bool(rule_results.rules_of(ip) & STRONG_RULES)) for ip in df.index]
    df["rules"] = ["+".join(map(str, sorted(rule_results.rules_of(ip)))) for ip in df.index]
    # стратификация по типу: в каждой выборке есть все виды ботов
    strata = df["kind"] + "_" + df["rule_flag"].astype(str)
    idx_train, idx_rest = _split(df.index, strata, df["label"], val_size + test_size,
                                 config.random_state)
    idx_val, idx_test = _split(idx_rest, strata, df["label"],
                               test_size / (val_size + test_size), config.random_state)
    df["split"] = "train"
    df.loc[idx_val, "split"] = "val"
    df.loc[idx_test, "split"] = "test"
    return Dataset(df)


def best_f1_threshold(y_true, scores):
    """Порог, при котором F1 на выборке максимален.

    precision_recall_curve считает ботами IP с оценкой >= thr, а детектор -
    с оценкой > порога. Поэтому порог ставится посередине между thr и
    ближайшей меньшей оценкой: сам IP с оценкой thr остаётся ботом.
    """
    scores = np.asarray(scores, dtype=float)
    prec, rec, thr = precision_recall_curve(y_true, scores)
    f1 = 2 * prec * rec / np.maximum(prec + rec, 1e-12)
    i = int(np.nanargmax(f1[:-1]))   # последняя точка кривой без порога
    lower = scores[scores < thr[i]]
    threshold = (thr[i] + lower.max()) / 2 if len(lower) else thr[i] - 1e-9
    return float(threshold), float(f1[i])


def train_detector(dataset, model_name, config, **model_params):
    """Обучить модель на чистых train-IP и подобрать порог на validation."""
    model_params.setdefault("random_state", config.random_state)
    det = AnomalyDetector(create_model(model_name, **model_params), FEATURE_NAMES)
    normal = dataset.normal_train()
    t0 = time.perf_counter()
    det.fit(normal)
    fit_seconds = time.perf_counter() - t0
    val = dataset.part("val", clean_only=True)
    det.threshold, val_f1 = best_f1_threshold(val["label"], det.score(val))
    det.meta = {"val_f1": val_f1, "n_train": len(normal), "n_val": len(val),
                "fit_seconds": round(fit_seconds, 2), "config": config.to_dict()}
    return det
