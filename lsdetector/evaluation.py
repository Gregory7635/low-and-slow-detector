"""Оценка качества: метрики, матрицы ошибок, графики и разбор ошибок."""

import json
import os

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
from sklearn.metrics import (  # noqa: E402
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)

from .features import FEATURE_NAMES  # noqa: E402

METHOD_TITLES = {
    "rules": "Только правила",
    "iforest": "Isolation Forest",
    "autoencoder": "Автоэнкодер (нейросеть)",
    "ocsvm": "One-Class SVM",
    "lof": "Local Outlier Factor",
    "rules+iforest": "Правила + Isolation Forest",
    "rules+autoencoder": "Правила + автоэнкодер",
    "rules+ocsvm": "Правила + One-Class SVM",
    "rules+lof": "Правила + LOF",
}


def binary_metrics(y, pred, scores=None):
    m = {"precision": precision_score(y, pred, zero_division=0),
         "recall": recall_score(y, pred, zero_division=0),
         "f1": f1_score(y, pred, zero_division=0)}
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    m.update(tp=int(tp), fp=int(fp), tn=int(tn), fn=int(fn))
    if scores is not None and len(set(y)) > 1:
        m["roc_auc"] = roc_auc_score(y, scores)
        m["pr_auc"] = average_precision_score(y, scores)
    return {k: (round(float(v), 4) if isinstance(v, float) else v) for k, v in m.items()}


def evaluate(dataset, detectors, out_dir=None):
    """Посчитать метрики всех методов на тестовой выборке.

    Тестовая выборка: синтетические боты (метка 1) и реальные IP, на которых
    не сработало ни одно надёжное правило (метка 0). Реальные IP, найденные
    правилами, отдельно используются для оценки согласованности модели
    с правилами.
    """
    test = dataset.part("test", clean_only=True)
    y = test["label"].to_numpy()
    rules_pred = test["rule_flag"].to_numpy().astype(bool)

    preds, scores = {"rules": rules_pred}, {}
    for name, det in detectors.items():
        scores[name] = det.score(test)
        preds[name] = scores[name] > det.threshold
        preds[f"rules+{name}"] = rules_pred | preds[name]

    results = {"n_test": int(len(test)), "n_bots": int(y.sum()), "methods": {},
               "recall_by_kind": {}, "thresholds": {}}
    for method, pred in preds.items():
        base = method.split("+")[-1]
        s = scores.get(method) if method in scores else None
        results["methods"][method] = binary_metrics(y, pred, s)
        kinds = test.assign(pred=pred)[test["label"] == 1].groupby("kind")["pred"].mean()
        results["recall_by_kind"][method] = {k: round(float(v), 4) for k, v in kinds.items()}
        if base in detectors:
            results["thresholds"][base] = detectors[base].threshold

    # согласованность модели с правилами на реальных IP
    flagged = dataset.part("test")
    flagged = flagged[(flagged["label"] == 0) & (flagged["rule_flag"] == 1)]
    results["agreement_with_rules"] = {
        name: round(float((det.score(flagged) > det.threshold).mean()), 4) if len(flagged) else None
        for name, det in detectors.items()}
    results["n_rule_flagged_real"] = int(len(flagged))

    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
        with open(os.path.join(out_dir, "metrics.json"), "w", encoding="utf-8") as f:
            json.dump(results, f, ensure_ascii=False, indent=2)
        plot_all(test, y, preds, scores, detectors, results, out_dir)
        error_analysis(test, preds, scores, detectors, out_dir)
    return results


# ---------------------------------------------------------------------------
# Графики
# ---------------------------------------------------------------------------

def _grid(n, max_cols, w, h):
    """Сетка графиков: оси по порядку, лишние скрыты."""
    cols = min(n, max_cols)
    rows = -(-n // cols)
    fig, axes = plt.subplots(rows, cols, figsize=(w * cols, h * rows), squeeze=False)
    axes = axes.ravel()
    for ax in axes[n:]:
        ax.set_visible(False)
    return fig, axes[:n]


def _save(fig, out_dir, name):
    fig.tight_layout()
    fig.savefig(os.path.join(out_dir, name), dpi=130)
    plt.close(fig)


def plot_all(test, y, preds, scores, detectors, results, out_dir):
    # ROC и PR кривые
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 4.5))
    for name, s in scores.items():
        fpr, tpr, _ = roc_curve(y, s)
        prec, rec, _ = precision_recall_curve(y, s)
        m = results["methods"][name]
        ax1.plot(fpr, tpr, label=f"{METHOD_TITLES[name]} (AUC={m['roc_auc']:.3f})")
        ax2.plot(rec, prec, label=f"{METHOD_TITLES[name]} (AP={m['pr_auc']:.3f})")
    ax1.plot([0, 1], [0, 1], "--", color="grey", lw=1)
    ax1.set(xlabel="Доля ложных срабатываний (FPR)", ylabel="Полнота (TPR)", title="ROC-кривая")
    ax2.set(xlabel="Полнота (Recall)", ylabel="Точность (Precision)", title="PR-кривая")
    for ax in (ax1, ax2):
        ax.legend(loc="lower right" if ax is ax1 else "lower left", fontsize=8)
        ax.grid(alpha=0.3)
    _save(fig, out_dir, "roc_pr.png")

    # матрицы ошибок
    fig, axes = _grid(len(preds), 5, 3.3, 3.4)
    for ax, (name, pred) in zip(axes, preds.items()):
        cm = confusion_matrix(y, pred, labels=[0, 1])
        ax.imshow(cm, cmap="Blues")
        for (i, j), v in np.ndenumerate(cm):
            ax.text(j, i, str(v), ha="center", va="center",
                    color="white" if v > cm.max() / 2 else "black", fontsize=12)
        ax.set_xticks([0, 1], ["человек", "бот"])
        ax.set_yticks([0, 1], ["человек", "бот"])
        ax.set(xlabel="Предсказание", ylabel="Истина")
        ax.set_title(METHOD_TITLES[name], fontsize=9)
    _save(fig, out_dir, "confusion_matrices.png")

    # распределение оценок
    fig, axes = _grid(len(scores), 2, 5.5, 4)
    for ax, (name, s) in zip(axes, scores.items()):
        log_scale = name == "autoencoder"   # ошибка восстановления - на порядки
        bins = (np.geomspace(max(s.min(), 1e-6), s.max(), 50) if log_scale
                else np.histogram_bin_edges(s, bins=50))
        ax.hist(s[y == 0], bins=bins, alpha=0.6, label="реальные IP", density=True)
        ax.hist(s[y == 1], bins=bins, alpha=0.6, label="синтетические боты", density=True)
        ax.axvline(detectors[name].threshold, color="red", ls="--", label="порог")
        ax.set(title=METHOD_TITLES[name], xlabel="Оценка аномальности", ylabel="Плотность")
        if log_scale:
            ax.set_xscale("log")
        ax.legend(fontsize=8)
    _save(fig, out_dir, "score_distribution.png")

    # сравнение методов
    methods = list(results["methods"])
    fig, ax = plt.subplots(figsize=(max(9, 1.2 * len(methods)), 4.5))
    width = 0.27
    for k, metric in enumerate(("precision", "recall", "f1")):
        vals = [results["methods"][m][metric] for m in methods]
        ax.bar(np.arange(len(methods)) + (k - 1) * width, vals, width, label=metric)
    ax.set_xticks(range(len(methods)), [METHOD_TITLES[m] for m in methods], rotation=25,
                  ha="right", fontsize=8)
    ax.set_ylim(0, 1.05)
    ax.set_title("Сравнение методов на тестовой выборке")
    ax.legend()
    ax.grid(axis="y", alpha=0.3)
    _save(fig, out_dir, "methods_comparison.png")

    # обучение автоэнкодера
    ae = detectors.get("autoencoder")
    if ae is not None and ae.model.history["train_loss"]:
        fig, ax = plt.subplots(figsize=(6, 4))
        ax.plot(ae.model.history["train_loss"], label="train")
        ax.plot(ae.model.history["val_loss"], label="validation")
        ax.set(xlabel="Эпоха", ylabel="MSE", title="Обучение автоэнкодера", yscale="log")
        ax.legend()
        ax.grid(alpha=0.3)
        _save(fig, out_dir, "autoencoder_loss.png")

        # средняя ошибка восстановления по признакам: боты против людей
        err = ae.model.feature_contributions(ae._transform(test))
        df = pd.DataFrame(err, columns=FEATURE_NAMES)
        comp = pd.DataFrame({"реальные IP": df[y == 0].mean(), "боты": df[y == 1].mean()})
        comp = comp.sort_values("боты")
        fig, ax = plt.subplots(figsize=(7, 6))
        comp.plot.barh(ax=ax)
        ax.set(xlabel="Средняя ошибка восстановления", title="Вклад признаков (автоэнкодер)")
        _save(fig, out_dir, "autoencoder_feature_errors.png")


def error_analysis(test, preds, scores, detectors, out_dir):
    """Сохранить ложные срабатывания и пропуски каждой модели в CSV."""
    rows = []
    for name, det in detectors.items():
        pred = preds[name]
        top = det.explain(test)
        for i, ip in enumerate(test.index):
            y = test["label"].iloc[i]
            if bool(pred[i]) != bool(y):
                rows.append({"model": name, "ip": ip, "error": "FP" if pred[i] else "FN",
                             "kind": test["kind"].iloc[i], "score": scores[name][i],
                             "threshold": det.threshold, "top_features": ", ".join(top[i]),
                             **test.iloc[i][FEATURE_NAMES].round(3).to_dict()})
    pd.DataFrame(rows).to_csv(os.path.join(out_dir, "errors.csv"), index=False,
                              encoding="utf-8-sig")
