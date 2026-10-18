import numpy as np
import pytest

from lsdetector.dns_verify import DnsVerifier
from lsdetector.evaluation import evaluate
from lsdetector.features import FEATURE_NAMES, extract_features, interval_stats, is_static
from lsdetector.models import AnomalyDetector, create_model
from lsdetector.rules import RuleEngine, default_rules
from lsdetector.training import best_f1_threshold, build_dataset, train_detector


@pytest.fixture(scope="module")
def dataset(demo):
    from lsdetector.config import DetectorConfig
    config = DetectorConfig(dns_offline=True)
    rules = RuleEngine(default_rules(DnsVerifier(offline=True)), config).run(demo.log)
    return build_dataset(demo.log, rules, demo.bot_ips, config), config


def test_is_static():
    assert is_static("/img/1.webp") and is_static("/fonts/a.woff2?v=1")
    assert not is_static("/product/123")


def test_interval_stats_regular():
    n, med, cv, entropy, max_gap = interval_stats([0, 60, 120, 180, 240])
    assert (n, med, cv, entropy) == (5, 60, 0, 0)
    assert max_gap == pytest.approx(0.25)


def test_extract_features_shape(demo):
    X = extract_features(demo.log, min_requests=5)
    assert list(X.columns) == FEATURE_NAMES
    assert not X.isna().any().any()
    assert all(len(demo.log.by_ip[ip]) >= 5 for ip in X.index)


def test_bots_have_no_static(demo):
    X = extract_features(demo.log)
    timers = [ip for ip, k in demo.bot_ips.items() if k == "timer" and ip in X.index]
    assert X.loc[timers, "static_share"].max() == 0


def test_dataset_split(dataset):
    ds, _ = dataset
    f = ds.frame
    assert set(f["split"]) == {"train", "val", "test"}
    assert f.loc[f["split"] == "test", "label"].sum() > 0
    normal = ds.normal_train()
    assert (normal["label"] == 0).all() and (normal["rule_flag"] == 0).all()


def test_best_f1_threshold():
    thr, f1 = best_f1_threshold(np.array([0, 0, 1, 1]), np.array([0.1, 0.2, 0.8, 0.9]))
    assert f1 == 1.0 and 0.2 < thr <= 0.8


def test_unknown_model():
    with pytest.raises(ValueError):
        create_model("svm")


@pytest.mark.parametrize("name, params", [
    ("iforest", {"n_estimators": 50}),
    ("autoencoder", {"epochs": 40, "patience": 10}),
])
def test_train_save_load(dataset, tmp_path, name, params):
    ds, config = dataset
    det = train_detector(ds, name, config, **params)
    test = ds.part("test", clean_only=True)
    scores = det.score(test)
    # боты в среднем аномальнее людей
    assert scores[test["label"] == 1].mean() > scores[test["label"] == 0].mean()

    path = tmp_path / f"{name}.joblib"
    det.save(path)
    loaded = AnomalyDetector.load(path)
    assert loaded.threshold == det.threshold
    np.testing.assert_allclose(loaded.score(test), scores, rtol=1e-5)
    assert len(loaded.explain(test.head(3))[0]) == 3


def test_evaluate_writes_report(dataset, tmp_path):
    ds, config = dataset
    det = train_detector(ds, "iforest", config, n_estimators=50)
    res = evaluate(ds, {"iforest": det}, str(tmp_path))
    assert {"rules", "iforest", "rules+iforest"} <= set(res["methods"])
    m = res["methods"]["rules+iforest"]
    assert m["recall"] >= res["methods"]["rules"]["recall"]
    for name in ("metrics.json", "roc_pr.png", "confusion_matrices.png", "errors.csv"):
        assert (tmp_path / name).exists()
