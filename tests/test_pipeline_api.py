import os

import pytest
from fastapi.testclient import TestClient

from conftest import ROOT
from lsdetector.cli import load_detectors, main
from lsdetector.pipeline import DetectionService
from lsdetector.simulate import format_record

DEMO_MODELS = os.path.join(ROOT, "models", "demo")


@pytest.fixture(scope="module")
def demo_text(demo):
    records = sorted((r for recs in demo.log.by_ip.values() for r in recs), key=lambda r: r.ts)
    return "\n".join(format_record(r) for r in records) + "\n"


def test_service_rules_only(demo, config):
    report = DetectionService(config).run(demo.log)
    s = report.summary()
    assert s["unique_ips"] == len(demo.log.by_ip)
    assert all(v.reason.startswith("rule") for v in report.bots())


def test_service_with_models_finds_bots(demo, config):
    detectors = load_detectors(DEMO_MODELS)
    assert set(detectors) == {"iforest", "autoencoder"}
    report = DetectionService(config, detectors=detectors).run(demo.log)
    found = {v.ip for v in report.bots()}
    bots = set(demo.bot_ips)
    assert len(found & bots) / len(bots) > 0.8          # полнота
    assert len(found & bots) / len(found) > 0.7         # точность
    v = next(v for v in report.bots() if v.reason == "model:autoencoder")
    assert v.top_features and v.scores["autoencoder"] > 0


def test_cli_detect(tmp_path, demo_text, capsys):
    log = tmp_path / "access.log"
    log.write_text(demo_text, encoding="utf-8")
    out, js = tmp_path / "bots.txt", tmp_path / "bots.json"
    main(["detect", str(log), "-o", str(out), "--json", str(js), "--dns-offline",
          "--models-dir", DEMO_MODELS, "--dns-cache", str(tmp_path / "dns.json")])
    assert "Подозрительных IP" in capsys.readouterr().out
    assert out.read_text(encoding="utf-8").count("\n") > 10
    assert js.exists()


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    import api.main as api_main
    api_main.MODELS_DIR = DEMO_MODELS
    api_main.DB_PATH = str(tmp_path_factory.mktemp("db") / "test.sqlite3")
    api_main.get_detectors.cache_clear()
    api_main.get_repository.cache_clear()
    return TestClient(api_main.app)


def test_api_health_and_models(client):
    assert client.get("/api/health").json()["status"] == "ok"
    models = {m["name"]: m for m in client.get("/api/models").json()}
    assert set(models) == {"iforest", "autoencoder"}
    assert len(models["autoencoder"]["features"]) == 21


def test_api_analyze_flow(client, demo_text):
    r = client.post("/api/analyze", params={"dns_offline": True},
                    files={"file": ("access.log", demo_text.encode(), "text/plain")})
    assert r.status_code == 200
    data = r.json()
    assert data["summary"]["suspicious_ips"] > 0
    bots = [i for i in data["ips"] if i["is_bot"]]
    assert all(i["description"] for i in bots)

    got = client.get(f"/api/analyses/{data['id']}", params={"only_bots": True}).json()
    assert len(got["ips"]) == len(bots)
    dl = client.get(f"/api/analyses/{data['id']}/download")
    assert "attachment" in dl.headers["content-disposition"]

    # результат сохранён в БД целиком
    full = client.get(f"/api/analyses/{data['id']}").json()
    assert full["ips"] == data["ips"] and full["decision_model"] == "autoencoder"
    history = client.get("/api/analyses").json()
    assert history[0]["id"] == data["id"]
    assert history[0]["suspicious_ips"] == data["summary"]["suspicious_ips"]

    bot_ip = bots[0]["ip"]
    items = client.get(f"/api/ips/{bot_ip}").json()
    assert items[0]["analysis_id"] == data["id"] and items[0]["is_bot"]

    assert client.delete(f"/api/analyses/{data['id']}").status_code == 204
    assert client.get(f"/api/analyses/{data['id']}").status_code == 404
    assert client.get(f"/api/ips/{bot_ip}").json() == []
    assert client.delete(f"/api/analyses/{data['id']}").status_code == 404


def test_api_errors(client):
    r = client.post("/api/analyze", params={"dns_offline": True},
                    files={"file": ("x.log", b"not a log\n", "text/plain")})
    assert r.status_code == 422
    assert client.get("/api/analyses/nope").status_code == 404
    r = client.post("/api/analyze", params={"cv_threshold": 5},
                    files={"file": ("x.log", b"x", "text/plain")})
    assert r.status_code == 422


def test_web_page(client):
    r = client.get("/")
    assert r.status_code == 200 and "Детектор" in r.text
    assert client.get("/static/app.js").status_code == 200
