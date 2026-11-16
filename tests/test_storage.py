from api.schemas import AnalysisResponse
from api.storage import AnalysisRepository

SUMMARY = {"lines": 3, "parsed": 3, "skipped": 0, "unique_ips": 2, "claimed_search_bots": 0,
           "verified_search_bots_excluded": 0, "dns_unknown": 0, "suspicious_ips": 1,
           "by_reason": {"rule5": 1}, "rule_counts": {"5": 1}, "models": ["autoencoder"],
           "seconds_total": 0.1}


def ip(addr, is_bot):
    return {"ip": addr, "requests": 10, "rules": [5] if is_bot else [], "details": {},
            "scores": {"autoencoder": 1.5 if is_bot else 0.01},
            "anomalous": {"autoencoder": is_bot},
            "top_features": ["interval_cv"] if is_bot else [], "is_bot": is_bot,
            "reason": "rule5" if is_bot else "", "description": "x" if is_bot else ""}


def result(rid):
    return AnalysisResponse(id=rid, filename="a.log", decision_model="autoencoder",
                            summary=SUMMARY, thresholds={"autoencoder": 0.5},
                            ips=[ip("1.1.1.1", True), ip("2.2.2.2", False)])


def test_save_get_roundtrip():
    repo = AnalysisRepository(":memory:")
    repo.save(result("a1"), {"dns_offline": True})
    got = repo.get("a1")
    assert got == result("a1")
    assert [i.ip for i in repo.get("a1", only_bots=True).ips] == ["1.1.1.1"]
    assert repo.get("nope") is None


def test_list_history_and_cascade_delete():
    repo = AnalysisRepository(":memory:")
    repo.save(result("a1"), {})
    repo.save(result("a2"), {})
    assert [a.id for a in repo.list()] == ["a2", "a1"]
    assert {h.analysis_id for h in repo.ip_history("1.1.1.1")} == {"a1", "a2"}
    assert repo.delete("a1") and not repo.delete("a1")
    assert [h.analysis_id for h in repo.ip_history("1.1.1.1")] == ["a2"]
