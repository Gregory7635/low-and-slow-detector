"""REST API детектора и раздача веб-страницы.

Запуск:  uvicorn api.main:app --reload
Документация Swagger: http://127.0.0.1:8000/docs
"""

import os
import threading
import uuid
from functools import lru_cache

from fastapi import Depends, FastAPI, File, HTTPException, Query, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from lsdetector import __version__
from lsdetector.cli import DEFAULT_MODELS_DIR, load_detectors
from lsdetector.config import DetectorConfig
from lsdetector.dns_verify import DnsVerifier
from lsdetector.parser import normalize_ip, parse_lines
from lsdetector.pipeline import DetectionService
from lsdetector.report import describe

from .schemas import (
    AnalysisResponse,
    AnalysisShort,
    AnalyzeParams,
    Health,
    IPHistoryItem,
    IPResult,
    ModelInfo,
)
from .storage import AnalysisRepository

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WEB_DIR = os.path.join(ROOT, "web")
MODELS_DIR = os.environ.get("LSD_MODELS_DIR", os.path.join(ROOT, DEFAULT_MODELS_DIR))
DNS_CACHE = os.environ.get("LSD_DNS_CACHE", os.path.join(ROOT, "dns_cache.json"))
DB_PATH = os.environ.get("LSD_DB", os.path.join(ROOT, "output", "lsdetector.sqlite3"))

app = FastAPI(title="Детектор low-and-slow ботов", version=__version__,
              description="Поиск медленных ботов в журналах Apache: правила + ML")


_dns_lock = threading.Lock()


@lru_cache(maxsize=1)
def get_repository():
    """Одно соединение с БД на процесс."""
    return AnalysisRepository(DB_PATH)


@lru_cache(maxsize=1)
def get_detectors():
    """Модели загружаются один раз при первом обращении."""
    return load_detectors(MODELS_DIR)


def analyze_text(text, filename, params: AnalyzeParams, detectors):
    config = DetectorConfig(
        rule5_cv_threshold=params.cv_threshold, subnet_window=params.subnet_window,
        subnet_ip_threshold=params.subnet_threshold, min_requests=params.min_requests,
        rule1_priority=not params.all_rules, dns_offline=params.dns_offline)
    if params.decision_model and params.decision_model not in detectors:
        raise HTTPException(400, f"модель {params.decision_model!r} не загружена")
    log = parse_lines(text.splitlines())
    if not log.by_ip:
        raise HTTPException(422, "в файле нет строк в формате Apache combined")
    with _dns_lock:   # кэш DNS общий для всех запросов
        verifier = DnsVerifier.from_file(DNS_CACHE, offline=params.dns_offline)
        service = DetectionService(config, verifier, detectors, params.decision_model)
        report = service.run(log)
        if not params.dns_offline:
            verifier.save(DNS_CACHE)
    ips = [IPResult(**v.to_dict(), description=describe(v))
           for v in sorted(report.verdicts.values(), key=lambda v: v.ip)]
    return AnalysisResponse(id=uuid.uuid4().hex[:12], filename=filename,
                            decision_model=service.decision_model,
                            summary=report.summary(),
                            thresholds={k: d.threshold for k, d in detectors.items()},
                            ips=ips)


@app.get("/api/health", response_model=Health)
def health(detectors=Depends(get_detectors)):
    return Health(status="ok", version=__version__, models=list(detectors))


@app.get("/api/models", response_model=list[ModelInfo])
def models(detectors=Depends(get_detectors)):
    return [ModelInfo(name=k, threshold=d.threshold, features=d.feature_names,
                      n_train=d.meta.get("n_train"), val_f1=d.meta.get("val_f1"))
            for k, d in detectors.items()]


@app.post("/api/analyze", response_model=AnalysisResponse)
def analyze(file: UploadFile = File(..., description="журнал Apache combined"),
            params: AnalyzeParams = Depends(), detectors=Depends(get_detectors),
            repo=Depends(get_repository)):
    text = file.file.read().decode("utf-8", errors="replace")
    result = analyze_text(text, file.filename or "access.log", params, detectors)
    repo.save(result, params.model_dump())
    return result


@app.get("/api/analyses", response_model=list[AnalysisShort])
def list_analyses(limit: int = Query(50, ge=1, le=500), repo=Depends(get_repository)):
    return repo.list(limit)


@app.get("/api/analyses/{analysis_id}", response_model=AnalysisResponse)
def get_analysis(analysis_id: str, only_bots: bool = False, repo=Depends(get_repository)):
    result = repo.get(analysis_id, only_bots)
    if result is None:
        raise HTTPException(404, "анализ не найден")
    return result


@app.delete("/api/analyses/{analysis_id}", status_code=204)
def delete_analysis(analysis_id: str, repo=Depends(get_repository)):
    if not repo.delete(analysis_id):
        raise HTTPException(404, "анализ не найден")


@app.get("/api/analyses/{analysis_id}/download")
def download(analysis_id: str, repo=Depends(get_repository)):
    result = get_analysis(analysis_id, only_bots=True, repo=repo)
    return JSONResponse(result.model_dump(), headers={
        "Content-Disposition": f'attachment; filename="bots_{analysis_id}.json"'})


@app.get("/api/ips/{ip}", response_model=list[IPHistoryItem])
def ip_history(ip: str, repo=Depends(get_repository)):
    """История решений по одному IP во всех сохранённых анализах."""
    return repo.ip_history(normalize_ip(ip) or ip)


@app.get("/", include_in_schema=False)
def index():
    return FileResponse(os.path.join(WEB_DIR, "index.html"))


app.mount("/static", StaticFiles(directory=WEB_DIR), name="static")
