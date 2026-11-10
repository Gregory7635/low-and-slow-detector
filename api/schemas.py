"""Pydantic-схемы запросов и ответов REST API."""

from pydantic import BaseModel, Field


class AnalyzeParams(BaseModel):
    decision_model: str | None = Field(None, description="autoencoder или iforest")
    dns_offline: bool = Field(False, description="не обращаться к DNS")
    all_rules: bool = False
    cv_threshold: float = Field(0.15, gt=0, lt=1)
    subnet_window: float = Field(600.0, ge=0)
    subnet_threshold: int = Field(5, ge=2)
    min_requests: int = Field(5, ge=3)


class IPResult(BaseModel):
    ip: str
    requests: int
    rules: list[int]
    details: dict
    scores: dict[str, float]
    anomalous: dict[str, bool]
    top_features: list[str]
    is_bot: bool
    reason: str
    description: str


class Summary(BaseModel):
    lines: int
    parsed: int
    skipped: int
    unique_ips: int
    claimed_search_bots: int
    verified_search_bots_excluded: int
    dns_unknown: int
    suspicious_ips: int
    by_reason: dict[str, int]
    rule_counts: dict[str, int]
    models: list[str]
    seconds_total: float


class AnalysisResponse(BaseModel):
    id: str
    filename: str
    decision_model: str | None = None
    summary: Summary
    thresholds: dict[str, float]
    ips: list[IPResult]


class ModelInfo(BaseModel):
    name: str
    threshold: float
    features: list[str]
    n_train: int | None = None
    val_f1: float | None = None


class Health(BaseModel):
    status: str
    version: str
    models: list[str]


class AnalysisShort(BaseModel):
    id: str
    filename: str
    created_at: str
    decision_model: str | None
    lines: int
    unique_ips: int
    suspicious_ips: int


class IPHistoryItem(BaseModel):
    analysis_id: str
    filename: str
    created_at: str
    requests: int
    rules: list[int]
    is_bot: bool
    reason: str
    description: str
