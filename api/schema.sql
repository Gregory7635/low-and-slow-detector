-- Схема БД истории анализов (SQLite).
-- Одна запись analyses - один загруженный журнал; ip_results - решения по его IP.

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS analyses (
    id               TEXT PRIMARY KEY,           -- короткий uuid
    filename         TEXT    NOT NULL,
    created_at       TEXT    NOT NULL,           -- ISO 8601, UTC
    decision_model   TEXT,                       -- autoencoder / iforest / NULL
    lines            INTEGER NOT NULL,
    unique_ips       INTEGER NOT NULL,
    suspicious_ips   INTEGER NOT NULL,
    params_json      TEXT    NOT NULL,           -- параметры запуска (AnalyzeParams)
    summary_json     TEXT    NOT NULL,           -- сводка (Summary)
    thresholds_json  TEXT    NOT NULL            -- пороги моделей
);

CREATE TABLE IF NOT EXISTS ip_results (
    analysis_id    TEXT    NOT NULL REFERENCES analyses (id) ON DELETE CASCADE,
    ip             TEXT    NOT NULL,
    requests       INTEGER NOT NULL,
    rules          TEXT    NOT NULL,             -- номера правил через запятую
    is_bot         INTEGER NOT NULL CHECK (is_bot IN (0, 1)),
    reason         TEXT    NOT NULL,             -- rule1 ... / model:autoencoder / ''
    scores_json    TEXT    NOT NULL,             -- {"autoencoder": 0.12, ...}
    anomalous_json TEXT    NOT NULL,
    top_features   TEXT    NOT NULL,             -- признаки через запятую
    description    TEXT    NOT NULL,
    details_json   TEXT    NOT NULL,
    PRIMARY KEY (analysis_id, ip)
);

CREATE INDEX IF NOT EXISTS idx_analyses_created ON analyses (created_at);
CREATE INDEX IF NOT EXISTS idx_ip_results_bot ON ip_results (analysis_id, is_bot);
CREATE INDEX IF NOT EXISTS idx_ip_results_ip ON ip_results (ip);
