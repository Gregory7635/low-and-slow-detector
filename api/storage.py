"""Хранение истории анализов в SQLite (слой доступа к данным).

SQLite выбрана, потому что встроена в Python, не требует отдельного
сервера и полностью покрывает нагрузку одного администратора. Схема -
в schema.sql; переход на PostgreSQL потребует только другой реализации
этого класса.
"""

import json
import os
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone

from .schemas import AnalysisResponse, AnalysisShort, IPHistoryItem, IPResult

SCHEMA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "schema.sql")


class AnalysisRepository:
    def __init__(self, path):
        self.path = path
        if path != ":memory:":
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        self._lock = threading.Lock()
        # check_same_thread=False: FastAPI выполняет обработчики в пуле потоков,
        # доступ к соединению сериализуется блокировкой
        # timeout - ждать освобождения БД, если пишет другой процесс (uvicorn --workers)
        self._conn = sqlite3.connect(path, check_same_thread=False, timeout=30)
        self._conn.row_factory = sqlite3.Row
        if path != ":memory:":
            # WAL: читатели не блокируют писателя, запись из разных процессов по очереди
            self._conn.execute("PRAGMA journal_mode = WAL")
        with open(SCHEMA, encoding="utf-8") as f:
            self._conn.executescript(f.read())

    @contextmanager
    def _tx(self):
        with self._lock:
            self._conn.execute("PRAGMA foreign_keys = ON")
            try:
                yield self._conn
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise

    def save(self, result: AnalysisResponse, params: dict):
        s = result.summary
        with self._tx() as c:
            c.execute(
                "INSERT INTO analyses VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (result.id, result.filename,
                 datetime.now(timezone.utc).isoformat(timespec="seconds"),
                 result.decision_model, s.lines, s.unique_ips, s.suspicious_ips,
                 json.dumps(params, ensure_ascii=False),
                 s.model_dump_json(), json.dumps(result.thresholds)))
            c.executemany(
                "INSERT INTO ip_results VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                [(result.id, i.ip, i.requests, ",".join(map(str, i.rules)), int(i.is_bot),
                  i.reason, json.dumps(i.scores), json.dumps(i.anomalous),
                  ",".join(i.top_features), i.description,
                  json.dumps(i.details, ensure_ascii=False)) for i in result.ips])

    @staticmethod
    def _ip(row):
        return IPResult(
            ip=row["ip"], requests=row["requests"],
            rules=[int(x) for x in row["rules"].split(",") if x],
            details=json.loads(row["details_json"]), scores=json.loads(row["scores_json"]),
            anomalous=json.loads(row["anomalous_json"]),
            top_features=[x for x in row["top_features"].split(",") if x],
            is_bot=bool(row["is_bot"]), reason=row["reason"], description=row["description"])

    def get(self, analysis_id, only_bots=False):
        with self._tx() as c:
            a = c.execute("SELECT * FROM analyses WHERE id = ?", (analysis_id,)).fetchone()
            if a is None:
                return None
            sql = "SELECT * FROM ip_results WHERE analysis_id = ?"
            if only_bots:
                sql += " AND is_bot = 1"
            rows = c.execute(sql + " ORDER BY ip", (analysis_id,)).fetchall()
        return AnalysisResponse(id=a["id"], filename=a["filename"],
                                decision_model=a["decision_model"],
                                summary=json.loads(a["summary_json"]),
                                thresholds=json.loads(a["thresholds_json"]),
                                ips=[self._ip(r) for r in rows])

    def list(self, limit=50):
        with self._tx() as c:
            rows = c.execute(
                "SELECT id, filename, created_at, decision_model, lines, unique_ips, "
                "suspicious_ips FROM analyses ORDER BY created_at DESC, rowid DESC LIMIT ?",
                (limit,)).fetchall()
        return [AnalysisShort(**dict(r)) for r in rows]

    def ip_history(self, ip):
        """Решения по одному IP во всех сохранённых анализах."""
        with self._tx() as c:
            rows = c.execute(
                "SELECT a.id, a.filename, a.created_at, r.requests, r.rules, r.is_bot, "
                "r.reason, r.description FROM ip_results r JOIN analyses a "
                "ON a.id = r.analysis_id WHERE r.ip = ? ORDER BY a.created_at DESC",
                (ip,)).fetchall()
        return [IPHistoryItem(analysis_id=r["id"], filename=r["filename"],
                              created_at=r["created_at"], requests=r["requests"],
                              rules=[int(x) for x in r["rules"].split(",") if x],
                              is_bot=bool(r["is_bot"]), reason=r["reason"],
                              description=r["description"]) for r in rows]

    def delete(self, analysis_id):
        with self._tx() as c:
            return c.execute("DELETE FROM analyses WHERE id = ?", (analysis_id,)).rowcount > 0
