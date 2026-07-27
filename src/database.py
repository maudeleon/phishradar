"""
PhishRadar — Base de datos (SQLite)
Sin ORM, sin magia. SQL directo para que entiendas exactamente qué pasa.
"""

import sqlite3
import logging
from datetime import datetime
from pathlib import Path

from config import DB_PATH

logger = logging.getLogger(__name__)


# ── Esquema ───────────────────────────────────────────────────────────────────

SCHEMA = """
-- Tabla principal: cada URL phishing que encontramos
CREATE TABLE IF NOT EXISTS urls (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    url         TEXT    NOT NULL UNIQUE,
    domain      TEXT    NOT NULL,
    source      TEXT    NOT NULL,           -- openphish | phishtank | manual
    first_seen  TEXT    NOT NULL,           -- ISO-8601
    last_seen   TEXT    NOT NULL,
    is_active   INTEGER NOT NULL DEFAULT 1, -- 1=activo, 0=caído
    brand_hit   TEXT,                       -- marca LATAM detectada (si aplica)
    tld         TEXT,                       -- .com | .gt | .xyz ...
    url_length  INTEGER
);

-- Tabla de ejecuciones: log de cada vez que corremos el colector
CREATE TABLE IF NOT EXISTS runs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at  TEXT NOT NULL,
    finished_at TEXT,
    source      TEXT NOT NULL,
    urls_found  INTEGER DEFAULT 0,
    urls_new    INTEGER DEFAULT 0,
    status      TEXT DEFAULT 'running'     -- running | ok | error
);

-- Índices para búsquedas rápidas
CREATE INDEX IF NOT EXISTS idx_domain    ON urls(domain);
CREATE INDEX IF NOT EXISTS idx_source    ON urls(source);
CREATE INDEX IF NOT EXISTS idx_brand_hit ON urls(brand_hit);
CREATE INDEX IF NOT EXISTS idx_tld       ON urls(tld);
CREATE INDEX IF NOT EXISTS idx_active    ON urls(is_active);
"""


# ── Conexión ──────────────────────────────────────────────────────────────────

def get_connection() -> sqlite3.Connection:
    """Devuelve una conexión con row_factory para acceder por nombre de columna."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")   # escrituras más rápidas
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db() -> None:
    """Crea las tablas si no existen. Seguro llamarlo varias veces."""
    with get_connection() as conn:
        conn.executescript(SCHEMA)
    logger.info(f"Base de datos lista en: {DB_PATH}")


# ── Operaciones de URLs ───────────────────────────────────────────────────────

def insert_urls(urls: list[dict]) -> tuple[int, int]:
    """
    Inserta una lista de URLs.
    Cada dict debe tener: url, domain, source, brand_hit, tld, url_length.
    Devuelve (total_procesadas, nuevas_insertadas).
    """
    now = datetime.utcnow().isoformat()
    new_count = 0

    with get_connection() as conn:
        for item in urls:
            try:
                conn.execute(
                    """
                    INSERT INTO urls (url, domain, source, first_seen, last_seen,
                                      brand_hit, tld, url_length)
                    VALUES (:url, :domain, :source, :first_seen, :last_seen,
                            :brand_hit, :tld, :url_length)
                    """,
                    {**item, "first_seen": now, "last_seen": now},
                )
                new_count += 1
            except sqlite3.IntegrityError:
                # URL ya existe → actualizar last_seen
                conn.execute(
                    "UPDATE urls SET last_seen=?, is_active=1 WHERE url=?",
                    (now, item["url"]),
                )

    logger.info(f"Procesadas: {len(urls)} | Nuevas: {new_count}")
    return len(urls), new_count


def get_stats() -> dict:
    """Devuelve estadísticas rápidas de la base de datos."""
    with get_connection() as conn:
        total     = conn.execute("SELECT COUNT(*) FROM urls").fetchone()[0]
        active    = conn.execute("SELECT COUNT(*) FROM urls WHERE is_active=1").fetchone()[0]
        with_brand= conn.execute("SELECT COUNT(*) FROM urls WHERE brand_hit IS NOT NULL").fetchone()[0]
        by_source = conn.execute(
            "SELECT source, COUNT(*) as n FROM urls GROUP BY source"
        ).fetchall()
        by_tld    = conn.execute(
            "SELECT tld, COUNT(*) as n FROM urls GROUP BY tld ORDER BY n DESC LIMIT 10"
        ).fetchall()
        by_brand  = conn.execute(
            "SELECT brand_hit, COUNT(*) as n FROM urls WHERE brand_hit IS NOT NULL "
            "GROUP BY brand_hit ORDER BY n DESC LIMIT 10"
        ).fetchall()

    return {
        "total":      total,
        "active":     active,
        "with_brand": with_brand,
        "by_source":  [dict(r) for r in by_source],
        "by_tld":     [dict(r) for r in by_tld],
        "by_brand":   [dict(r) for r in by_brand],
    }


# ── Operaciones de Runs ───────────────────────────────────────────────────────

def start_run(source: str) -> int:
    """Registra el inicio de una ejecución. Devuelve el ID del run."""
    with get_connection() as conn:
        cur = conn.execute(
            "INSERT INTO runs (started_at, source) VALUES (?, ?)",
            (datetime.utcnow().isoformat(), source),
        )
        return cur.lastrowid


def finish_run(run_id: int, urls_found: int, urls_new: int, status: str = "ok") -> None:
    """Actualiza el registro del run al terminar."""
    with get_connection() as conn:
        conn.execute(
            """UPDATE runs
               SET finished_at=?, urls_found=?, urls_new=?, status=?
               WHERE id=?""",
            (datetime.utcnow().isoformat(), urls_found, urls_new, status, run_id),
        )
