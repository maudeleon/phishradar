"""
PhishRadar — Base de datos en la nube (Supabase/PostgreSQL)
Sincroniza datos entre SQLite local y PostgreSQL en la nube.
El dashboard público lee desde Supabase.
"""

import os
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

# URL de conexión desde variable de entorno
def _get_db_url():
    """Busca la URL de Supabase en variables de entorno o en Streamlit secrets."""
    url = os.environ.get("SUPABASE_DB_URL")
    if url:
        return url
    try:
        import streamlit as st
        return st.secrets.get("SUPABASE_DB_URL")
    except Exception:
        return None

DB_URL = _get_db_url()


# ── Esquema ───────────────────────────────────────────────────────────────────

SCHEMA = """
CREATE TABLE IF NOT EXISTS urls (
    id          SERIAL PRIMARY KEY,
    url         TEXT NOT NULL UNIQUE,
    domain      TEXT NOT NULL,
    source      TEXT NOT NULL,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    is_active   INTEGER NOT NULL DEFAULT 1,
    brand_hit   TEXT,
    tld         TEXT,
    url_length  INTEGER
);

CREATE INDEX IF NOT EXISTS idx_domain    ON urls(domain);
CREATE INDEX IF NOT EXISTS idx_source    ON urls(source);
CREATE INDEX IF NOT EXISTS idx_brand_hit ON urls(brand_hit);
CREATE INDEX IF NOT EXISTS idx_tld       ON urls(tld);
CREATE INDEX IF NOT EXISTS idx_active    ON urls(is_active);
"""


def get_connection():
    """Devuelve conexión a Supabase PostgreSQL."""
    try:
        import psycopg2
        import psycopg2.extras
        conn = psycopg2.connect(DB_URL)
        return conn
    except Exception as e:
        logger.error(f"Error conectando a Supabase: {e}")
        raise


def is_available() -> bool:
    """Verifica si Supabase está configurado y accesible."""
    if not DB_URL:
        return False
    try:
        conn = get_connection()
        conn.close()
        return True
    except Exception:
        return False


def init_cloud_db() -> None:
    """Crea las tablas en Supabase si no existen."""
    if not DB_URL:
        logger.warning("SUPABASE_DB_URL no configurado — saltando init cloud")
        return
    try:
        conn = get_connection()
        with conn.cursor() as cur:
            cur.execute(SCHEMA)
        conn.commit()
        conn.close()
        logger.info("Base de datos en la nube inicializada correctamente")
    except Exception as e:
        logger.error(f"Error inicializando Supabase: {e}")


def sync_urls(urls: list[dict]) -> tuple[int, int]:
    """
    Sincroniza URLs a Supabase.
    Devuelve (total, nuevas).
    """
    if not DB_URL:
        return 0, 0

    now = datetime.utcnow().isoformat()
    new_count = 0

    try:
        conn = get_connection()
        with conn.cursor() as cur:
            for item in urls:
                try:
                    cur.execute(
                        """
                        INSERT INTO urls (url, domain, source, first_seen, last_seen,
                                          brand_hit, tld, url_length)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (url) DO UPDATE SET last_seen=%s, is_active=1
                        """,
                        (
                            item["url"], item["domain"], item["source"],
                            now, now, item.get("brand_hit"),
                            item.get("tld"), item.get("url_length"),
                            now,
                        ),
                    )
                    if cur.rowcount > 0:
                        new_count += 1
                except Exception as e:
                    logger.debug(f"Error insertando URL: {e}")
                    continue

        conn.commit()
        conn.close()
        logger.info(f"Supabase sync: {len(urls)} procesadas | {new_count} nuevas")

    except Exception as e:
        logger.error(f"Error sincronizando con Supabase: {e}")

    return len(urls), new_count


def get_cloud_stats() -> dict:
    """Estadísticas desde Supabase para el dashboard público."""
    if not DB_URL:
        return {}

    try:
        conn = get_connection()
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM urls")
            total = cur.fetchone()[0]

            cur.execute("SELECT COUNT(*) FROM urls WHERE is_active=1")
            active = cur.fetchone()[0]

            cur.execute("SELECT COUNT(*) FROM urls WHERE brand_hit IS NOT NULL")
            with_brand = cur.fetchone()[0]

            cur.execute(
                "SELECT source, COUNT(*) as n FROM urls GROUP BY source"
            )
            by_source = [{"source": r[0], "n": r[1]} for r in cur.fetchall()]

            cur.execute(
                "SELECT tld, COUNT(*) as n FROM urls GROUP BY tld ORDER BY n DESC LIMIT 10"
            )
            by_tld = [{"tld": r[0], "n": r[1]} for r in cur.fetchall()]

            cur.execute(
                """SELECT brand_hit, COUNT(*) as n FROM urls
                   WHERE brand_hit IS NOT NULL
                   GROUP BY brand_hit ORDER BY n DESC LIMIT 10"""
            )
            by_brand = [{"brand_hit": r[0], "n": r[1]} for r in cur.fetchall()]

        conn.close()
        return {
            "total": total,
            "active": active,
            "with_brand": with_brand,
            "by_source": by_source,
            "by_tld": by_tld,
            "by_brand": by_brand,
        }

    except Exception as e:
        logger.error(f"Error obteniendo stats de Supabase: {e}")
        return {}


def get_cloud_urls(limit: int = 2000) -> list[dict]:
    """Obtiene URLs recientes desde Supabase para el dashboard."""
    if not DB_URL:
        return []

    try:
        conn = get_connection()
        with conn.cursor() as cur:
            cur.execute(
                """SELECT url, domain, source, first_seen, last_seen,
                          is_active, brand_hit, tld, url_length
                   FROM urls ORDER BY first_seen DESC LIMIT %s""",
                (limit,)
            )
            cols = [d[0] for d in cur.description]
            rows = [dict(zip(cols, row)) for row in cur.fetchall()]
        conn.close()
        return rows

    except Exception as e:
        logger.error(f"Error obteniendo URLs de Supabase: {e}")
        return []