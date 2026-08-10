"""
PhishRadar — Auto-updater (Capa 4)
Reentrenamiento automático del modelo cuando hay suficientes URLs nuevas.
Corre como proceso en segundo plano o via cron.
"""

import json
import logging
from datetime import datetime, timedelta
from pathlib import Path

from config import MODELS_DIR, REPORTS_DIR
from src.database import get_connection, init_db
from src.model import train, LEGIT_URLS_SAMPLE

logger = logging.getLogger(__name__)

METRICS_PATH    = MODELS_DIR / "last_metrics.json"
UPDATE_LOG_PATH = MODELS_DIR / "update_history.json"

# Umbral: reentrenar si hay X URLs nuevas desde el último entrenamiento
MIN_NEW_URLS_TO_RETRAIN = 50


def get_update_history() -> list:
    if not UPDATE_LOG_PATH.exists():
        return []
    with open(UPDATE_LOG_PATH) as f:
        return json.load(f)


def save_update_history(history: list) -> None:
    MODELS_DIR.mkdir(exist_ok=True)
    with open(UPDATE_LOG_PATH, "w") as f:
        json.dump(history, f, indent=2)


def get_urls_since(since_date: str) -> list[str]:
    """Obtiene URLs insertadas desde una fecha dada."""
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT url FROM urls WHERE first_seen > ? AND is_active=1",
            (since_date,)
        ).fetchall()
    return [r["url"] for r in rows]


def get_all_phish_urls(limit: int = 5000) -> list[str]:
    """Obtiene todas las URLs phishing de la DB para reentrenar."""
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT url FROM urls WHERE is_active=1 ORDER BY first_seen DESC LIMIT ?",
            (limit,)
        ).fetchall()
    return [r["url"] for r in rows]


def should_retrain() -> tuple[bool, str]:
    """
    Decide si es necesario reentrenar el modelo.
    Devuelve (bool, razón).
    """
    # Si no hay modelo, siempre entrenar
    if not METRICS_PATH.exists():
        return True, "Modelo no existe"

    with open(METRICS_PATH) as f:
        metrics = json.load(f)

    trained_at = metrics.get("trained_at", "2000-01-01")

    # URLs nuevas desde el último entrenamiento
    new_urls = get_urls_since(trained_at)
    if len(new_urls) >= MIN_NEW_URLS_TO_RETRAIN:
        return True, f"{len(new_urls)} URLs nuevas desde el último entrenamiento"

    # Reentrenar si han pasado más de 7 días
    trained_dt = datetime.fromisoformat(trained_at)
    if datetime.utcnow() - trained_dt > timedelta(days=7):
        return True, "Han pasado más de 7 días desde el último entrenamiento"

    return False, f"No es necesario (solo {len(new_urls)} URLs nuevas)"


def auto_update(force: bool = False) -> dict:
    """
    Ejecuta el ciclo de actualización automática.
    Si force=True, reentréna sin importar los umbrales.
    """
    init_db()
    result = {
        "timestamp": datetime.utcnow().isoformat(),
        "retrained": False,
        "reason": "",
        "metrics": None,
    }

    should, reason = should_retrain()
    result["reason"] = reason

    if not should and not force:
        logger.info(f"Auto-update: omitido — {reason}")
        return result

    logger.info(f"Auto-update: reentrenando — {reason}")

    # Obtener datos actuales
    phish_urls = get_all_phish_urls(limit=5000)
    legit_urls = LEGIT_URLS_SAMPLE  # en producción: ampliar con dataset real

    if len(phish_urls) < 10:
        logger.warning("Muy pocas URLs phishing para reentrenar. Mínimo 10.")
        result["reason"] = "Insuficientes datos"
        return result

    # Entrenar
    metrics = train(phish_urls=phish_urls, legit_urls=legit_urls)
    result["retrained"] = True
    result["metrics"]   = metrics

    # Guardar historial
    history = get_update_history()
    history.append({
        "timestamp":   result["timestamp"],
        "reason":      reason,
        "accuracy":    metrics["accuracy"],
        "f1":          metrics["f1_phish"],
        "phish_count": len(phish_urls),
    })
    save_update_history(history)

    logger.info(
        f"Auto-update completo — "
        f"Accuracy: {metrics['accuracy']:.2%} | F1: {metrics['f1_phish']:.2%}"
    )
    return result


def print_update_history() -> None:
    """Muestra el historial de actualizaciones del modelo."""
    history = get_update_history()

    print("\n" + "═" * 60)
    print("  PhishRadar — Historial de actualizaciones del modelo")
    print("═" * 60)

    if not history:
        print("  Sin historial todavía.")
    else:
        for entry in history[-10:]:   # últimas 10
            print(f"\n  📅 {entry['timestamp'][:16]}")
            print(f"     Razón:    {entry['reason']}")
            print(f"     Accuracy: {entry['accuracy']:.2%}")
            print(f"     F1:       {entry['f1']:.2%}")
            print(f"     URLs:     {entry['phish_count']:,}")

    print("\n" + "═" * 60 + "\n")

def get_training_phish_urls(limit: int = 5000) -> list[str]:
    """
    Obtiene URLs phishing reales para entrenar el modelo — intenta primero
    Supabase (necesario en Streamlit Cloud, donde el SQLite local está
    vacío), y si no está disponible cae a SQLite local (para uso en tu
    máquina). Sin esto, el entrenamiento siempre usaba los 20 ejemplos
    de juguete de PHISH_URLS_SAMPLE, sin importar cuántas URLs reales
    hubiera en la base de datos.
    """
    try:
        from src.cloud_database import is_available, get_cloud_urls
        if is_available():
            rows = get_cloud_urls(limit)
            urls = [r["url"] for r in rows if r.get("is_active", 1)]
            if urls:
                logger.info(f"Entrenando con {len(urls)} URLs reales de Supabase")
                return urls
    except Exception as e:
        logger.warning(f"No se pudo leer de Supabase para entrenar: {e}")

    urls = get_all_phish_urls(limit)
    if urls:
        logger.info(f"Entrenando con {len(urls)} URLs reales de SQLite local")
    return urls