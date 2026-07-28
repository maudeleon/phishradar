"""
PhishRadar — Colector de fuentes
Descarga feeds de URLs phishing y los entrega como listas limpias.
"""

import logging
import requests

from config import SOURCES, FETCH_TIMEOUT, MAX_URLS_PER_RUN

logger = logging.getLogger(__name__)


def fetch_openphish() -> list[str]:
    """
    Descarga el feed público de OpenPhish.
    Formato: una URL por línea, sin cabeceras.
    """
    cfg = SOURCES["openphish"]
    if not cfg["enabled"]:
        logger.info("OpenPhish desactivado en config.py")
        return []

    try:
        logger.info(f"Descargando OpenPhish desde {cfg['url']}")
        resp = requests.get(cfg["url"], timeout=FETCH_TIMEOUT)
        resp.raise_for_status()

        urls = [line.strip() for line in resp.text.splitlines() if line.strip()]
        logger.info(f"OpenPhish: {len(urls)} URLs descargadas")
        return urls[:MAX_URLS_PER_RUN]

    except requests.RequestException as e:
        logger.error(f"Error descargando OpenPhish: {e}")
        return []


def fetch_phishtank() -> list[str]:
    """
    Descarga el CSV de PhishTank.
    Requiere API key (configurar SOURCES['phishtank']['enabled'] = True).
    """
    cfg = SOURCES["phishtank"]
    if not cfg["enabled"]:
        logger.info("PhishTank desactivado — actívalo en config.py cuando tengas API key")
        return []

    try:
        logger.info(f"Descargando PhishTank desde {cfg['url']}")
        resp = requests.get(cfg["url"], timeout=FETCH_TIMEOUT)
        resp.raise_for_status()

        urls = []
        for line in resp.text.splitlines()[1:]:   # saltar cabecera CSV
            parts = line.split(",")
            if parts:
                url = parts[0].strip().strip('"')
                if url.startswith("http"):
                    urls.append(url)

        logger.info(f"PhishTank: {len(urls)} URLs descargadas")
        return urls[:MAX_URLS_PER_RUN]

    except requests.RequestException as e:
        logger.error(f"Error descargando PhishTank: {e}")
        return []

def fetch_urlhaus(auth_key: str) -> list[str]:
    """
    Descarga URLs maliciosas recientes de URLhaus (abuse.ch).
    Requiere Auth-Key gratuito de auth.abuse.ch
    """
    url = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
    headers = {"Auth-Key": auth_key}

    try:
        logger.info(f"Descargando URLhaus...")
        resp = requests.get(url, headers=headers, timeout=FETCH_TIMEOUT)
        resp.raise_for_status()

        data = resp.json()
        if data.get("query_status") != "ok":
            logger.warning(f"URLhaus respondió: {data.get('query_status')}")
            return []

        urls = [
            entry["url"]
            for entry in data.get("urls", [])
            if entry.get("url_status") == "online"
        ]
        logger.info(f"URLhaus: {len(urls)} URLs activas descargadas")
        return urls[:MAX_URLS_PER_RUN]

    except requests.RequestException as e:
        logger.error(f"Error descargando URLhaus: {e}")
        return []

def fetch_all() -> dict[str, list[str]]:
    """
    Ejecuta todos los colectores habilitados.
    Devuelve dict: {nombre_fuente: [urls]}
    """
    results = {}

    if SOURCES["openphish"]["enabled"]:
        results["openphish"] = fetch_openphish()

    if SOURCES["phishtank"]["enabled"]:
        results["phishtank"] = fetch_phishtank()

    if SOURCES["urlhaus"]["enabled"]:
        auth_key = SOURCES["urlhaus"]["auth_key"]
        results["urlhaus"] = fetch_urlhaus(auth_key)

    total = sum(len(v) for v in results.values())
    logger.info(f"Total URLs recolectadas: {total} de {len(results)} fuente(s)")
    return results
