"""
PhishRadar — Análisis de URLs
Extrae características básicas de cada URL para enriquecer la base de datos.
En la Capa 2 estas features alimentarán el modelo ML.
"""

import re
import math
from urllib.parse import urlparse

from config import LATAM_BRANDS


# ── Utilidades ────────────────────────────────────────────────────────────────

def extract_domain(url: str) -> str:
    """Extrae el dominio (sin esquema ni path)."""
    try:
        parsed = urlparse(url)
        return parsed.netloc.lower().strip()
    except Exception:
        return ""


def extract_tld(domain: str) -> str:
    """
    Extrae el TLD del dominio.
    Ejemplo: 'banco-gt.xyz.com' → '.com'
    """
    parts = domain.split(".")
    return f".{parts[-1]}" if len(parts) >= 2 else ""


def entropy(text: str) -> float:
    """
    Entropía de Shannon del texto.
    Alta entropía = strings aleatorios (señal de phishing).
    """
    if not text:
        return 0.0
    freq = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def detect_brand(url: str, domain: str) -> str | None:
    """
    Detecta si la URL intenta imitar una marca LATAM conocida.
    Retorna el nombre de la marca o None.
    Busca en el dominio completo para mayor cobertura.
    """
    target = (url + " " + domain).lower()
    for brand in LATAM_BRANDS:
        # coincidencia exacta como substring
        if brand in target:
            return brand
        # coincidencia con guiones/puntos intermedios: ban-rural, b4nrural
        normalized = re.sub(r"[^a-z0-9]", "", target)
        brand_clean = re.sub(r"[^a-z0-9]", "", brand)
        if brand_clean in normalized:
            return brand
    return None


def has_ip_address(url: str) -> bool:
    """True si la URL usa IP directamente en lugar de dominio (señal fuerte)."""
    pattern = r"https?://(\d{1,3}\.){3}\d{1,3}"
    return bool(re.match(pattern, url))


def count_subdomains(domain: str) -> int:
    """Cantidad de subdominios (más de 3 es sospechoso)."""
    parts = domain.split(".")
    return max(0, len(parts) - 2)


def has_suspicious_keywords(url: str) -> bool:
    """Palabras clave comunes en phishing."""
    keywords = [
        "login", "signin", "secure", "account", "update", "verify",
        "confirm", "banking", "paypal", "suspended", "unusual",
        "validate", "password", "credential", "authenticate",
        # Español (relevante para LATAM)
        "banco", "seguro", "cuenta", "verificar", "confirmar",
        "actualizar", "contrasena", "clave", "tarjeta",
    ]
    url_lower = url.lower()
    return any(kw in url_lower for kw in keywords)


# ── Función principal ─────────────────────────────────────────────────────────

def analyze_url(url: str, source: str) -> dict | None:
    """
    Analiza una URL y devuelve un dict listo para insertar en la DB.
    Retorna None si la URL está mal formada.
    """
    url = url.strip()
    if not url or not url.startswith(("http://", "https://")):
        return None

    domain = extract_domain(url)
    if not domain:
        return None

    tld       = extract_tld(domain)
    brand_hit = detect_brand(url, domain)

    return {
        "url":        url,
        "domain":     domain,
        "source":     source,
        "brand_hit":  brand_hit,
        "tld":        tld,
        "url_length": len(url),
        # Features extra (guardadas en JSON en Capa 2, por ahora solo calculadas)
        "_entropy":          round(entropy(domain), 4),
        "_has_ip":           has_ip_address(url),
        "_subdomains":       count_subdomains(domain),
        "_suspicious_words": has_suspicious_keywords(url),
    }


def analyze_batch(urls: list[str], source: str) -> list[dict]:
    """Analiza una lista de URLs y filtra las inválidas."""
    results = []
    for url in urls:
        item = analyze_url(url, source)
        if item:
            results.append(item)
    return results
