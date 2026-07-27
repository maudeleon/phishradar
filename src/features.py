"""
PhishRadar — Feature Engineering (Capa 2)
Convierte URLs crudas en vectores numéricos para el modelo ML.
"""

import re
import math
from urllib.parse import urlparse

# TLDs frecuentes en phishing (basado en datasets públicos + LATAM)
SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq",   # Freenom (gratuitos, muy usados en phishing)
    ".xyz", ".top", ".club", ".online",
    ".ru", ".cn",                          # Alta incidencia en campañas
    ".zip", ".mov",                        # TLDs nuevos usados para engañar
}

SUSPICIOUS_KEYWORDS = [
    # Inglés
    "login", "signin", "secure", "account", "update", "verify",
    "confirm", "banking", "suspended", "unusual", "validate",
    "password", "credential", "authenticate", "recover", "unlock",
    # Español (LATAM)
    "banco", "seguro", "cuenta", "verificar", "confirmar",
    "actualizar", "clave", "tarjeta", "acceso", "banca",
    "pago", "factura", "declaracion", "renovar",
]

LATAM_BRANDS = [
    "banrural", "banguat", "bac", "baccredomatic", "scotiabank",
    "bancolombia", "tigo", "claro", "sat", "igss", "renap",
    "mercadolibre", "mercadopago", "rappi", "uber",
    "paypal", "amazon", "netflix", "facebook", "whatsapp",
    "instagram", "google", "microsoft", "apple",
]


# ── Funciones individuales ────────────────────────────────────────────────────

def _entropy(text: str) -> float:
    if not text:
        return 0.0
    freq = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(text)
    return round(-sum((c / n) * math.log2(c / n) for c in freq.values()), 4)


def _extract_domain(url: str) -> str:
    try:
        return urlparse(url).netloc.lower().strip()
    except Exception:
        return ""


def _extract_tld(domain: str) -> str:
    parts = domain.split(".")
    return f".{parts[-1]}" if len(parts) >= 2 else ""


def _count_subdomains(domain: str) -> int:
    parts = domain.split(".")
    return max(0, len(parts) - 2)


def _has_ip(url: str) -> int:
    return int(bool(re.match(r"https?://(\d{1,3}\.){3}\d{1,3}", url)))


def _suspicious_keyword_count(url: str) -> int:
    url_lower = url.lower()
    return sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url_lower)


def _brand_impersonation(url: str, domain: str) -> int:
    target = (url + " " + domain).lower()
    normalized = re.sub(r"[^a-z0-9]", "", target)
    for brand in LATAM_BRANDS:
        if brand in target:
            return 1
        if re.sub(r"[^a-z0-9]", "", brand) in normalized:
            return 1
    return 0


def _suspicious_tld(tld: str) -> int:
    return int(tld in SUSPICIOUS_TLDS)


def _has_at_symbol(url: str) -> int:
    """URLs con @ son técnica clásica de phishing: http://legit.com@evil.com"""
    return int("@" in url)


def _has_double_slash(url: str) -> int:
    """Doble slash fuera del protocolo es señal de redirección."""
    return int("//" in url[8:])


def _digit_ratio(domain: str) -> float:
    """Proporción de dígitos en el dominio. Alto = sospechoso."""
    if not domain:
        return 0.0
    digits = sum(1 for c in domain if c.isdigit())
    return round(digits / len(domain), 4)


def _special_char_count(url: str) -> int:
    """Cuenta caracteres especiales frecuentes en phishing."""
    return sum(url.count(c) for c in ["-", "_", "~", "%", "=", "?", "&"])


# ── Función principal ─────────────────────────────────────────────────────────

def extract_features(url: str) -> dict:
    """
    Extrae todas las features de una URL.
    Devuelve un dict con valores numéricos listos para ML.
    """
    url = url.strip()
    domain = _extract_domain(url)
    tld = _extract_tld(domain)

    return {
        # Estructura de la URL
        "url_length":          len(url),
        "domain_length":       len(domain),
        "path_length":         len(urlparse(url).path),
        "subdomain_count":     _count_subdomains(domain),
        "special_char_count":  _special_char_count(url),

        # Entropía (aleatoriedad)
        "domain_entropy":      _entropy(domain),
        "url_entropy":         _entropy(url),
        "digit_ratio":         _digit_ratio(domain),

        # Señales binarias (0 o 1)
        "has_ip":              _has_ip(url),
        "has_at_symbol":       _has_at_symbol(url),
        "has_double_slash":    _has_double_slash(url),
        "suspicious_tld":      _suspicious_tld(tld),
        "brand_impersonation": _brand_impersonation(url, domain),

        # Conteos
        "suspicious_keyword_count": _suspicious_keyword_count(url),
    }


def extract_features_batch(urls: list[str]) -> list[dict]:
    """Extrae features de una lista de URLs."""
    return [extract_features(url) for url in urls if url.strip()]


def feature_names() -> list[str]:
    """Lista ordenada de nombres de features (útil para el modelo)."""
    return list(extract_features("http://example.com").keys())
