"""
PhishRadar — Feature Engineering (Capa 2)
Convierte URLs crudas en vectores numéricos para el modelo ML.
"""

import re
import math
import unicodedata
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

from Levenshtein import distance as levenshtein_distance

LATAM_BRANDS = [
    "banrural", "banguat", "bac", "baccredomatic", "scotiabank",
    "bancolombia", "promerica", "tigo", "claro", "sat", "igss", "renap",
    "mercadolibre", "mercadopago", "rappi", "uber",
    "paypal", "amazon", "netflix", "facebook", "whatsapp",
    "instagram", "google", "microsoft", "apple",
]

# Dominios legítimos — nunca marcarlos como suplantación
LEGITIMATE_DOMAINS = [
    "google.com", "facebook.com", "instagram.com", "amazon.com",
    "netflix.com", "microsoft.com", "apple.com", "paypal.com",
    "mercadolibre.com", "baccredomatic.com",
    "banrural.com.gt", "tigo.com.gt", "claro.com.gt", "sat.gob.gt",
    "portal.sat.gob.gt", "igss.org.gt", "youtube.com", "twitter.com",
    "linkedin.com", "github.com", "whatsapp.com",
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


def _normalize_unicode(text: str) -> str:
    """
    Convierte caracteres unicode usados en phishing a su equivalente ASCII.
    Ejemplo: æ→a, ø→o, ñ→n, ü→u, etc.
    """
    replacements = {
        "æ": "a", "à": "a", "á": "a", "â": "a", "ã": "a", "ä": "a",
        "è": "e", "é": "e", "ê": "e", "ë": "e",
        "ì": "i", "í": "i", "î": "i", "ï": "i",
        "ò": "o", "ó": "o", "ô": "o", "õ": "o", "ö": "o", "ø": "o",
        "ù": "u", "ú": "u", "û": "u", "ü": "u",
        "ñ": "n", "ç": "c", "ý": "y",
        "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t",
    }
    text = text.lower()
    for char, replacement in replacements.items():
        text = text.replace(char, replacement)
    return text

def _brand_impersonation(url: str, domain: str) -> int:
    # Si el dominio es legítimo conocido, no es suplantación
    domain_clean = domain.replace("www.", "")
    if any(domain_clean == legit or domain_clean.endswith("." + legit) 
           for legit in LEGITIMATE_DOMAINS):
        return 0


    # Normalizar unicode: æ→a, ñ→n, etc.
    domain = _normalize_unicode(domain)
    url = _normalize_unicode(url)
      
            
    """
    Detecta suplantación de marca incluyendo typosquatting.
    Usa coincidencia exacta Y distancia de Levenshtein para
    detectar variantes como banrurall, bænrural, paypa1, etc.
    """
    target = (url + " " + domain).lower()
    normalized = re.sub(r"[^a-z0-9]", "", target)

    for brand in LATAM_BRANDS:
        # Coincidencia exacta
        if brand in target:
            return 1
        brand_clean = re.sub(r"[^a-z0-9]", "", brand)
        if brand_clean in normalized:
            return 1

        # Typosquatting — distancia de edición
        # Extraer solo el nombre del dominio sin TLD para comparar
        domain_name = re.sub(r"[^a-z0-9]", "", domain.split(".")[0])
        if len(domain_name) >= 4 and len(brand_clean) >= 4:
            dist = levenshtein_distance(domain_name, brand_clean)
            # Tolerancia: 1 carácter diferente para marcas cortas,
            # 2 caracteres para marcas largas
            threshold = 1 if len(brand_clean) <= 6 else 2
            if dist <= threshold:
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
