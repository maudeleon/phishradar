"""
PhishRadar — Clustering de Campañas (Capa 3)
Agrupa URLs phishing por similitud de infraestructura para detectar campañas.
Usa DBSCAN: no necesita saber cuántos grupos hay de antemano.
"""

import logging
import re
import hashlib
from urllib.parse import urlparse
from collections import defaultdict

import numpy as np
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler

from src.features import extract_features, feature_names

logger = logging.getLogger(__name__)


# ── Señales de infraestructura ────────────────────────────────────────────────

def extract_infra_signals(url: str) -> dict:
    """
    Extrae señales de infraestructura compartida de una URL.
    Estas señales complementan las features del modelo ML.
    """
    url = url.strip()
    parsed = urlparse(url)
    domain = parsed.netloc.lower()

    # Registrador del dominio (últimas 2 partes: dominio + TLD)
    parts = domain.split(".")
    registrar_domain = ".".join(parts[-2:]) if len(parts) >= 2 else domain

    # ASN simulado por rango de IP o patrón de dominio
    # En producción esto se resuelve con python-whois o ipwhois
    asn_hint = _estimate_asn_hint(domain)

    # Hash del path sin parámetros (campañas reusan mismos paths)
    path_clean = re.sub(r"\d+", "N", parsed.path.lower())  # normalizar números
    path_hash  = hashlib.md5(path_clean.encode()).hexdigest()[:8]

    # Patrón del dominio: sustituir números y hashes por placeholder
    domain_pattern = re.sub(r"\d+", "N", domain)
    domain_pattern = re.sub(r"[a-f0-9]{6,}", "HASH", domain_pattern)

    return {
        "registrar_domain": registrar_domain,
        "tld":              f".{parts[-1]}" if parts else "",
        "path_hash":        path_hash,
        "domain_pattern":   domain_pattern,
        "asn_hint":         asn_hint,
        "path_depth":       len([p for p in parsed.path.split("/") if p]),
        "has_query":        int(bool(parsed.query)),
        "subdomain_count":  max(0, len(parts) - 2),
    }


def _estimate_asn_hint(domain: str) -> str:
    """
    Estima el 'grupo de hosting' por patrones conocidos en el dominio.
    En producción real se reemplaza con consulta WHOIS/BGP.
    """
    cheap_hosts = {
        ".tk": "freenom", ".ml": "freenom", ".ga": "freenom",
        ".cf": "freenom", ".gq": "freenom",
    }
    for tld, provider in cheap_hosts.items():
        if domain.endswith(tld):
            return provider

    vps_hints = ["vps", "digitalocean", "vultr", "linode", "hostinger",
                 "namecheap", "godaddy", "bluehost"]
    for hint in vps_hints:
        if hint in domain:
            return hint

    return "unknown"


# ── Feature vector para clustering ────────────────────────────────────────────

def build_cluster_vector(url: str) -> np.ndarray:
    """
    Construye un vector numérico combinando features ML + señales de infraestructura.
    Este vector es lo que DBSCAN usa para calcular similitud.
    """
    ml_features  = extract_features(url)
    infra        = extract_infra_signals(url)

    vector = [
        # Features cuantitativas del modelo
        ml_features.get("url_length", 0),
        ml_features.get("domain_length", 0),
        ml_features.get("subdomain_count", 0),
        ml_features.get("domain_entropy", 0),
        ml_features.get("suspicious_keyword_count", 0),
        ml_features.get("special_char_count", 0),
        ml_features.get("digit_ratio", 0),

        # Señales de infraestructura
        infra.get("path_depth", 0),
        infra.get("has_query", 0),
        infra.get("subdomain_count", 0),

        # Features binarias
        ml_features.get("has_ip", 0),
        ml_features.get("suspicious_tld", 0),
        ml_features.get("brand_impersonation", 0),
    ]

    return np.array(vector, dtype=float)


# ── Motor DBSCAN ──────────────────────────────────────────────────────────────

def detect_campaigns(
    urls: list[str],
    eps: float = 1.2,
    min_samples: int = 2,
) -> dict:
    """
    Detecta campañas agrupando URLs por similitud.

    Parámetros DBSCAN:
        eps         → distancia máxima para considerar vecinos (ajustar según dataset)
        min_samples → mínimo de URLs para formar un cluster (campaña)

    Devuelve dict con clusters, outliers y análisis por campaña.
    """
    if len(urls) < 2:
        logger.warning("Se necesitan al menos 2 URLs para clustering.")
        return {"clusters": {}, "outliers": urls, "summary": {}}

    logger.info(f"Analizando {len(urls)} URLs con DBSCAN (eps={eps}, min={min_samples})")

    # Construir matriz de features
    vectors = []
    valid_urls = []
    for url in urls:
        try:
            vec = build_cluster_vector(url)
            vectors.append(vec)
            valid_urls.append(url)
        except Exception as e:
            logger.debug(f"URL ignorada ({url}): {e}")

    X = np.array(vectors)

    # Escalar
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # DBSCAN
    db = DBSCAN(eps=eps, min_samples=min_samples, metric="euclidean")
    labels = db.fit_predict(X_scaled)

    # Organizar resultados
    clusters  = defaultdict(list)
    outliers  = []

    for url, label in zip(valid_urls, labels):
        if label == -1:
            outliers.append(url)       # -1 = ruido, URL única
        else:
            clusters[int(label)].append(url)

    # Analizar cada campaña
    campaign_analysis = {}
    for cluster_id, cluster_urls in clusters.items():
        campaign_analysis[cluster_id] = analyze_campaign(cluster_urls, cluster_id)

    n_campaigns = len(clusters)
    n_outliers  = len(outliers)

    logger.info(f"Resultado: {n_campaigns} campaña(s) detectada(s) | {n_outliers} URLs aisladas")

    return {
        "clusters":  dict(clusters),
        "outliers":  outliers,
        "campaigns": campaign_analysis,
        "summary": {
            "total_urls":    len(valid_urls),
            "n_campaigns":   n_campaigns,
            "n_outliers":    n_outliers,
            "coverage":      round((len(valid_urls) - n_outliers) / len(valid_urls), 4) if valid_urls else 0,
        },
    }


# ── Análisis de campaña ───────────────────────────────────────────────────────

def analyze_campaign(urls: list[str], campaign_id: int) -> dict:
    """
    Analiza una campaña detectada y extrae sus características comunes.
    """
    infra_signals = [extract_infra_signals(u) for u in urls]
    ml_features   = [extract_features(u) for u in urls]

    # TLDs usados
    tlds = [s["tld"] for s in infra_signals]
    tld_counts = defaultdict(int)
    for t in tlds:
        tld_counts[t] += 1

    # Marcas suplantadas
    brands = [f.get("brand_impersonation") for f in ml_features]

    # Patrones de dominio compartidos
    patterns = [s["domain_pattern"] for s in infra_signals]
    pattern_counts = defaultdict(int)
    for p in patterns:
        pattern_counts[p] += 1

    # ASN hints
    asns = [s["asn_hint"] for s in infra_signals]
    asn_counts = defaultdict(int)
    for a in asns:
        asn_counts[a] += 1

    # Score de riesgo de la campaña
    avg_keywords = sum(f.get("suspicious_keyword_count", 0) for f in ml_features) / len(urls)
    avg_entropy  = sum(f.get("domain_entropy", 0) for f in ml_features) / len(urls)
    has_brand    = any(brands)

    risk_score = round(
        (avg_keywords * 0.3) +
        (avg_entropy  * 0.2) +
        (int(has_brand) * 0.5),
        4
    )

    return {
        "campaign_id":       campaign_id,
        "url_count":         len(urls),
        "urls":              urls,
        "top_tlds":          dict(sorted(tld_counts.items(), key=lambda x: -x[1])),
        "top_asns":          dict(sorted(asn_counts.items(), key=lambda x: -x[1])),
        "top_patterns":      dict(sorted(pattern_counts.items(), key=lambda x: -x[1])[:5]),
        "brand_targeted":    has_brand,
        "avg_keyword_count": round(avg_keywords, 2),
        "avg_entropy":       round(avg_entropy, 4),
        "risk_score":        risk_score,
        "risk_level":        _campaign_risk(risk_score),
    }


def _campaign_risk(score: float) -> str:
    if score >= 0.7:
        return "🔴 CRÍTICO"
    elif score >= 0.4:
        return "🟡 MODERADO"
    else:
        return "🟢 BAJO"