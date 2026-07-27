"""
PhishRadar — Reporter (Capa 3)
Genera reportes de campañas en texto y JSON para análisis posterior.
"""

import json
import logging
from datetime import datetime
from pathlib import Path

from config import REPORTS_DIR

logger = logging.getLogger(__name__)


def save_campaign_report(detection_result: dict) -> Path:
    """
    Guarda el resultado completo de detección como JSON.
    Devuelve la ruta del archivo generado.
    """
    REPORTS_DIR.mkdir(exist_ok=True)
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    path = REPORTS_DIR / f"campaigns_{timestamp}.json"

    with open(path, "w", encoding="utf-8") as f:
        json.dump(detection_result, f, indent=2, ensure_ascii=False)

    logger.info(f"Reporte guardado: {path}")
    return path


def print_campaign_report(detection_result: dict) -> None:
    """
    Imprime un reporte legible de campañas detectadas.
    """
    summary  = detection_result.get("summary", {})
    campaigns = detection_result.get("campaigns", {})
    outliers  = detection_result.get("outliers", [])

    print("\n" + "═" * 60)
    print("  PhishRadar — Reporte de Campañas Detectadas")
    print("═" * 60)
    print(f"  URLs analizadas:     {summary.get('total_urls', 0):,}")
    print(f"  Campañas detectadas: {summary.get('n_campaigns', 0)}")
    print(f"  URLs aisladas:       {summary.get('n_outliers', 0)}")
    coverage = summary.get('coverage', 0)
    print(f"  Cobertura:           {coverage:.1%}")

    if not campaigns:
        print("\n  No se detectaron campañas con los parámetros actuales.")
        print("  (Intenta bajar eps en --campaigns si tienes más URLs)")
    else:
        for cid, camp in campaigns.items():
            print(f"\n  {'─' * 56}")
            print(f"  🎯 CAMPAÑA #{cid + 1}  —  {camp['risk_level']}")
            print(f"  {'─' * 56}")
            print(f"  URLs en campaña:   {camp['url_count']}")
            print(f"  Score de riesgo:   {camp['risk_score']}")
            print(f"  Marca suplantada:  {'Sí' if camp['brand_targeted'] else 'No'}")
            print(f"  Keywords promedio: {camp['avg_keyword_count']}")
            print(f"  Entropía promedio: {camp['avg_entropy']}")

            if camp["top_tlds"]:
                tlds_str = ", ".join(
                    f"{t}({n})" for t, n in list(camp["top_tlds"].items())[:4]
                )
                print(f"  TLDs usados:       {tlds_str}")

            if camp["top_asns"]:
                asns_str = ", ".join(
                    f"{a}({n})" for a, n in list(camp["top_asns"].items())[:3]
                )
                print(f"  Hosting detectado: {asns_str}")

            print(f"\n  URLs de la campaña:")
            for url in camp["urls"][:5]:          # máximo 5 para no saturar
                print(f"    • {url}")
            if len(camp["urls"]) > 5:
                print(f"    ... y {len(camp['urls']) - 5} más (ver JSON completo)")

    if outliers:
        print(f"\n  {'─' * 56}")
        print(f"  URLs aisladas (sin campaña): {len(outliers)}")
        for url in outliers[:3]:
            print(f"    • {url}")
        if len(outliers) > 3:
            print(f"    ... y {len(outliers) - 3} más")

    print("\n" + "═" * 60 + "\n")


def print_ioc_list(detection_result: dict) -> None:
    """
    Imprime lista de IOCs (Indicators of Compromise) — formato para compartir con SOC.
    """
    campaigns = detection_result.get("campaigns", {})
    outliers  = detection_result.get("outliers", [])

    print("\n" + "═" * 60)
    print("  IOC List — PhishRadar")
    print(f"  Generado: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}")
    print("═" * 60)

    all_urls = []
    for camp in campaigns.values():
        all_urls.extend(camp["urls"])
    all_urls.extend(outliers)

    for url in sorted(set(all_urls)):
        print(url)

    print(f"\n  Total IOCs: {len(set(all_urls))}")
    print("═" * 60 + "\n")