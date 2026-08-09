"""
PhishRadar — Script principal
Uso:
    python main.py                        → recolecta URLs de los feeds
    python main.py --stats                → estadísticas de la DB
    python main.py --init                 → inicializa la DB
    python main.py --demo                 → carga URLs de prueba
    python main.py --train                → entrena el modelo ML
    python main.py --predict <url>        → analiza una URL concreta
    python main.py --importance           → importancia de features
    python main.py --campaigns            → detecta campañas en la DB
    python main.py --campaigns --ioc      → campañas + lista IOC
    python main.py --update               → reentrenamiento automático
    python main.py --update --force       → forzar reentrenamiento
    python main.py --history              → historial de actualizaciones
"""

import sys
import logging
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from config import LOGS_DIR, LOG_LEVEL
from src.database   import init_db, insert_urls, get_stats, start_run, finish_run, get_connection
from src.collector  import fetch_all
from src.analyzer   import analyze_batch
from src.model      import train, predict, feature_importance_report
from src.clustering import detect_campaigns
from src.reporter   import print_campaign_report, save_campaign_report, print_ioc_list
from src.updater    import auto_update, print_update_history


# ── Logging ───────────────────────────────────────────────────────────────────

def setup_logging():
    LOGS_DIR.mkdir(exist_ok=True)
    logging.basicConfig(
        level=getattr(logging, LOG_LEVEL),
        format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler(LOGS_DIR / "phishradar.log", encoding="utf-8"),
        ],
    )


# ── Capa 1 ────────────────────────────────────────────────────────────────────

def run_collection():
    logger.info("═" * 55)
    logger.info("  PhishRadar — Capa 1  |  Recolección iniciada")
    logger.info("═" * 55)
    init_db()

    
    # Inicializar Supabase si está disponible
    from src.cloud_database import init_cloud_db, sync_urls, is_available
    if is_available():
        init_cloud_db()
        logger.info("Supabase conectado ✅")
    else:
        logger.info("Supabase no configurado — modo local")

    feeds = fetch_all()
    if not feeds:
        logger.warning("No se obtuvo ninguna URL.")
        return

    for source, raw_urls in feeds.items():
        logger.info(f"\n── Procesando fuente: {source} ({len(raw_urls)} URLs) ──")
        run_id = start_run(source)
        try:
            analyzed = analyze_batch(raw_urls, source)
            total, new = insert_urls(analyzed)
            finish_run(run_id, total, new, status="ok")

            # Sincronizar a Supabase
            if is_available():
                sync_urls(analyzed)
                logger.info(f"[{source}] Sincronizado a Supabase")

            logger.info(f"[{source}] Insertadas: {new} nuevas / {total} procesadas")
        except Exception as e:
            finish_run(run_id, 0, 0, status="error")
            logger.error(f"[{source}] Error: {e}")
    print_stats()


def print_stats():
    stats = get_stats()
    print("\n" + "═" * 55)
    print("  PhishRadar — Estadísticas de la base de datos")
    print("═" * 55)
    print(f"  Total URLs:          {stats['total']:,}")
    print(f"  URLs activas:        {stats['active']:,}")
    print(f"  Con marca LATAM:     {stats['with_brand']:,}")
    if stats["by_source"]:
        print("\n  Por fuente:")
        for row in stats["by_source"]:
            print(f"    {row['source']:<20} {row['n']:>6,}")
    if stats["by_tld"]:
        print("\n  Top TLDs:")
        for row in stats["by_tld"]:
            print(f"    {row['tld']:<15} {row['n']:>6,}")
    if stats["by_brand"]:
        print("\n  Marcas LATAM más suplantadas:")
        for row in stats["by_brand"]:
            print(f"    {row['brand_hit']:<20} {row['n']:>6,}")
    print("═" * 55 + "\n")


# ── Capa 2 ────────────────────────────────────────────────────────────────────

def run_train():
    logger.info("═" * 55)
    logger.info("  PhishRadar — Capa 2  |  Entrenando modelo ML")
    logger.info("═" * 55)
    metrics = train()
    print("\n" + "═" * 55)
    print("  Resultado del entrenamiento")
    print("═" * 55)
    print(f"  Accuracy:             {metrics['accuracy']:.2%}")
    print(f"  Precisión (phishing): {metrics['precision_phish']:.2%}")
    print(f"  Recall    (phishing): {metrics['recall_phish']:.2%}")
    print(f"  F1-score  (phishing): {metrics['f1_phish']:.2%}")
    print(f"  Muestras phishing:    {metrics['phish_samples']}")
    print(f"  Muestras legítimas:   {metrics['legit_samples']}")
    print("═" * 55 + "\n")


def run_predict(urls: list[str]):
    print("\n" + "═" * 55)
    print("  PhishRadar — Análisis de URLs")
    print("═" * 55)
    results = predict(urls)
    for r in results:
        print(f"\n  URL:     {r['url']}")
        print(f"  Score:   {r['score']:.2%}  →  {r['risk']}")
        print(f"  Señales: {', '.join(r['top_signals'])}")
    print("\n" + "═" * 55 + "\n")


# ── Capa 3 ────────────────────────────────────────────────────────────────────

def run_campaigns(export_ioc: bool = False):
    logger.info("═" * 55)
    logger.info("  PhishRadar — Capa 3  |  Detección de campañas")
    logger.info("═" * 55)
    init_db()
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT url FROM urls WHERE is_active=1 ORDER BY first_seen DESC LIMIT 2000"
        ).fetchall()
    urls = [row["url"] for row in rows]
    if not urls:
        print("\n  No hay URLs. Corre: python main.py --demo\n")
        return
    logger.info(f"Cargadas {len(urls)} URLs activas")
    result = detect_campaigns(urls)
    print_campaign_report(result)
    report_path = save_campaign_report(result)
    print(f"  📄 Reporte guardado en: {report_path}\n")
    if export_ioc:
        print_ioc_list(result)


def run_demo():
    from src.model import PHISH_URLS_SAMPLE
    from src.analyzer import analyze_batch

    campaign_a = [
        "http://banrural-gt-seguro.xyz/login/cuenta",
        "http://banrural-verificar.xyz/login/acceso",
        "http://banrural-banca.xyz/login/validar",
        "http://banrural-online-gt.xyz/cuenta/ingresar",
    ]
    campaign_b = [
        "http://sat-gt-declaracion.tk/verificar/clave",
        "http://sat-guatemala-portal.tk/declaracion/anual",
        "http://sat-pagos-gt.tk/verificar/renta",
    ]
    otros = [
        "http://netflix-gt-renovar.ml/account/update",
        "http://tigo-factura-pagos.ml/verificar",
        "http://igss-guatemala.ru/acceso",
    ]
    all_urls = campaign_a + campaign_b + otros + PHISH_URLS_SAMPLE
    init_db()
    analyzed = analyze_batch(all_urls, "demo")
    insert_urls(analyzed)
    logger.info(f"Demo: {len(all_urls)} URLs cargadas")
    print(f"\n  ✅ {len(all_urls)} URLs de demo insertadas.\n")
    print("  Ahora puedes correr:")
    print("    python main.py --campaigns")
    print("    streamlit run dashboard.py\n")


# ── Capa 4 ────────────────────────────────────────────────────────────────────

def run_update(force: bool = False):
    logger.info("═" * 55)
    logger.info("  PhishRadar — Capa 4  |  Auto-actualización")
    logger.info("═" * 55)
    result = auto_update(force=force)
    if result["retrained"]:
        m = result["metrics"]
        print(f"\n  ✅ Modelo actualizado")
        print(f"  Accuracy: {m['accuracy']:.2%} | F1: {m['f1_phish']:.2%}\n")
    else:
        print(f"\n  ℹ️  Sin cambios: {result['reason']}\n")

def run_scrape_domains(): #agregado el 8-8-26
    """Scrapea y guarda dominios legítimos (bancos por ahora)."""
    from src.domain_scraper import sync_bank_domains_to_db
    logger.info("═" * 55)
    logger.info("  PhishRadar — Scraping de dominios legítimos")
    logger.info("═" * 55)
    resultado = sync_bank_domains_to_db()
    print(f"\n  ✅ {resultado['total']} dominios de categoría '{resultado['categoria']}' guardados\n")

# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    setup_logging()
    logger = logging.getLogger(__name__)
    args = sys.argv[1:]

    # Cargar whitelist dinámica ANTES de cualquier comando 8.8.26
    from src.typosquat import refresh_legitimate_domains
    from src.domain_scraper import load_legitimate_domains_from_db
    total = refresh_legitimate_domains(extra_domains=load_legitimate_domains_from_db())
    logger.info(f"Whitelist de dominios legítimos cargada: {total} dominios")

    if "--stats" in args:
        init_db(); print_stats()
    elif "--init" in args:
        init_db(); logger.info("DB inicializada.")
    elif "--demo" in args:
        run_demo()
    elif "--train" in args:
        run_train()
    elif "--predict" in args:
        idx  = args.index("--predict")
        urls = args[idx + 1:]
        if not urls:
            print("Uso: python main.py --predict <url1> <url2> ...")
        else:
            run_predict(urls)
    elif "--importance" in args:
        feature_importance_report()
    elif "--campaigns" in args:
        run_campaigns(export_ioc="--ioc" in args)
    elif "--ioc" in args:
        run_campaigns(export_ioc=True)
    elif "--update" in args:
        run_update(force="--force" in args)
    elif "--history" in args:
        print_update_history()
    elif "--scrape-domains" in args: #agregado el 8-8-26
        run_scrape_domains()
    else:
        run_collection()
