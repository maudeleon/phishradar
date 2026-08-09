"""
PhishRadar — Scraper de dominios legítimos (Capa 5, nueva)

Reemplaza la whitelist manual (LEGITIMATE_DOMAINS hardcodeada en typosquat.py)
por un inventario que se actualiza automáticamente desde fuentes oficiales.

FUENTE ACTUAL:
- Banco de Guatemala (banguat.gob.gt) — tabla oficial de bancos nacionales
  con enlaces directos a sus sitios web reales.

NOTA HONESTA SOBRE COBERTURA:
- La Superintendencia de Bancos (sib.gob.gt), que sería la fuente MÁS
  autorizada para instituciones financieras, bloquea peticiones automatizadas
  (bot detection). Por eso usamos Banguat como fuente primaria — es oficial
  y accesible, pero cubre "bancos nacionales" específicamente, no todas las
  entidades supervisadas (financieras, aseguradoras, etc.)
- Este scraper cubre SOLO bancos por ahora. Instituciones de gobierno
  (.gob.gt) y universidades (.edu.gt) son la siguiente fuente a construir,
  no están incluidas todavía.
"""

import re
import logging
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

BANGUAT_URL = "https://banguat.gob.gt/page/bancos-nacionales"

# Dominios que aparecen en la página pero NO son bancos (redes sociales,
# navegación del sitio, etc.) — se excluyen explícitamente para no
# contaminar el inventario con enlaces irrelevantes.
DOMINIOS_EXCLUIDOS = {
    "banguat.gob.gt", "facebook.com", "twitter.com", "x.com",
    "instagram.com", "youtube.com", "linkedin.com",
}


# ── Seed verificado ────────────────────────────────────────────────────────
# Extraído manualmente el 2026-08-04 como respaldo inmediato y como fixture
# de referencia para verificar que el scraper automático extrae lo mismo.
# Si el scraper deja de funcionar (la página cambia de estructura), el
# sistema sigue operando con este seed en vez de fallar por completo.
SEED_BANCOS_GUATEMALA = {
    "chn.com.gt", "bancoinmobiliario.com.gt", "bantrab.com.gt",
    "bi.com.gt", "banrural.com.gt", "interbanco.com.gt",
    "vivibanco.com.gt", "ficohsa.com", "bancopromerica.com.gt",
    "bantigua.com.gt", "baccredomatic.com", "bam.com.gt",
    "gtc.com.gt", "bancoazteca.com.gt", "inv.com.gt",
}


# ── Dominios adicionales verificados manualmente ──────────────────────────────
# El scraper de Banguat solo captura UN link oficial por institución. Algunos
# bancos operan varios dominios raíz REALES y distintos para funciones
# diferentes (banca en línea, sitio corporativo, blog) que esa única fuente
# no puede descubrir por sí sola — no es un problema del scraping como técnica,
# es que la fuente (Banguat) solo publica un enlace por fila.
#
# Cada entrada aquí está VERIFICADA con evidencia, no adivinada. Se fusiona
# con lo que trae el scraper, no lo reemplaza.
DOMINIOS_ADICIONALES_VERIFICADOS = [
    {
        "nombre": "Corporación Bi (sitio corporativo, distinto de bi.com.gt)",
        "domain": "corporacionbi.com",
        "fuente_verificacion": (
            "corporacionbi.com/gt/bancoindustrial/ — confirmado como sitio "
            "oficial de Banco Industrial, incluye página propia advirtiendo "
            "sobre canales fraudulentos que suplantan a la Corporación Bi. "
            "Verificado 2026-08-08."
        ),
    },
    {
        "nombre": "Bi en Línea (banca personal de Banco Industrial)",
        "domain": "bienlinea.bi.com.gt",
        "fuente_verificacion": (
            "Servicio real documentado de banca en línea de Banco Industrial. "
            "Se registra explícitamente (no solo como subdominio heredado de "
            "bi.com.gt) para proteger contra dominios INDEPENDIENTES que "
            "imiten el nombre del servicio (ej. 'bienlineaa-bi.com'), ya que "
            "un atacante no puede registrar subdominios reales de bi.com.gt "
            "pero sí puede registrar un dominio propio con nombre parecido. "
            "Verificado 2026-08-08."
        ),
    },
    {
        "nombre": "Bi Banking (banca empresarial de Banco Industrial)",
        "domain": "bibanking.bi.com.gt",
        "fuente_verificacion": (
            "corporacionbi.com/gt/bancoindustrial/bi-banking/ — confirmado: "
            "'ingresando a bibanking.bi.com.gt'. Mismo motivo que Bi en Línea: "
            "se registra explícitamente para proteger el NOMBRE del servicio "
            "contra dominios independientes que lo imiten. Verificado 2026-08-08."
        ),
    },
]


def _extract_domain(href: str) -> str | None:
    """Extrae el dominio limpio (sin www, sin path) de un href."""
    try:
        hostname = urlparse(href).hostname
        if not hostname:
            return None
        hostname = hostname.lower()
        if hostname.startswith("www."):
            hostname = hostname[4:]
        return hostname
    except Exception:
        return None


def _parse_bank_links(html: str) -> list[dict]:
    """
    Extrae pares (nombre, dominio) de la tabla de bancos.
    Estrategia GENÉRICA (no depende de clases CSS específicas, que pueden
    cambiar): toma todos los enlaces <a href="http..."> del documento,
    excluye los que apuntan al propio sitio o a redes sociales, y usa el
    texto del enlace como nombre de la institución.
    """
    soup = BeautifulSoup(html, "html.parser")
    resultados = []
    vistos = set()

    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        if not href.startswith("http"):
            continue

        domain = _extract_domain(href)
        if not domain:
            continue
        # Excluir el dominio propio del sitio Y sus subdominios (ej.
        # "app1.banguat.gob.gt" es un módulo interno de Banguat, no un
        # banco — se coló en la primera prueba en vivo porque solo se
        # comparaba contra el dominio exacto, no contra subdominios).
        es_excluido = any(
            domain == excl or domain.endswith("." + excl)
            for excl in DOMINIOS_EXCLUIDOS
        )
        if es_excluido:
            continue

        nombre = a.get_text(strip=True)
        if not nombre or len(nombre) < 3:
            continue

        if domain in vistos:
            continue
        vistos.add(domain)

        resultados.append({"nombre": nombre, "domain": domain})

    return resultados


def scrape_bank_domains(timeout: int = 15) -> list[dict]:
    """
    Descarga la página de Banguat y extrae los dominios de bancos reales.
    Si falla la petición de red, devuelve el seed verificado como respaldo
    (con una advertencia en el log) en vez de dejar el sistema sin datos.

    Se fusiona con DOMINIOS_ADICIONALES_VERIFICADOS — casos donde una
    institución opera más de un dominio real que la fuente única (Banguat)
    no puede capturar por su propia estructura (un solo link por fila).
    """
    try:
        resp = requests.get(
            BANGUAT_URL,
            timeout=timeout,
            headers={"User-Agent": "PhishRadar-Research/1.0 (+educational project)"},
        )
        resp.raise_for_status()
        resultados = _parse_bank_links(resp.text)

        if not resultados:
            logger.warning(
                "El scraper no encontró ningún banco — la estructura de la "
                "página pudo haber cambiado. Usando seed verificado como respaldo."
            )
            resultados = [{"nombre": "(seed)", "domain": d} for d in SEED_BANCOS_GUATEMALA]
        else:
            logger.info(f"Scraper de bancos: {len(resultados)} dominios extraídos de Banguat")

    except requests.RequestException as e:
        logger.error(f"Error al scrapear Banguat: {e} — usando seed verificado")
        resultados = [{"nombre": "(seed)", "domain": d} for d in SEED_BANCOS_GUATEMALA]

    # Fusionar con las excepciones verificadas manualmente (sin duplicar)
    dominios_ya_presentes = {r["domain"] for r in resultados}
    for extra in DOMINIOS_ADICIONALES_VERIFICADOS:
        if extra["domain"] not in dominios_ya_presentes:
            resultados.append({"nombre": extra["nombre"], "domain": extra["domain"]})
            logger.info(f"Agregado dominio verificado manualmente: {extra['domain']}")

    return resultados


def verify_against_seed(resultados: list[dict]) -> dict:
    """
    Compara lo que el scraper extrajo contra el seed verificado manualmente.
    Útil para detectar si la página cambió de estructura sin que el scraper
    lo note silenciosamente (devolvería una lista vacía o incompleta).
    """
    extraidos = {r["domain"] for r in resultados}
    faltantes = SEED_BANCOS_GUATEMALA - extraidos
    nuevos = extraidos - SEED_BANCOS_GUATEMALA

    return {
        "total_extraidos": len(extraidos),
        "total_seed": len(SEED_BANCOS_GUATEMALA),
        "coinciden": len(extraidos & SEED_BANCOS_GUATEMALA),
        "faltantes_del_seed": sorted(faltantes),
        "nuevos_no_en_seed": sorted(nuevos),
    }


def sync_bank_domains_to_db() -> dict:
    """
    Ejecuta el scraper de bancos y guarda el resultado en la base de datos
    (SQLite local + Supabase si está disponible), igual que se hace con
    las URLs de phishing. Esta es la función que main.py llama para
    mantener la whitelist actualizada automáticamente.
    """
    from datetime import datetime, timezone
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from src.database import get_connection as get_local_connection

    resultados = scrape_bank_domains()
    now = datetime.now(timezone.utc).isoformat()

    with get_local_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS legitimate_domains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL UNIQUE,
                nombre TEXT,
                categoria TEXT NOT NULL,
                fuente TEXT NOT NULL,
                scraped_at TEXT NOT NULL
            )
        """)
        for r in resultados:
            conn.execute("""
                INSERT INTO legitimate_domains (domain, nombre, categoria, fuente, scraped_at)
                VALUES (?, ?, 'banco', 'banguat.gob.gt', ?)
                ON CONFLICT(domain) DO UPDATE SET scraped_at=excluded.scraped_at, nombre=excluded.nombre
            """, (r["domain"], r["nombre"], now))

    try:
        from src.cloud_database import is_available, get_connection as get_cloud_connection
        if is_available():
            conn = get_cloud_connection()
            with conn.cursor() as cur:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS legitimate_domains (
                        id SERIAL PRIMARY KEY,
                        domain TEXT NOT NULL UNIQUE,
                        nombre TEXT,
                        categoria TEXT NOT NULL,
                        fuente TEXT NOT NULL,
                        scraped_at TEXT NOT NULL
                    )
                """)
                for r in resultados:
                    cur.execute("""
                        INSERT INTO legitimate_domains (domain, nombre, categoria, fuente, scraped_at)
                        VALUES (%s, %s, 'banco', 'banguat.gob.gt', %s)
                        ON CONFLICT (domain) DO UPDATE SET scraped_at=%s, nombre=%s
                    """, (r["domain"], r["nombre"], now, now, r["nombre"]))
            conn.commit()
            conn.close()
            logger.info("Dominios legítimos sincronizados también a Supabase")
    except Exception as e:
        logger.warning(f"No se sincronizó a Supabase (modo local OK): {e}")

    return {"total": len(resultados), "categoria": "banco", "fuente": "banguat.gob.gt"}


def load_legitimate_domains_from_db() -> set[str]:
    """
    Carga todos los dominios legítimos guardados en la base de datos local.
    Se usa al arrancar la aplicación para alimentar refresh_legitimate_domains().
    """
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from src.database import get_connection

    try:
        with get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS legitimate_domains (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT NOT NULL UNIQUE,
                    nombre TEXT,
                    categoria TEXT NOT NULL,
                    fuente TEXT NOT NULL,
                    scraped_at TEXT NOT NULL
                )
            """)
            rows = conn.execute("SELECT domain FROM legitimate_domains").fetchall()
        return {row["domain"] for row in rows}
    except Exception as e:
        logger.warning(f"No se pudo cargar dominios legítimos de la DB: {e}")
        return set()