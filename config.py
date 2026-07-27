"""
PhishRadar — Configuración central
Edita este archivo para ajustar rutas, fuentes y parámetros.
"""

from pathlib import Path

# ── Rutas base ──────────────────────────────────────────────────────────────
BASE_DIR    = Path(__file__).parent
DATA_DIR    = BASE_DIR / "data"
LOGS_DIR    = BASE_DIR / "logs"
MODELS_DIR  = BASE_DIR / "models"
REPORTS_DIR = BASE_DIR / "reports"

DB_PATH = DATA_DIR / "phishradar.db"

# ── Fuentes de datos ─────────────────────────────────────────────────────────
SOURCES = {
    "openphish": {
        "url": "https://openphish.com/feed.txt",
        "enabled": True,
        "description": "Feed público de OpenPhish (URLs phishing activas)",
    },
    "phishtank": {
        "url": "http://data.phishtank.com/data/online-valid.csv",
        "enabled": False,   # Requiere API key; activar cuando la tengas
        "description": "Dataset validado de PhishTank (requiere key)",
    },
    "urlhaus": {
    "url": "https://urlhaus-api.abuse.ch/v1/urls/recent/",
    "enabled": True,
    "auth_key": "0c02e7f9e0b784e3c77362456f4ca840dd81c69a632c8943",
    "description": "URLhaus (abuse.ch) — URLs maliciosas activas",
},
}

# ── Marcas latinoamericanas para detección de similitud ─────────────────────
LATAM_BRANDS = [
    # Guatemala
    "banrural", "banguat", "bancogt", "bat", "tigo", "claro",
    "sat-gt", "igss", "renap", "mibanco",
    # Centroamérica / regional
    "baccredomatic", "bac", "scotiabank", "bancolombia",
    "mercadolibre", "mercadopago", "rappi", "uber",
    # Globales con presencia fuerte en LATAM
    "paypal", "amazon", "netflix", "facebook", "whatsapp",
    "instagram", "google", "microsoft", "apple",
]

# ── Parámetros de recolección ────────────────────────────────────────────────
FETCH_TIMEOUT    = 15       # segundos por request HTTP
MAX_URLS_PER_RUN = 5_000    # tope de URLs a procesar por ejecución
LOG_LEVEL        = "INFO"   # DEBUG | INFO | WARNING | ERROR
