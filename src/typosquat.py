"""
PhishRadar — Detección de typosquatting (v2, rediseñada)

DISEÑO:
- Es una REGLA DURA, no una feature del modelo ML. Si detecta typosquatting,
  la URL se marca ALTO RIESGO sin pasar por el Random Forest.
- La normalización Unicode usa el mecanismo GENÉRICO de la librería estándar
  (NFKD + eliminación de diacríticos), no un diccionario manual de caracteres.
- El leetspeak (0->o, 1->l, etc.) se resuelve generando variantes, no
  reemplazando a ciegas (para no romper dominios legítimos que usan números).
- Los dominios "legítimos" son una lista blanca explícita — cualquier dominio
  que NO esté ahí se evalúa contra typosquatting.
"""

import re
import unicodedata
from urllib.parse import urlparse

try:
    from Levenshtein import distance as levenshtein_distance
except ImportError:
    def levenshtein_distance(a: str, b: str) -> int:
        """Fallback puro Python si la librería no está instalada."""
        if len(a) < len(b):
            a, b = b, a
        if len(b) == 0:
            return len(a)
        previous = list(range(len(b) + 1))
        for i, ca in enumerate(a):
            current = [i + 1]
            for j, cb in enumerate(b):
                ins = previous[j + 1] + 1
                dele = current[j] + 1
                sub = previous[j] + (ca != cb)
                current.append(min(ins, dele, sub))
            previous = current
        return previous[-1]


# ── Dominios legítimos conocidos (whitelist) ──────────────────────────────────
# Este es el SEED — el respaldo de emergencia si la base de datos no está
# disponible (sin internet, tests offline, o la tabla aún vacía). NO es la
# fuente de verdad en producción: eso es la tabla `legitimate_domains`,
# alimentada por scrapers reales (src/domain_scraper.py) que consultan
# fuentes oficiales (Banguat, y próximamente gobierno/universidades).
SEED_LEGITIMATE_DOMAINS = {
    "banrural.com.gt", "baccredomatic.com", "bam.com.gt",
    "bancolombia.com", "scotiabank.com.gt",
    "tigo.com.gt", "claro.com.gt",
    "sat.gob.gt", "portal.sat.gob.gt", "igss.gob.gt", "renap.gob.gt",
    "usac.edu.gt", "url.edu.gt", "galileo.edu",
    "mercadolibre.com", "mercadolibre.com.gt", "mercadopago.com",
    "rappi.com", "uber.com",
    "google.com", "facebook.com", "instagram.com", "whatsapp.com",
    "amazon.com", "netflix.com", "paypal.com", "apple.com",
    "microsoft.com", "twitter.com", "linkedin.com", "github.com",
}

# Alias por compatibilidad con código/tests existentes que ya usan este nombre.
LEGITIMATE_DOMAINS = set(SEED_LEGITIMATE_DOMAINS)

# Nombre "core" de cada marca (sin TLD) — se deriva automáticamente
# de LEGITIMATE_DOMAINS, no se mantiene una segunda lista a mano.
#
# IMPORTANTE: se excluyen labels genéricos (palabras del diccionario común
# en español/inglés que aparecen como primer segmento de un dominio legítimo
# por razones administrativas, ej. "portal.sat.gob.gt" o "url.edu.gt") porque
# usarlos como "marca" para comparación por substring genera falsos positivos
# graves en dominios legítimos no relacionados (ej. "url" coincidía con
# "tinyurl.com", un servicio real). Estos dominios SIGUEN protegidos como
# legítimos vía LEGITIMATE_DOMAINS — solo no se usan como ancla de detección.
GENERIC_LABELS = {
    "portal", "url", "www", "mail", "app", "web", "api", "my", "mi",
    "online", "secure", "admin", "login", "account", "support",
    "help", "shop", "store", "info", "news", "blog",
}

def _brand_cores(domains: set[str]) -> set[str]:
    """
    Extrae los "nombres core" de cada marca legítima para comparación.
    Además del label completo (ej. "bancopromerica"), también registra
    la variante sin el prefijo genérico "banco"/"bank" (ej. "promerica")
    cuando aplica — porque un atacante frecuentemente omite ese prefijo
    al registrar el dominio falso (ej. "promerica.com" en vez de
    "bancopromerica.com"), y sin esto esa variante quedaba completamente
    desprotegida aunque el nombre completo sí estuviera en la whitelist.
    """
    PREFIJOS_BANCARIOS = ("banco", "bank")
    cores = set()
    for domain in domains:
        first_label = domain.split(".")[0]
        if len(first_label) < 3 or first_label in GENERIC_LABELS:
            continue
        cores.add(first_label)

        for prefijo in PREFIJOS_BANCARIOS:
            if first_label.startswith(prefijo) and len(first_label) > len(prefijo):
                resto = first_label[len(prefijo):]
                if len(resto) >= 3 and resto not in GENERIC_LABELS:
                    cores.add(resto)
    return cores

BRAND_CORES = _brand_cores(LEGITIMATE_DOMAINS)


def refresh_legitimate_domains(extra_domains: set[str] = None) -> int:
    """
    Actualiza la whitelist en tiempo de ejecución, mezclando el seed fijo
    con dominios adicionales (típicamente cargados desde la base de datos,
    alimentada por los scrapers). Recalcula BRAND_CORES en consecuencia.

    Se llama explícitamente al arrancar la aplicación real (main.py,
    dashboard.py) — el import normal del módulo (usado por los tests)
    NUNCA llama esto, por lo que los tests siguen siendo 100% offline
    y deterministas, sin depender de la base de datos ni de internet.

    Devuelve la cantidad total de dominios en la whitelist tras la mezcla.
    """
    global LEGITIMATE_DOMAINS, BRAND_CORES
    nuevos = set(SEED_LEGITIMATE_DOMAINS)
    if extra_domains:
        nuevos |= {d.lower().strip() for d in extra_domains if d}
    LEGITIMATE_DOMAINS = nuevos
    BRAND_CORES = _brand_cores(LEGITIMATE_DOMAINS)
    return len(LEGITIMATE_DOMAINS)


# ── Normalización Unicode genérica (sin diccionario manual) ──────────────────

def normalize_unicode(text: str) -> str:
    """
    Convierte cualquier carácter Unicode acentuado/decorado a su forma base.
    æ, å, ā, ã, ä -> a  |  ñ -> n  |  ç -> c  |  etc.
    Funciona para CUALQUIER combinación, no solo las que enumeremos a mano
    (gracias a NFKD), MÁS una tabla explícita de homoglifos de otros alfabetos
    (cirílico, griego) que NFKD no resuelve porque son scripts distintos,
    no variantes acentuadas del mismo alfabeto.
    """
    text = text.lower()

    # Homoglifos de otros alfabetos — visualmente idénticos a letras latinas
    # pero con punto de código distinto. NFKD NO los normaliza porque no son
    # "la misma letra con acento", son letras de OTRO alfabeto que se dibujan igual.
    HOMOGLYPHS = {
        # Cirílico -> Latino
        "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
        "у": "y", "х": "x", "і": "i", "ѕ": "s", "һ": "h",
        "ј": "j", "ԁ": "d", "ѡ": "w", "ц": "u", "ѵ": "v",
        # Griego -> Latino
        "α": "a", "ο": "o", "ρ": "p", "ν": "v", "υ": "u",
        "κ": "k", "ι": "i", "χ": "x",
        # æ y œ se tratan como homoglifos 1-a-1 de "a" y "o", NO como
        # ligadura lingüística "ae"/"oe". Para detección de suplantación
        # visual, un atacante que usa æ está imitando la LETRA "a", no
        # agregando una "e" extra — expandir a 2 caracteres rompía la
        # comparación exacta contra marcas cortas (ej. "bæm" -> "baem"
        # ya no calzaba con la marca real "bam", de 3 letras).
        "æ": "a", "œ": "o",
    }
    for homoglifo, base in HOMOGLYPHS.items():
        text = text.replace(homoglifo, base)

    nfkd = unicodedata.normalize("NFKD", text)
    sin_diacriticos = "".join(c for c in nfkd if not unicodedata.combining(c))
    ligaduras = {"ø": "o", "þ": "th", "ð": "d"}
    for lig, base in ligaduras.items():
        sin_diacriticos = sin_diacriticos.replace(lig, base)
    return sin_diacriticos


def normalize_leetspeak(text: str) -> str:
    """
    Normaliza sustituciones leetspeak comunes SOLO para efectos de comparación
    contra marcas conocidas (no se usa para mostrar el dominio, solo para detectar).
    """
    mapping = str.maketrans({
        "0": "o", "1": "l", "3": "e", "4": "a",
        "5": "s", "7": "t", "@": "a", "$": "s",
    })
    return text.translate(mapping)


SUSPICIOUS_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".icu"}

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "secure", "security", "account", "verify", "confirm",
    "banking", "suspended", "validate", "password", "recover",
    "declaracion", "renovar", "actualizar", "clave", "acceso",
    "factura", "pago", "pagos", "tarjeta", "saldo", "recarga",
    "premio", "promo", "oferta", "gratis", "alert", "alerta",
    "banco", "bank", "oficial", "official", "app", "web", "portal",
    "online", "digital", "virtual", "soporte", "ayuda", "support",
    "cliente", "clientes", "centro", "nuevo", "nueva",
    # Palabras en español que faltaban — muy comunes en phishing LATAM
    "seguro", "segura", "verificar", "confirmar", "validar",
    "restringido", "bloqueado", "bloqueada", "activar", "activacion",
]

# El código de país (ej. "gt") se trata aparte del resto de keywords porque
# es una señal distinta: replicar ".com.gt" con guiones en vez de puntos
# para imitar visualmente el dominio real (ej. "banrural-com-gt.evil.xyz").
# Es un patrón intencional documentado, no una coincidencia de substring.
COUNTRY_CODE_MIMICRY = ["gt", "mx", "cr", "sv", "hn", "ni", "pa"]


def _has_non_ascii(text: str) -> bool:
    """True si el texto original contiene caracteres fuera de ASCII."""
    return any(ord(c) > 127 for c in text)


def _strip_invisible_chars(text: str) -> tuple[str, bool]:
    """
    Elimina caracteres Unicode invisibles (zero-width space/joiner, marcas
    de dirección de texto, BOM, etc. — categoría Unicode "Cf" = Format).
    Estos caracteres no tienen representación visual: su único propósito
    en un dominio es romper comparaciones de texto/distancia de edición
    mientras el dominio se ve idéntico al ojo humano. Se eliminan SIEMPRE,
    sin importar cuántos haya, en vez de depender de que la tolerancia de
    Levenshtein los "absorba" por casualidad (lo cual falla con 3+ inserciones).
    Devuelve (texto_limpio, tenia_invisibles).
    """
    limpio = "".join(c for c in text if unicodedata.category(c) != "Cf")
    return limpio, (limpio != text)


def _ensure_scheme(url: str) -> str:
    """
    Garantiza que la URL tenga esquema (http://) antes de parsear.
    Sin esto, urlparse('banrural.com.gt').hostname devuelve None —
    Python interpreta todo el string como una "ruta", no como un host,
    cuando falta el "://". Esto es exactamente lo que pasa cuando un
    usuario escribe una URL a mano sin el protocolo (muy común en el
    mundo real: la gente escribe "banrural.com" sin "http://").
    """
    if not url:
        return url
    if "://" not in url:
        return "http://" + url
    return url


def _label_script_mix(label: str) -> bool:
    """
    Detecta si un label mezcla alfabetos distintos (ej. latín + cirílico).
    Esta es la misma heurística que usan Chrome/Firefox para decidir si
    mostrar un dominio IDN decodificado o dejarlo en punycode crudo —
    mezclar scripts dentro de una sola palabra casi nunca tiene uso legítimo.
    A diferencia de la comparación contra BRAND_CORES, esta regla NO depende
    de que la marca imitada esté en nuestra whitelist — detecta el ataque
    aunque sea contra una institución que nunca agregamos a la lista.
    """
    tiene_latin = False
    tiene_cirilico = False
    tiene_griego = False
    for ch in label:
        cp = ord(ch)
        if (0x0041 <= cp <= 0x005A) or (0x0061 <= cp <= 0x007A):
            tiene_latin = True
        elif 0x0400 <= cp <= 0x04FF:
            tiene_cirilico = True
        elif 0x0370 <= cp <= 0x03FF:
            tiene_griego = True
    return tiene_latin and (tiene_cirilico or tiene_griego)


def _decode_punycode(domain: str) -> tuple[str, bool]:
    """
    Decodifica dominios punycode (xn--...) a su forma Unicode real.
    Devuelve (dominio_decodificado, era_punycode).
    Esto detecta el mismo ataque homógrafo pero codificado en ASCII puro,
    que es como los navegadores reciben el dominio realmente.
    """
    if "xn--" not in domain:
        return domain, False
    try:
        labels = domain.split(".")
        decoded = [
            label.encode("ascii").decode("idna") if label.startswith("xn--") else label
            for label in labels
        ]
        return ".".join(decoded), True
    except Exception:
        return domain, True  # si falla decodificar, sigue siendo sospechoso


def _extract_domain_core(url: str) -> tuple[str, str, bool]:
    """
    Devuelve (dominio_completo_normalizado, label_principal_sin_tld, tenia_unicode).
    `tenia_unicode` indica si el dominio ORIGINAL usaba caracteres no-ASCII
    O codificación punycode (señal de posible ataque homógrafo).
    Usa urlparse().hostname (no .netloc) para que userinfo ("user:pass@")
    y puerto (":8080") no contaminen el dominio extraído — un bug real que
    causaba tanto falsos negativos (userinfo rompía el parsing) como falsos
    positivos (puerto pegado al TLD rompía la comparación con la whitelist).
    """
    try:
        url = _ensure_scheme(url)
        raw_domain = (urlparse(url).hostname or "").lower()
    except Exception:
        return "", "", False

    if raw_domain.startswith("www."):
        raw_domain = raw_domain[4:]

    raw_domain, tenia_invisibles = _strip_invisible_chars(raw_domain)
    raw_domain, era_punycode = _decode_punycode(raw_domain)
    tenia_unicode = _has_non_ascii(raw_domain) or era_punycode or tenia_invisibles

    domain = normalize_unicode(raw_domain)
    domain = re.sub(r"\.{2,}", ".", domain)  # puntos duplicados accidentales
    labels = [l for l in domain.split(".") if l]
    main_label = labels[0] if labels else domain
    return domain, main_label, tenia_unicode


# ── Función principal — regla dura ────────────────────────────────────────────

def is_typosquat(url) -> bool:
    """
    Devuelve True si la URL es typosquatting de una marca conocida.
    Esta es una REGLA DURA — no depende del modelo ML.
    """
    if not url or not isinstance(url, str):
        return False

    url = _ensure_scheme(url)
    domain, main_label, tenia_unicode = _extract_domain_core(url)
    if not domain:
        return False
    tld = "." + domain.split(".")[-1] if "." in domain else ""

    # -1. Mezcla de alfabetos dentro de un mismo label — señal fuerte de
    #     ataque IDN/homógrafo, INDEPENDIENTE de si la marca imitada está
    #     en nuestra whitelist. Se revisa sobre el dominio original, antes
    #     de cualquier normalización (que ya habría convertido los caracteres
    #     y ocultado la mezcla).
    raw_domain = (urlparse(url).hostname or "").lower()
    raw_labels = raw_domain.split(".")
    if any(_label_script_mix(label) for label in raw_labels):
        return True

    normalized_whitelist = {normalize_unicode(d) for d in LEGITIMATE_DOMAINS}
    es_match_whitelist = domain in normalized_whitelist or any(
        domain.endswith("." + w) for w in normalized_whitelist
    )

    # 0. Suplantación por subdominio: la marca real aparece como decoración
    #    en algún punto del dominio (al inicio o en medio), pero el dominio
    #    que realmente controla el atacante es el segmento final.
    #    Cubre tanto "banrural.com.gt.evil.xyz" (prefijo) como
    #    "xyz.banrural.com.gt.evil.xyz" (marca en medio, no al inicio).
    #    IMPORTANTE: primero se descarta si el dominio completo YA ES
    #    legítimo por sí mismo (ej. "mercadolibre.com.gt" contiene a
    #    "mercadolibre.com" como prefijo textual, pero es su propio dominio
    #    real, no un ataque).
    if not es_match_whitelist:
        for w in normalized_whitelist:
            if ("." + w + ".") in ("." + domain + "."):
                return True

    # 1. Ataque homógrafo: el dominio ORIGINAL usaba caracteres Unicode raros
    #    (å, ā, ã, æ...) y al normalizarlos coincide con una marca real.
    #    Un dominio legítimo real nunca usa esos caracteres — que coincida
    #    tras normalizar es justamente la técnica del ataque, no una prueba
    #    de inocencia.
    if tenia_unicode and es_match_whitelist:
        return True

    # 2. Si coincide con la whitelist y NO tenía Unicode raro -> es legítimo real
    if es_match_whitelist:
        return False

    # 3. Comparar el label principal contra cada marca conocida
    label_variants = {
        main_label,
        normalize_leetspeak(main_label),
        re.sub(r"[-_]", "", main_label),
        re.sub(r"[-_]", "", normalize_leetspeak(main_label)),
    }

    for brand in BRAND_CORES:
        for variant in label_variants:
            if not variant:
                continue

            if variant == brand:
                return True

            # Distancia de edición — typosquatting clásico (banrurall, paypa1...)
            if len(brand) >= 4:
                dist = levenshtein_distance(variant, brand)
                threshold = 1 if len(brand) <= 6 else 2
                if 0 < dist <= threshold:
                    return True

            # Marca + texto extra pegado (guiones, sufijos, keywords de phishing)
            if brand in variant and variant != brand:
                extra = variant.replace(brand, "", 1)
                extra_es_corto = len(extra) <= 4
                extra_tiene_keyword = any(kw in extra for kw in SUSPICIOUS_KEYWORDS)
                tld_sospechoso = tld in SUSPICIOUS_TLDS
                # Sufijo tipo "xk9281" — mezcla letras y números, patrón típico
                # de generación automática de dominios de campaña, a diferencia
                # de una palabra real del idioma (ej. "pierecipes", "technologies")
                # que NUNCA mezcla dígitos así. Esto evita marcar negocios
                # legítimos que casualmente usan una palabra común como marca
                # (ej. "applepie-recipes.com", "ubertechnologies.com").
                extra_parece_random = bool(re.search(r"\d", extra)) and len(extra) <= 10

                marca_corta_tld_sospechoso = len(brand) <= 4 and tld_sospechoso
                # Marca como PREFIJO exacto (no en cualquier posición) + TLD
                # sospechoso — sin importar longitud de marca. Exigir prefijo
                # (no solo "contiene") reduce el riesgo de falsos positivos
                # en dominios que casualmente incluyen la marca en medio de
                # otra palabra no relacionada.
                marca_prefijo_tld_sospechoso = variant.startswith(brand) and tld_sospechoso

                if extra_es_corto:
                    return True
                if extra_tiene_keyword:
                    return True
                if extra_parece_random:
                    return True
                if marca_corta_tld_sospechoso:
                    return True
                if marca_prefijo_tld_sospechoso:
                    return True

    # 4. Imitación de ".com.gt" (u otro ccTLD LATAM) usando GUIONES en vez de
    #    puntos — ej. "banrural-com-gt.evil.xyz" — para que a simple vista
    #    parezca "banrural.com.gt". Se revisa por TOKEN exacto, no por
    #    substring, para no disparar con palabras que casualmente contengan
    #    esas dos letras.
    tokens = main_label.split("-")
    if "com" in tokens:
        idx_com = tokens.index("com")
        resto = tokens[idx_com + 1:]
        if any(t in COUNTRY_CODE_MIMICRY for t in resto):
            marca_presente = any(
                brand in tokens or brand in normalize_leetspeak("".join(tokens))
                for brand in BRAND_CORES
            )
            if marca_presente:
                return True

    return False


def typosquat_details(url: str) -> dict:
    """Devuelve el detalle de por qué se marcó (o no) como typosquatting."""
    domain, main_label, tenia_unicode = _extract_domain_core(url)
    resultado = is_typosquat(url)
    return {
        "url": url,
        "domain_normalizado": domain,
        "label_principal": main_label,
        "tenia_unicode_o_punycode": tenia_unicode,
        "es_typosquat": resultado,
    }