"""
PhishRadar — Test suite de detección de typosquatting
Este archivo NO se modifica para acomodar el código.
El código tiene que pasar ESTAS pruebas, no al revés.

Ejecutar con: python tests/test_typosquatting.py
"""

# ── Casos que DEBEN detectarse como PHISHING (typosquatting) ──────────────────
CASOS_PHISHING = [
    # Sustitución de letra por número (leetspeak)
    "http://banrura1.com.gt",       # l -> 1
    "http://paypa1.com",
    "http://amaz0n.com",
    "http://netflixx-login1.com",   # doble x + número

    # Caracteres Unicode que parecen letras latinas
    "https://www.bænrural.com",     # æ -> a+e
    "https://båm.com.gt",           # å -> a
    "https://banrurāl.com.gt",      # ā -> a (macron)
    "https://amãzon.com",           # ã -> a (tilde)
    "https://bänrural.com",         # ä -> a (diéresis)

    # Doble letra / letra extra
    "http://banrurall.com",
    "http://faceboook.com",

    # Punto extra / typo de teclado
    "http://banrurāl..como.gt",     # doble punto + orden alterado

    # Marca + sufijo sospechoso (dominio corto, "limpio")
    "http://tigo-gt.xyz",
    "http://sat-gt-declaracion.tk",

    # Guiones insertados
    "http://ban-rural.com.gt",
    "http://pay-pal.com",

    # Homoglifos de otro alfabeto (cirílico/griego, visualmente idénticos)
    "http://аpple.com",              # а cirílica (U+0430), no la 'a' latina
    "http://gооgle.com",             # о cirílica (U+043E) x2
    "http://раypal.com",             # р y а cirílicas

    # Punycode (IDN) — la forma en que el navegador realmente ve el Unicode
    "http://xn--banrural-19a.com",

    # Suplantación por subdominio — la marca real es decoración, no el dominio real
    "http://banrural.com.gt.verificar-ahora.xyz",
    "http://www.paypal.com.confirmar-datos.tk",

    # Palabras genéricas (español/inglés) pegadas a la marca
    "http://bancobanrural.com",
    "http://banrural-oficial.com",
    "http://appbanrural.com",
    "http://webpaypal.com",

    # Imitación de ".com.gt" con guiones en vez de puntos
    "http://banrural-com-gt.verificar-cuenta.xyz",
    "http://tigo-com-gt.pagos-online.net",

    # Marca real incrustada EN MEDIO del dominio, no solo al inicio
    "http://xyz123.banrural.com.gt.phish.ru",
    "http://cdn.amazon.com.actualizacion-urgente.top",

    # Leetspeak combinado con palabra de alerta/seguridad
    "http://faceb00k-security-alert.com",

    # Script mixto (latín + cirílico/griego) SIN marca conocida —
    # prueba de que no depende de la whitelist para detectar el ataque
    "http://unіversity-becas-gt.com",     # і cirílica (U+0456)
    "http://sсholarship-portal.net",       # с cirílica (U+0441)

    # Reordenamiento de TLD (imita ".com.gt" invertido)
    "http://banrural.gt.com",
    # Omisión de letra (typo real, no solo sustitución)
    "http://banrual.com.gt",
    # Sufijo aleatorio alfanumérico (patrón de generación automática)
    "http://banruralxk9281.com",

    # Caracteres invisibles insertados (múltiples, para romper la
    # tolerancia de distancia de edición si solo se limpiara "por suerte")
    "http://b\u200ba\u200bn\u200br\u200bu\u200br\u200ba\u200bl.com.gt",

    # SIN esquema (http://) — el bug real que se encontró probando en
    # el dashboard: la gente escribe URLs a mano sin "http://" al inicio
    "banrurall.com.gt",
    "banrura1.com",
    "www.paypal-secure-login.tk",

    # Lote de prueba real del usuario — marca corta "bam" (3 letras) con
    # æ como homoglifo de "a" (el bug real encontrado: æ se expandía a
    # "ae", rompiendo la comparación contra marcas cortas)
    "https://bæm-login.com.gt",
    "https://bãm-login.com.gt",
    "https://båm-login.com.gt",
    "https://bÄm-login.com.gt",
    "https://bam-login.com.gt",
    "https://bam1.com.gt",
    "http://bäm-log1n.com.gt",
    "https://banrural-login.com.gt",
]

# ── Casos que DEBEN detectarse como LEGÍTIMOS ──────────────────────────────────
CASOS_LEGITIMOS = [
    "https://www.banrural.com.gt",
    "https://baccredomatic.com/es-gt",
    "https://www.google.com",
    "https://www.amazon.com",
    "https://www.netflix.com/gt",
    "https://portal.sat.gob.gt",
    "https://www.tigo.com.gt",
    "https://www.paypal.com",
    "https://www.facebook.com",
    "https://usac.edu.gt",           # institución que antes no se reconocía
    "https://www.mercadolibre.com.gt",

    # Control anti-falso-positivo: dominios legítimos que contienen palabras
    # genéricas (url, portal, app, web) que NO deben tratarse como "marca"
    "https://tinyurl.com",
    "https://www.bit-url-shortener-example.com",
    "https://customer-portal-empresa.com",

    # Control: marcas que también son palabras comunes del idioma —
    # no deben marcarse falso positivo cuando se usan en su sentido genérico
    "https://applepie-recipes.com",
    "https://ubertechnologies-consulting.com",

    # SIN esquema, dominio real, para confirmar que no se rompe lo legítimo
    "banrural.com.gt",
    "www.google.com",
]


def run_tests(detector_func):
    """
    Corre el set de pruebas contra una función detectora.
    detector_func(url) debe devolver True si es phishing, False si es legítimo.
    """
    print("\n" + "═" * 65)
    print("  PhishRadar — Test Suite de Typosquatting")
    print("═" * 65)

    fallos = []

    print("\n🔴 Casos que DEBEN marcar PHISHING:")
    aciertos_phishing = 0
    for url in CASOS_PHISHING:
        resultado = detector_func(url)
        ok = resultado is True
        aciertos_phishing += int(ok)
        icono = "✅" if ok else "❌"
        print(f"  {icono}  {url}")
        if not ok:
            fallos.append(("FALSO NEGATIVO", url))

    print(f"\n  → {aciertos_phishing}/{len(CASOS_PHISHING)} detectados correctamente")

    print("\n🟢 Casos que DEBEN marcar LEGÍTIMO:")
    aciertos_legit = 0
    for url in CASOS_LEGITIMOS:
        resultado = detector_func(url)
        ok = resultado is False
        aciertos_legit += int(ok)
        icono = "✅" if ok else "❌"
        print(f"  {icono}  {url}")
        if not ok:
            fallos.append(("FALSO POSITIVO", url))

    print(f"\n  → {aciertos_legit}/{len(CASOS_LEGITIMOS)} detectados correctamente")

    total = len(CASOS_PHISHING) + len(CASOS_LEGITIMOS)
    aciertos = aciertos_phishing + aciertos_legit

    print("\n" + "─" * 65)
    print(f"  RESULTADO FINAL: {aciertos}/{total} ({aciertos/total:.1%})")
    print("─" * 65)

    if fallos:
        print("\n  ⚠️  Casos fallidos:")
        for tipo, url in fallos:
            print(f"    [{tipo}] {url}")
    else:
        print("\n  🎉 Todos los casos pasaron.")

    print("═" * 65 + "\n")

    return aciertos == total


if __name__ == "__main__":
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent.parent))

    from src.features import is_typosquat  # función que vamos a construir

    exito = run_tests(is_typosquat)
    sys.exit(0 if exito else 1)