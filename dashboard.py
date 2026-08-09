"""
PhishRadar — Dashboard (Capa 4)
Interfaz visual con Streamlit.
Correr con: streamlit run dashboard.py
"""

import sys
import json
import sqlite3
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent))

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

from config import DB_PATH, MODELS_DIR, REPORTS_DIR
from src.database   import init_db, get_stats, get_connection
from src.model      import predict, train
from src.clustering import detect_campaigns
from src.reporter   import save_campaign_report

#agregada el 8.8.26
from src.typosquat import refresh_legitimate_domains
from src.domain_scraper import load_legitimate_domains_from_db
refresh_legitimate_domains(extra_domains=load_legitimate_domains_from_db())

from src.typosquat import refresh_legitimate_domains, LEGITIMATE_DOMAINS
from src.domain_scraper import load_legitimate_domains_from_db

_extra = load_legitimate_domains_from_db()
_total = refresh_legitimate_domains(extra_domains=_extra)

st.write(f"DEBUG — dominios cargados de la DB: {len(_extra)}")
st.write(f"DEBUG — total en whitelist: {_total}")
st.write(f"DEBUG — ¿bancoazteca.com.gt está?: {'bancoazteca.com.gt' in LEGITIMATE_DOMAINS}")
st.write(f"DEBUG — primeros 10: {sorted(LEGITIMATE_DOMAINS)[:10]}")

# ── Configuración de página ───────────────────────────────────────────────────

st.set_page_config(
    page_title="PhishRadar",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# CSS mínimo para mejorar la apariencia
st.markdown("""
<style>
    .metric-card {
        background: #1e1e2e;
        border-radius: 10px;
        padding: 1rem;
        border-left: 4px solid #7c3aed;
    }
    .risk-alto   { color: #ef4444; font-weight: bold; }
    .risk-medio  { color: #f59e0b; font-weight: bold; }
    .risk-bajo   { color: #22c55e; font-weight: bold; }
    .stTabs [data-baseweb="tab"] { font-size: 1rem; }
</style>
""", unsafe_allow_html=True)


# ── Helpers ───────────────────────────────────────────────────────────────────

@st.cache_data(ttl=60)
def load_stats():
    from src.cloud_database import is_available, get_cloud_stats
    if is_available():
        stats = get_cloud_stats()
        if stats:
            return stats
    init_db()
    return get_stats()


@st.cache_data(ttl=60)
def load_urls(limit: int = 2000) -> pd.DataFrame:
    from src.cloud_database import is_available, get_cloud_urls
    if is_available():
        rows = get_cloud_urls(limit)
        if rows:
            return pd.DataFrame(rows)
    with get_connection() as conn:
        rows = conn.execute(
            """SELECT url, domain, source, first_seen, last_seen,
                      is_active, brand_hit, tld, url_length
               FROM urls ORDER BY first_seen DESC LIMIT ?""",
            (limit,)
        ).fetchall()
    if not rows:
        return pd.DataFrame()
    return pd.DataFrame([dict(r) for r in rows])


@st.cache_data(ttl=300)
def load_metrics() -> dict | None:
    path = MODELS_DIR / "last_metrics.json"
    if not path.exists():
        return None
    with open(path) as f:
        return json.load(f)


def risk_badge(score: float) -> str:
    if score >= 0.8:
        return "🔴 ALTO"
    elif score >= 0.5:
        return "🟡 MEDIO"
    return "🟢 BAJO"


# ── Sidebar ───────────────────────────────────────────────────────────────────

with st.sidebar:
    st.image("https://img.icons8.com/fluency/96/shield.png", width=60)
    st.title("PhishRadar 🛡️")
    st.caption("Detección de phishing para LATAM")
    st.divider()

    page = st.radio(
        "Navegación",
        ["📊 Dashboard", "🔍 Analizar URL", "🎯 Campañas", "🤖 Modelo ML", "📋 Base de datos"],
        label_visibility="collapsed",
    )

    st.divider()
    stats = load_stats()
    st.metric("Total URLs", f"{stats['total']:,}")
    st.metric("URLs activas", f"{stats['active']:,}")
    st.metric("Con marca LATAM", f"{stats['with_brand']:,}")

    st.divider()
    st.caption(f"DB: `{DB_PATH.name}`")
    st.caption("PhishRadar v1.0 · Capa 4")


# ══════════════════════════════════════════════════════════════════════════════
# PÁGINA: Dashboard
# ══════════════════════════════════════════════════════════════════════════════

if page == "📊 Dashboard":
    st.title("📊 Dashboard General")
    st.caption(f"Actualizado: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}")

    df = load_urls()

    if df.empty:
        st.warning("No hay datos en la base de datos todavía.")
        st.info("Corre en terminal: `python main.py --demo` para cargar datos de prueba.")
        st.stop()

    # ── Métricas principales
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total URLs", f"{stats['total']:,}")
    col2.metric("URLs activas", f"{stats['active']:,}")
    col3.metric("Con marca LATAM", f"{stats['with_brand']:,}")
    coverage = round(stats['with_brand'] / stats['total'] * 100, 1) if stats['total'] else 0
    col4.metric("Cobertura LATAM", f"{coverage}%")

    st.divider()

    # ── Gráficas
    col_a, col_b = st.columns(2)

    with col_a:
        st.subheader("Top TLDs sospechosos")
        if stats["by_tld"]:
            tld_df = pd.DataFrame(stats["by_tld"])
            fig = px.bar(
                tld_df, x="n", y="tld", orientation="h",
                color="n", color_continuous_scale="reds",
                labels={"n": "URLs", "tld": "TLD"},
            )
            fig.update_layout(showlegend=False, height=300, margin=dict(l=0, r=0, t=0, b=0))
            st.plotly_chart(fig, use_container_width=True)

    with col_b:
        st.subheader("Marcas LATAM más suplantadas")
        if stats["by_brand"]:
            brand_df = pd.DataFrame(stats["by_brand"])
            fig = px.pie(
                brand_df, values="n", names="brand_hit",
                color_discrete_sequence=px.colors.sequential.RdBu,
                hole=0.4,
            )
            fig.update_layout(height=300, margin=dict(l=0, r=0, t=0, b=0))
            st.plotly_chart(fig, use_container_width=True)

    # ── Línea de tiempo
    if "first_seen" in df.columns:
        st.subheader("URLs detectadas por día")
        df["fecha"] = pd.to_datetime(df["first_seen"]).dt.date
        timeline = df.groupby("fecha").size().reset_index(name="count")
        fig = px.area(
            timeline, x="fecha", y="count",
            color_discrete_sequence=["#7c3aed"],
            labels={"fecha": "Fecha", "count": "URLs"},
        )
        fig.update_layout(height=250, margin=dict(l=0, r=0, t=10, b=0))
        st.plotly_chart(fig, use_container_width=True)

    # ── Tabla reciente
    st.subheader("Últimas URLs detectadas")
    display_cols = ["url", "domain", "brand_hit", "tld", "source", "first_seen"]
    available = [c for c in display_cols if c in df.columns]
    st.dataframe(df[available].head(20), use_container_width=True, hide_index=True)


# ══════════════════════════════════════════════════════════════════════════════
# PÁGINA: Analizar URL
# ══════════════════════════════════════════════════════════════════════════════

elif page == "🔍 Analizar URL":
    st.title("🔍 Analizar URL")
    st.caption("Ingresa una o varias URLs para saber si son phishing.")

    url_input = st.text_area(
        "URLs a analizar (una por línea)",
        placeholder="https://ejemplo.com\nhttp://banco-verificar.xyz/login",
        height=150,
    )

    col_btn, col_info = st.columns([1, 3])
    with col_btn:
        analizar = st.button("🔍 Analizar", type="primary", use_container_width=True)

    if analizar and url_input.strip():
        urls = [u.strip() for u in url_input.strip().splitlines() if u.strip()]

        metrics_exist = (MODELS_DIR / "phishradar_model.pkl").exists()
        if not metrics_exist:
            st.warning("El modelo no está entrenado. Entrénalo primero en la sección **Modelo ML**.")
            st.stop()

        with st.spinner(f"Analizando {len(urls)} URL(s)..."):
            results = predict(urls)

        
        st.divider()
        for r in results:
            score_pct = r["score"] * 100
            with st.container():
                col1, col2, col3 = st.columns([3, 1, 2])
                with col1:
                    st.markdown(f"**`{r['url']}`**")
                    st.caption(f"Señales: {', '.join(r['top_signals'])}")
                with col2:
                    st.markdown(f"### {r['risk']}")
                with col3:
                    st.progress(r["score"], text=f"{score_pct:.1f}% phishing")
                st.divider()

    elif analizar:
        st.warning("Ingresa al menos una URL para analizar.")


# ══════════════════════════════════════════════════════════════════════════════
# PÁGINA: Campañas
# ══════════════════════════════════════════════════════════════════════════════

elif page == "🎯 Campañas":
    st.title("🎯 Detección de Campañas")
    st.caption("Agrupa URLs por similitud de infraestructura para identificar actores maliciosos.")

    col1, col2, col3 = st.columns(3)
    with col1:
        eps = st.slider("Sensibilidad (eps)", 0.5, 3.0, 1.2, 0.1,
                        help="Menor = clusters más estrictos. Mayor = más URLs agrupadas.")
    with col2:
        min_samples = st.slider("Mín. URLs por campaña", 2, 10, 2,
                                help="Mínimo de URLs para considerar una campaña.")
    with col3:
        limit = st.selectbox("URLs a analizar", [100, 500, 1000, 2000], index=1)

    detectar = st.button("🎯 Detectar campañas", type="primary")

    if detectar:
        with get_connection() as conn:
            rows = conn.execute(
                "SELECT url FROM urls WHERE is_active=1 ORDER BY first_seen DESC LIMIT ?",
                (limit,)
            ).fetchall()
        urls = [r["url"] for r in rows]

        if not urls:
            st.warning("No hay URLs en la DB. Corre `python main.py --demo` primero.")
            st.stop()

        with st.spinner(f"Analizando {len(urls)} URLs..."):
            result = detect_campaigns(urls, eps=eps, min_samples=min_samples)
            save_campaign_report(result)

        summary   = result["summary"]
        campaigns = result["campaigns"]

        # Métricas
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("URLs analizadas",   summary["total_urls"])
        c2.metric("Campañas detectadas", summary["n_campaigns"])
        c3.metric("URLs aisladas",     summary["n_outliers"])
        c4.metric("Cobertura",         f"{summary['coverage']:.1%}")

        st.divider()

        if not campaigns:
            st.info("No se detectaron campañas. Prueba aumentando la sensibilidad (eps).")
        else:
            for cid, camp in campaigns.items():
                with st.expander(
                    f"🎯 Campaña #{int(cid)+1} — {camp['risk_level']} — {camp['url_count']} URLs",
                    expanded=True,
                ):
                    col_a, col_b, col_c = st.columns(3)
                    col_a.metric("URLs", camp["url_count"])
                    col_b.metric("Score riesgo", camp["risk_score"])
                    col_c.metric("Marca suplantada", "Sí" if camp["brand_targeted"] else "No")

                    col_d, col_e = st.columns(2)
                    with col_d:
                        if camp["top_tlds"]:
                            tld_df = pd.DataFrame(
                                list(camp["top_tlds"].items()), columns=["TLD", "count"]
                            )
                            fig = px.bar(tld_df, x="TLD", y="count",
                                         color_discrete_sequence=["#ef4444"])
                            fig.update_layout(height=200, margin=dict(l=0,r=0,t=0,b=0))
                            st.plotly_chart(fig, use_container_width=True)
                    with col_e:
                        st.markdown("**URLs de la campaña:**")
                        for url in camp["urls"][:8]:
                            st.code(url, language=None)

        # IOC export
        st.divider()
        st.subheader("📤 Exportar IOCs")
        all_urls = []
        for camp in campaigns.values():
            all_urls.extend(camp["urls"])
        all_urls.extend(result["outliers"])
        ioc_text = "\n".join(sorted(set(all_urls)))
        st.download_button(
            "⬇️ Descargar lista de IOCs (.txt)",
            data=ioc_text,
            file_name=f"phishradar_ioc_{datetime.utcnow().strftime('%Y%m%d')}.txt",
            mime="text/plain",
        )


# ══════════════════════════════════════════════════════════════════════════════
# PÁGINA: Modelo ML
# ══════════════════════════════════════════════════════════════════════════════

elif page == "🤖 Modelo ML":
    st.title("🤖 Modelo ML")

    metrics = load_metrics()

    if metrics:
        st.success(f"Modelo entrenado el {metrics['trained_at'][:10]}")
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Accuracy",   f"{metrics['accuracy']:.2%}")
        c2.metric("Precisión",  f"{metrics['precision_phish']:.2%}")
        c3.metric("Recall",     f"{metrics['recall_phish']:.2%}")
        c4.metric("F1-score",   f"{metrics['f1_phish']:.2%}")

        st.divider()

        # Importancia de features
        st.subheader("Importancia de features")
        fi = metrics.get("feature_importance", {})
        if fi:
            fi_df = pd.DataFrame(
                sorted(fi.items(), key=lambda x: -x[1]),
                columns=["Feature", "Importancia"]
            )
            fig = px.bar(
                fi_df, x="Importancia", y="Feature",
                orientation="h",
                color="Importancia",
                color_continuous_scale="purples",
            )
            fig.update_layout(height=400, margin=dict(l=0, r=0, t=0, b=0))
            st.plotly_chart(fig, use_container_width=True)

        # Matriz de confusión
        cm = metrics.get("confusion_matrix")
        if cm:
            st.subheader("Matriz de confusión")
            fig = px.imshow(
                cm,
                labels=dict(x="Predicho", y="Real"),
                x=["Legítima", "Phishing"],
                y=["Legítima", "Phishing"],
                color_continuous_scale="reds",
                text_auto=True,
            )
            fig.update_layout(height=300)
            st.plotly_chart(fig, use_container_width=True)

    else:
        st.warning("El modelo aún no ha sido entrenado.")

    st.divider()
    st.subheader("Reentrenar modelo")
    st.caption("Usa los datos actuales de la DB para mejorar el modelo.")

    if st.button("🔄 Entrenar ahora", type="primary"):
        with st.spinner("Entrenando... esto toma unos segundos."):
            m = train()
        st.success(f"✅ Modelo entrenado — Accuracy: {m['accuracy']:.2%} | F1: {m['f1_phish']:.2%}")
        st.cache_data.clear()
        st.rerun()


# ══════════════════════════════════════════════════════════════════════════════
# PÁGINA: Base de datos
# ══════════════════════════════════════════════════════════════════════════════

elif page == "📋 Base de datos":
    st.title("📋 Base de datos")

    df = load_urls(5000)

    if df.empty:
        st.warning("No hay datos. Corre `python main.py --demo` primero.")
        st.stop()

    # Filtros
    st.subheader("Filtros")
    col1, col2, col3 = st.columns(3)

    with col1:
        fuentes = ["Todas"] + sorted(df["source"].dropna().unique().tolist())
        fuente  = st.selectbox("Fuente", fuentes)

    with col2:
        tlds    = ["Todos"] + sorted(df["tld"].dropna().unique().tolist())
        tld_sel = st.selectbox("TLD", tlds)

    with col3:
        marcas    = ["Todas"] + sorted(df["brand_hit"].dropna().unique().tolist())
        marca_sel = st.selectbox("Marca", marcas)

    busqueda = st.text_input("🔎 Buscar en URL o dominio", "")

    # Aplicar filtros
    filtered = df.copy()
    if fuente != "Todas":
        filtered = filtered[filtered["source"] == fuente]
    if tld_sel != "Todos":
        filtered = filtered[filtered["tld"] == tld_sel]
    if marca_sel != "Todas":
        filtered = filtered[filtered["brand_hit"] == marca_sel]
    if busqueda:
        mask = (
            filtered["url"].str.contains(busqueda, case=False, na=False) |
            filtered["domain"].str.contains(busqueda, case=False, na=False)
        )
        filtered = filtered[mask]

    st.caption(f"Mostrando {len(filtered):,} de {len(df):,} URLs")
    st.dataframe(filtered, use_container_width=True, hide_index=True)

    # Exportar
    csv = filtered.to_csv(index=False)
    st.download_button(
        "⬇️ Exportar CSV",
        data=csv,
        file_name=f"phishradar_export_{datetime.utcnow().strftime('%Y%m%d')}.csv",
        mime="text/csv",
    )
