"""
PhishRadar — Modelo ML (Capa 2)
Random Forest para clasificar URLs como phishing o legítimas.
Diseñado para reentrenarse automáticamente con nuevos datos.
"""

import json
import logging
import pickle
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

from config import MODELS_DIR
from src.features import extract_features_batch, feature_names

logger = logging.getLogger(__name__)

MODEL_PATH   = MODELS_DIR / "phishradar_model.pkl"
SCALER_PATH  = MODELS_DIR / "phishradar_scaler.pkl"
METRICS_PATH = MODELS_DIR / "last_metrics.json"


# ── Dataset de arranque ───────────────────────────────────────────────────────
# URLs legítimas conocidas para balancear el entrenamiento inicial.
# En Capa 3 esto se reemplaza con un dataset real descargado.

LEGIT_URLS_SAMPLE = [
    "https://www.google.com",
    "https://www.facebook.com",
    "https://www.youtube.com",
    "https://www.amazon.com",
    "https://www.wikipedia.org",
    "https://www.microsoft.com",
    "https://www.apple.com",
    "https://www.netflix.com/gt",
    "https://www.mercadolibre.com.gt",
    "https://baccredomatic.com/es-gt",
    "https://www.banrural.com.gt",
    "https://portal.sat.gob.gt",
    "https://www.tigo.com.gt",
    "https://www.claro.com.gt",
    "https://www.paypal.com",
    "https://www.instagram.com",
    "https://www.twitter.com",
    "https://www.linkedin.com",
    "https://www.github.com",
    "https://www.python.org",
]

PHISH_URLS_SAMPLE = [
    "http://banrural-gt-seguro.xyz/login/cuenta",
    "http://192.168.1.1/paypal/verify",
    "http://baccredomatic-update.tk/account/suspended",
    "http://mercadolibre-pago-seguro.ml/confirmar",
    "http://netflix-gt-renovar.com/account/update",
    "http://tigo-factura-pagos.xyz/verificar",
    "http://sat-gt-declaracion.net/login",
    "http://igss-guatemala.ru/acceso",
    "http://amazon.com.verificar-cuenta.tk/signin",
    "http://secure-paypal-login.phish.net/confirm",
    "http://banco-industrial-gt.xyz/banca-en-linea",
    "http://google-cuenta-verificar.ml/acceso",
    "http://update-account-microsoft.tk/signin",
    "http://apple-id-verify.xyz/account/locked",
    "http://facebook-login-secure.ml/checkpoint",
    "http://whatsapp-verify-phone.tk/code",
    "http://instagram-cuenta-suspendida.xyz/recover",
    "http://rappi-promo-gt.ml/oferta/verificar",
    "http://claro-factura-vencida.xyz/pagar",
    "http://renap-dpi-renovar.tk/tramite",
]


# ── Entrenamiento ─────────────────────────────────────────────────────────────

def train(phish_urls: list[str] = None, legit_urls: list[str] = None) -> dict:
    """
    Entrena el modelo con URLs phishing y legítimas.
    Si no se pasan listas, usa el dataset de arranque incluido.
    Devuelve métricas del entrenamiento.
    """
    MODELS_DIR.mkdir(exist_ok=True)

    phish = phish_urls or PHISH_URLS_SAMPLE
    legit = legit_urls or LEGIT_URLS_SAMPLE

    logger.info(f"Entrenando con {len(phish)} phishing + {len(legit)} legítimas")

    # Extraer features
    X_phish = extract_features_batch(phish)
    X_legit = extract_features_batch(legit)

    df_phish = pd.DataFrame(X_phish)
    df_legit = pd.DataFrame(X_legit)

    df_phish["label"] = 1   # 1 = phishing
    df_legit["label"] = 0   # 0 = legítima

    df = pd.concat([df_phish, df_legit], ignore_index=True).fillna(0)

    X = df[feature_names()].values
    y = df["label"].values

    # Split train/test
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )

    # Escalar
    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test  = scaler.transform(X_test)

    # Modelo
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        random_state=42,
        class_weight="balanced",
    )
    model.fit(X_train, y_train)

    # Métricas
    y_pred = model.predict(X_test)
    report = classification_report(y_test, y_pred, output_dict=True)
    cm     = confusion_matrix(y_test, y_pred).tolist()

    metrics = {
        "trained_at":      datetime.utcnow().isoformat(),
        "phish_samples":   len(phish),
        "legit_samples":   len(legit),
        "accuracy":        round(report["accuracy"], 4),
        "precision_phish": round(report["1"]["precision"], 4),
        "recall_phish":    round(report["1"]["recall"], 4),
        "f1_phish":        round(report["1"]["f1-score"], 4),
        "confusion_matrix": cm,
        "feature_importance": dict(zip(
            feature_names(),
            [round(f, 4) for f in model.feature_importances_]
        )),
    }

    # Guardar modelo y scaler
    with open(MODEL_PATH, "wb") as f:
        pickle.dump(model, f)
    with open(SCALER_PATH, "wb") as f:
        pickle.dump(scaler, f)
    with open(METRICS_PATH, "w") as f:
        json.dump(metrics, f, indent=2)

    logger.info(f"Modelo guardado. Accuracy: {metrics['accuracy']:.2%} | F1: {metrics['f1_phish']:.2%}")
    return metrics


# ── Predicción ────────────────────────────────────────────────────────────────

def load_model():
    """Carga el modelo y scaler desde disco."""
    if not MODEL_PATH.exists():
        raise FileNotFoundError("Modelo no encontrado. Corre train() primero.")
    with open(MODEL_PATH, "rb") as f:
        model = pickle.load(f)
    with open(SCALER_PATH, "rb") as f:
        scaler = pickle.load(f)
    return model, scaler


def predict(urls: list[str]) -> list[dict]:
    """
    Predice si una lista de URLs son phishing o legítimas.
    Devuelve lista de dicts con url, score, label, y features principales.
    """
    model, scaler = load_model()

    features = extract_features_batch(urls)
    df = pd.DataFrame(features).fillna(0)
    X  = scaler.transform(df[feature_names()].values)

    probas  = model.predict_proba(X)[:, 1]   # probabilidad de phishing
    labels  = model.predict(X)

    results = []
    for url, prob, label, feat in zip(urls, probas, labels, features):
        results.append({
            "url":        url,
            "score":      round(float(prob), 4),     # 0.0 a 1.0
            "label":      "phishing" if label == 1 else "legítima",
            "risk":       _risk_level(prob),
            "top_signals": _top_signals(feat),
        })

    return results


def _risk_level(score: float) -> str:
    if score >= 0.8:
        return "🔴 ALTO"
    elif score >= 0.5:
        return "🟡 MEDIO"
    else:
        return "🟢 BAJO"


def _top_signals(features: dict) -> list[str]:
    """Devuelve las señales más relevantes de una URL para explicar la predicción."""
    signals = []
    if features.get("has_ip"):
        signals.append("Usa IP directa")
    if features.get("brand_impersonation"):
        signals.append("Imita marca conocida")
    if features.get("suspicious_tld"):
        signals.append("TLD sospechoso")
    if features.get("has_at_symbol"):
        signals.append("Contiene símbolo @")
    if features.get("suspicious_keyword_count", 0) >= 2:
        signals.append("Múltiples palabras clave")
    if features.get("subdomain_count", 0) >= 3:
        signals.append("Exceso de subdominios")
    if features.get("domain_entropy", 0) > 3.5:
        signals.append("Dominio muy aleatorio")
    return signals or ["Sin señales claras"]


# ── Reporte de importancia ────────────────────────────────────────────────────

def feature_importance_report() -> None:
    """Imprime qué features son más importantes para el modelo."""
    if not METRICS_PATH.exists():
        print("No hay métricas guardadas. Entrena el modelo primero.")
        return
    with open(METRICS_PATH) as f:
        metrics = json.load(f)

    print("\n── Importancia de features ──────────────────────────")
    sorted_fi = sorted(
        metrics["feature_importance"].items(),
        key=lambda x: x[1], reverse=True
    )
    for name, score in sorted_fi:
        bar = "█" * int(score * 40)
        print(f"  {name:<28} {score:.4f}  {bar}")
    print()
