"""Prédiction pour l'appli Flask.

Utilisation dans routes.py :
    from app.ml.predict import predict_url
    result = predict_url("http://exemple.com/login")
    # {"is_phishing": True, "probability": 0.93, "label": "Phishing"}
"""
from pathlib import Path

import joblib
import pandas as pd

try:  # import depuis Flask (app.ml.predict)
    from .features import extract_features, get_domain
except ImportError:  # lancé directement (python predict.py)
    from features import extract_features, get_domain

MODEL_PATH = Path(__file__).resolve().parent / "model.joblib"
THRESHOLD = 0.5  # au-dessus : considéré comme suspect

_bundle = None


def _load():
    global _bundle
    if _bundle is None:
        _bundle = joblib.load(MODEL_PATH)
    return _bundle


def predict_url(url: str) -> dict:
    bundle = _load()
    row = pd.DataFrame([extract_features(url)])
    row["domain"] = get_domain(url)
    row = row[bundle["features"]]
    proba = float(bundle["model"].predict_proba(row)[0][1])  # P(phishing)
    is_phishing = proba >= THRESHOLD
    return {
        "is_phishing": is_phishing,
        "probability": round(proba, 4),
        "label": "Phishing" if is_phishing else "Légitime",
    }


if __name__ == "__main__":
    for u in ["https://www.google.com", "http://192.168.0.1/secure-login@bank.com"]:
        print(u, "->", predict_url(u))