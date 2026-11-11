"""Pont entre l'appli Flask et le modèle IA (app/ml)."""
from .ml.features import extract_features
from .ml.predict import predict_url


def analyze_url(url: str) -> dict:
    """Lance le modèle. Lève FileNotFoundError si model.joblib est absent."""
    r = predict_url(url)
    return {
        "label": "Phishing" if r["is_phishing"] else "Légitime",
        "probability": r["probability"],
    }


def explain(url: str) -> list:
    """Points d'attention lisibles, calculés à partir de l'URL.

    Ce sont des règles simples affichées à l'utilisateur : elles complètent
    la décision du modèle mais ne l'expliquent pas exactement.
    """
    url = (url or "").strip()
    f = extract_features(url)
    reasons = []
    if f["NoOfSuspiciousKeywords"] > 0:
        reasons.append("Domaine suspect : contient des mots souvent utilisés dans le phishing (login, verify, account…)")
    if f["IsDomainIP"]:
        reasons.append("Adresse IP utilisée à la place d'un nom de domaine")
    if f["NoOfHyphensInDomain"] >= 2 or f["NoOfDigitsInDomain"] >= 3 or f["HasPunycode"]:
        reasons.append("Présence de caractères inhabituels dans le domaine (tirets, chiffres)")
    if url.lower().startswith("http://"):
        reasons.append("Utilisation du protocole HTTP (non sécurisé)")
    if f["DomainLength"] > 25:
        reasons.append("Longueur de domaine inhabituelle")
    if f["NoOfSubDomain"] >= 3:
        reasons.append("Nombre élevé de sous-domaines")
    if "@" in url:
        reasons.append("Présence du symbole @ dans l'URL")
    return reasons