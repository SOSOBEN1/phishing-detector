"""Extraction de caractéristiques à partir du NOM DE DOMAINE d'une URL.

Version 3 (v2 + retrait du www. + get_domain pour les n-grammes) : on n'utilise plus le chemin, la longueur totale ni HTTPS, car le
modèle v1 s'appuyait surtout dessus (biais du dataset : les URL légitimes y
sont presque toutes des pages d'accueil).

Le même code sert à l'entraînement (02_preparation.py) et à l'appli Flask
(predict.py), ce qui garantit que le modèle reçoit les mêmes features.
"""
import re
from urllib.parse import urlparse

FEATURE_NAMES = [
    "DomainLength", "IsDomainIP", "TLDLength", "NoOfSubDomain",
    "NoOfDotsInDomain", "NoOfHyphensInDomain", "NoOfDigitsInDomain",
    "DigitRatioInDomain", "LetterRatioInDomain", "NoOfOtherCharsInDomain",
    "LongestLabelLength", "NoOfSuspiciousKeywords", "HasPunycode",
]

KEYWORDS = (
    "login", "secure", "verify", "account", "update", "signin",
    "support", "confirm", "wallet", "bonus", "free", "banking",
)

_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def extract_features(url: str) -> dict:
    url = (url or "").strip()
    parsed = urlparse(url if "://" in url else "http://" + url)
    domain = (parsed.hostname or "").lower()
    if domain.startswith("www."):
        domain = domain[4:]  # le "www." ne doit pas servir de raccourci au modèle
    parts = domain.split(".") if domain else []
    n = max(len(domain), 1)
    letters = sum(c.isalpha() for c in domain)
    digits = sum(c.isdigit() for c in domain)

    return {
        "DomainLength": len(domain),
        "IsDomainIP": int(bool(_IP_RE.match(domain))),
        "TLDLength": len(parts[-1]) if parts else 0,
        "NoOfSubDomain": max(len(parts) - 2, 0),
        "NoOfDotsInDomain": domain.count("."),
        "NoOfHyphensInDomain": domain.count("-"),
        "NoOfDigitsInDomain": digits,
        "DigitRatioInDomain": digits / n,
        "LetterRatioInDomain": letters / n,
        "NoOfOtherCharsInDomain": sum(
            1 for c in domain if not c.isalnum() and c not in ".-"
        ),
        "LongestLabelLength": max((len(p) for p in parts), default=0),
        "NoOfSuspiciousKeywords": sum(k in domain for k in KEYWORDS),
        "HasPunycode": int("xn--" in domain),
    }


def features_vector(url: str) -> list:
    """Valeurs dans l'ordre exact de FEATURE_NAMES."""
    f = extract_features(url)
    return [f[name] for name in FEATURE_NAMES]


def get_domain(url: str) -> str:
    """Nom de domaine en minuscules, sans le préfixe www."""
    url = (url or "").strip()
    parsed = urlparse(url if "://" in url else "http://" + url)
    domain = (parsed.hostname or "").lower()
    return domain[4:] if domain.startswith("www.") else domain