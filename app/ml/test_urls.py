"""Test rapide du modèle sur des URL dont on connaît la vraie classe.

Lancer depuis la racine du projet :
    python app/ml/test_urls.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from predict import predict_url  # noqa: E402

LEGIT = [
    "https://github.com/SOSOBEN1/phishing-detector/issues/12",
    "https://fr.wikipedia.org/wiki/Hame%C3%A7onnage",
    "https://www.lemonde.fr/international/article/2024/05/12/un-long-titre_6232.html",
    "http://www.univ-bejaia.dz/fr/faculte-des-sciences-exactes",
    "https://stackoverflow.com/questions/11227809/why-is-processing-a-sorted-array-faster",
    "https://www.google.com",
    "https://www.amazon.fr/dp/B08N5WRWNW",
    "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
]
PHISH = [
    "https://www.google.com.evil-site.ru",
    "http://paypal.com.account-update.top/login",
    "https://secure-paypal-login.verify-account.xyz/signin?id=123&session=abc",
    "https://paypa1-support.com",
    "http://192.168.0.1/secure-login@bank.com",
    "https://amazon-verify-account.top",
]


def run(title, urls, expected):
    print(f"\n--- {title} (attendu : {expected}) ---")
    ok = 0
    for u in urls:
        r = predict_url(u)
        good = r["label"] == expected
        ok += good
        print(f"{'OK ' if good else 'XX '} {r['label']:9} {r['probability']:.3f}  {u}")
    print(f"=> {ok}/{len(urls)} corrects")


run("LÉGITIMES", LEGIT, "Légitime")
run("PHISHING", PHISH, "Phishing")