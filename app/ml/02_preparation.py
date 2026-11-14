"""Étape 1 : étude et préparation du dataset PhiUSIIL.

Utilisation :
    python app/ml/02_preparation.py [chemin/vers/PhiUSIIL_Phishing_URL_Dataset.csv]

Choix importants :
- On ne garde QUE la colonne URL du dataset. Beaucoup de colonnes de PhiUSIIL
  décrivent le CONTENU de la page (LineOfCode, HasTitle, NoOfImage…) : l'appli
  ne reçoit qu'une URL, elle ne pourrait pas les calculer.
- Les features sont recalculées avec app/ml/features.py, le même code que
  l'appli Flask : entraînement et prédiction voient exactement les mêmes valeurs.
- Dans PhiUSIIL, label = 1 signifie LÉGITIME et 0 PHISHING. On inverse pour
  que la classe 1 soit « phishing » (predict.py lit predict_proba[:, 1]).
"""
import sys
from pathlib import Path

import pandas as pd

from features import FEATURE_NAMES, extract_features, get_domain

ROOT = Path(__file__).resolve().parents[2]
RAW = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "data" / "PhiUSIIL_Phishing_URL_Dataset.csv"
OUT = ROOT / "data" / "prepared.csv"

# Colonnes calculées sur le contenu HTML de la page : inutilisables avec une URL seule
CONTENT_COLUMNS = [
    "LineOfCode", "LargestLineLength", "HasTitle", "Title", "DomainTitleMatchScore",
    "URLTitleMatchScore", "HasFavicon", "Robots", "IsResponsive", "NoOfURLRedirect",
    "NoOfSelfRedirect", "HasDescription", "NoOfPopup", "NoOfiFrame", "HasExternalFormSubmit",
    "HasSocialNet", "HasSubmitButton", "HasHiddenFields", "HasPasswordField", "Bank", "Pay",
    "Crypto", "HasCopyrightInfo", "NoOfImage", "NoOfCSS", "NoOfJS", "NoOfSelfRef",
    "NoOfEmptyRef", "NoOfExternalRef",
]


def main():
    df = pd.read_csv(RAW)
    print(f"Dataset brut : {df.shape[0]} lignes, {df.shape[1]} colonnes")
    content = [c for c in CONTENT_COLUMNS if c in df.columns]
    print(f"Colonnes ignorées (contenu de la page) : {len(content)}")
    print("Répartition label (1 = légitime, 0 = phishing) :", df["label"].value_counts().to_dict())

    # Nettoyage
    df = df[["URL", "label"]].dropna()
    df["URL"] = df["URL"].astype(str).str.strip()
    df = df[df["URL"] != ""]
    before = len(df)
    df = df.drop_duplicates(subset="URL")
    print(f"Doublons d'URL supprimés : {before - len(df)}")

    # Features identiques à celles de l'appli
    feats = pd.DataFrame([extract_features(u) for u in df["URL"]], index=df.index)
    feats["domain"] = df["URL"].map(get_domain)
    feats["is_phishing"] = (df["label"] == 0).astype(int)
    feats["URL"] = df["URL"]
    feats = feats[feats["domain"] != ""]

    print("\nStatistiques des features (moyenne par classe) :")
    print(feats.groupby("is_phishing")[FEATURE_NAMES].mean().T.round(3))

    OUT.parent.mkdir(exist_ok=True)
    feats.to_csv(OUT, index=False)
    print(f"\n{len(feats)} lignes préparées -> {OUT}")


if __name__ == "__main__":
    main()
