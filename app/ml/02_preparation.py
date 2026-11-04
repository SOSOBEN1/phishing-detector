"""Étape 1.3 : nettoyage et préparation des données.

Lancer depuis la racine du projet :
    python app/ml/02_preparation.py

Produit data/features.csv (colonnes de FEATURE_NAMES + 'is_phishing').
"""
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from features import FEATURE_NAMES, features_vector, get_domain  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
CSV = ROOT / "data" / "PhiUSIIL_Phishing_URL_Dataset.csv"
OUT = ROOT / "data" / "features.csv"

df = pd.read_csv(CSV, usecols=["URL", "label"])
print("Lignes au départ :", len(df))

# Nettoyage
df = df.dropna(subset=["URL", "label"])
df = df.drop_duplicates(subset="URL")
print("Après nettoyage  :", len(df))

# Dans PhiUSIIL : label 1 = légitime, 0 = phishing.
# On inverse pour avoir 1 = phishing (plus naturel pour un détecteur).
df["is_phishing"] = 1 - df["label"].astype(int)

# Extraction des features à partir de l'URL (même code que l'appli Flask)
print("Extraction des features (peut prendre ~1 minute)...")
X = pd.DataFrame(
    [features_vector(u) for u in df["URL"]],
    columns=FEATURE_NAMES,
    index=df.index,
)
out = X.assign(is_phishing=df["is_phishing"].values)
out["domain"] = [get_domain(u) for u in df["URL"]]
out.to_csv(OUT, index=False)

print("Classes (1 = phishing) :")
print(out["is_phishing"].value_counts().to_string())
print(f"\nFichier créé : {OUT}  ({out.shape[0]} lignes, {out.shape[1]} colonnes)")