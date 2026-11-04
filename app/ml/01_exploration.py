"""Étape 1.2 : étude des caractéristiques disponibles du dataset PhiUSIIL.

Lancer depuis la racine du projet :
    python app/ml/01_exploration.py
"""
from pathlib import Path

import matplotlib

matplotlib.use("Agg")  # on sauvegarde les figures, pas de fenêtre bloquante
import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns

ROOT = Path(__file__).resolve().parents[2]
CSV = ROOT / "data" / "PhiUSIIL_Phishing_URL_Dataset.csv"
FIG = Path(__file__).resolve().parent / "figures"
FIG.mkdir(exist_ok=True)

df = pd.read_csv(CSV)

# ---------------------------------------------------------------- 1. Aperçu
print("=== Dimensions ===")
print(df.shape)
print("\n=== Colonnes et types ===")
print(df.dtypes.to_string())
print("\n=== Aperçu ===")
print(df.head(3).T.to_string())

# ------------------------------------------------------------ 2. Qualité
print("\n=== Valeurs manquantes (colonnes concernées) ===")
na = df.isnull().sum()
print(na[na > 0].to_string() if (na > 0).any() else "Aucune")
print("\nDoublons (lignes entières) :", df.duplicated().sum())
print("Doublons sur l'URL         :", df["URL"].duplicated().sum())

# -------------------------------------------------------------- 3. Cible
# Dans ce dataset : label = 1 -> légitime, label = 0 -> phishing
print("\n=== Répartition de la cible (label) ===")
print(df["label"].value_counts())
print(df["label"].value_counts(normalize=True).round(3))
df["label"].value_counts().plot(kind="bar", title="Répartition des classes (1=légitime, 0=phishing)")
plt.tight_layout()
plt.savefig(FIG / "classes.png")
plt.close()

# ------------------------------------------------ 4. Types de caractéristiques
text_cols = df.select_dtypes(exclude="number").columns.tolist()
num_cols = df.select_dtypes(include="number").columns.drop("label").tolist()
binary_cols = [c for c in num_cols if set(df[c].dropna().unique()) <= {0, 1}]
print("\n=== Colonnes textuelles (non utilisables telles quelles) ===")
print(text_cols)
print(f"\n=== Colonnes binaires ({len(binary_cols)}) ===")
print(binary_cols)
print(f"\n=== Colonnes numériques non binaires ({len(num_cols) - len(binary_cols)}) ===")
print([c for c in num_cols if c not in binary_cols])

# ------------------------------------------------------------ 5. Corrélations
corr = df[num_cols + ["label"]].corr()["label"].drop("label").sort_values()
print("\n=== Corrélation avec label (top 10 négatives / positives) ===")
print(corr.head(10).round(3).to_string())
print("...")
print(corr.tail(10).round(3).to_string())

plt.figure(figsize=(8, 10))
corr.plot(kind="barh")
plt.title("Corrélation de chaque caractéristique avec label")
plt.tight_layout()
plt.savefig(FIG / "correlation_label.png")
plt.close()

plt.figure(figsize=(14, 12))
sns.heatmap(df[num_cols].corr(), cmap="coolwarm", center=0)
plt.title("Matrice de corrélation")
plt.tight_layout()
plt.savefig(FIG / "heatmap.png")
plt.close()

# ----------------------------------------- 6. Risque de fuite / sur-ajustement
print("\n=== Caractéristiques très corrélées à la cible (|r| > 0.5) ===")
print(corr[corr.abs() > 0.5].round(3).to_string())
print(
    "\nAttention : certaines (ex. URLSimilarityIndex, TLDLegitimateProb, "
    "LineOfCode...) sont calculées à partir de la page ou de statistiques "
    "du dataset : à signaler dans le rapport."
)

# ---------------------- 7. Caractéristiques calculables depuis l'URL seule
URL_ONLY = [
    "URLLength", "DomainLength", "IsDomainIP", "TLDLength", "NoOfSubDomain",
    "HasObfuscation", "NoOfObfuscatedChar", "ObfuscationRatio",
    "NoOfLettersInURL", "LetterRatioInURL", "NoOfDegitsInURL", "DegitRatioInURL",
    "NoOfEqualsInURL", "NoOfQMarkInURL", "NoOfAmpersandInURL",
    "NoOfOtherSpecialCharsInURL", "SpacialCharRatioInURL", "IsHTTPS",
]
present = [c for c in URL_ONLY if c in df.columns]
print(f"\n=== {len(present)} caractéristiques basées uniquement sur l'URL ===")
print(df.groupby("label")[present].mean().T.round(3).to_string())

print(f"\nFigures sauvegardées dans : {FIG}")