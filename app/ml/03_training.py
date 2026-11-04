"""Étape 2 : entraînement et évaluation du modèle.

Lancer depuis la racine du projet :
    python app/ml/03_training.py

Lit data/features.csv, entraîne deux modèles, garde le meilleur (F1) et
le sauvegarde dans app/ml/model.joblib.
"""
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix, f1_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.compose import ColumnTransformer
from sklearn.feature_extraction.text import TfidfVectorizer

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
DATA = ROOT / "data" / "features.csv"
MODEL_PATH = HERE / "model.joblib"

df = pd.read_csv(DATA)
df["domain"] = df["domain"].fillna("")
X = df.drop(columns="is_phishing")
y = df["is_phishing"]

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

num_cols = [c for c in df.columns if c not in ("domain", "is_phishing")]
prep = ColumnTransformer([
    ("ngrams", TfidfVectorizer(analyzer="char", ngram_range=(2, 4),
                               min_df=5, sublinear_tf=True), "domain"),
    ("num", StandardScaler(), num_cols),
])
candidates = {
    "TFIDF+LogReg": make_pipeline(prep, LogisticRegression(max_iter=2000)),
}

best_name, best_model, best_f1 = None, None, -1
for name, model in candidates.items():
    print(f"\n===== {name} =====")
    model.fit(X_train, y_train)
    pred = model.predict(X_test)
    print(classification_report(y_test, pred, target_names=["légitime", "phishing"]))
    print("Matrice de confusion [[VN FP] [FN VP]] :")
    print(confusion_matrix(y_test, pred))
    f1 = f1_score(y_test, pred)
    if f1 > best_f1:
        best_name, best_model, best_f1 = name, model, f1

print(f"\nMeilleur modèle : {best_name} (F1 = {best_f1:.4f})")

if hasattr(best_model, "feature_importances_"):
    imp = pd.Series(best_model.feature_importances_, index=X.columns)
    print("\nImportance des caractéristiques :")
    print(imp.sort_values(ascending=False).round(4).to_string())

joblib.dump({"model": best_model, "features": list(X.columns)}, MODEL_PATH)
print(f"\nModèle sauvegardé : {MODEL_PATH}")