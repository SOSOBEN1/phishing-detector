"""Étape 2 : entraînement, évaluation et sauvegarde du modèle.

Utilisation (après 02_preparation.py) :
    python app/ml/03_training.py

Produit :
- app/ml/model.joblib            : {"model": pipeline, "features": colonnes attendues}
- app/ml/results/metrics.txt     : précision, rappel, F1, matrice de confusion
- app/ml/results/confusion_matrix.png

Anti data leakage : le découpage train/test est fait PAR DOMAINE
(GroupShuffleSplit). Un même domaine n'est jamais à la fois dans le train et
dans le test, sinon le modèle « reconnaîtrait » les domaines au lieu
d'apprendre à détecter le phishing, et les scores seraient trop optimistes.
"""
from pathlib import Path

import joblib
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import pandas as pd  # noqa: E402
from sklearn.compose import ColumnTransformer  # noqa: E402
from sklearn.feature_extraction.text import TfidfVectorizer  # noqa: E402
from sklearn.linear_model import LogisticRegression  # noqa: E402
from sklearn.metrics import (  # noqa: E402
    ConfusionMatrixDisplay, accuracy_score, classification_report, confusion_matrix,
    f1_score, precision_score, recall_score,
)
from sklearn.model_selection import GroupShuffleSplit  # noqa: E402
from sklearn.pipeline import Pipeline  # noqa: E402
from sklearn.preprocessing import StandardScaler  # noqa: E402

from features import FEATURE_NAMES  # noqa: E402

HERE = Path(__file__).resolve().parent
DATA = HERE.parents[1] / "data" / "prepared.csv"
MODEL_PATH = HERE / "model.joblib"
RESULTS = HERE / "results"
COLUMNS = FEATURE_NAMES + ["domain"]


def build_model():
    """Features numériques (normalisées) + n-grammes de caractères du domaine."""
    pre = ColumnTransformer([
        ("num", StandardScaler(), FEATURE_NAMES),
        ("ngrams", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=5,
                                   max_features=50000, sublinear_tf=True), "domain"),
    ])
    return Pipeline([
        ("pre", pre),
        ("clf", LogisticRegression(max_iter=2000, C=1.0, class_weight="balanced")),
    ])


def main():
    df = pd.read_csv(DATA, keep_default_na=False)
    X, y = df[COLUMNS], df["is_phishing"]

    split = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=42)
    train_idx, test_idx = next(split.split(X, y, groups=df["domain"]))
    overlap = set(df["domain"].iloc[train_idx]) & set(df["domain"].iloc[test_idx])
    assert not overlap, "fuite : domaines communs entre train et test"
    print(f"Train : {len(train_idx)}  Test : {len(test_idx)}  (domaines communs : 0)")

    model = build_model().fit(X.iloc[train_idx], y.iloc[train_idx])
    y_test, y_pred = y.iloc[test_idx], model.predict(X.iloc[test_idx])

    cm = confusion_matrix(y_test, y_pred)
    lines = [
        "Modèle : régression logistique (13 features du domaine + n-grammes de caractères)",
        "Classe positive = phishing ; découpage 80/20 groupé par domaine",
        "",
        f"Exactitude (accuracy) : {accuracy_score(y_test, y_pred):.4f}",
        f"Précision             : {precision_score(y_test, y_pred):.4f}",
        f"Rappel                : {recall_score(y_test, y_pred):.4f}",
        f"F1-score              : {f1_score(y_test, y_pred):.4f}",
        "",
        "Matrice de confusion (lignes = réel, colonnes = prédit) :",
        "                 Légitime  Phishing",
        f"  Légitime      {cm[0, 0]:>9}  {cm[0, 1]:>8}",
        f"  Phishing      {cm[1, 0]:>9}  {cm[1, 1]:>8}",
        "",
        classification_report(y_test, y_pred, target_names=["Légitime", "Phishing"], digits=4),
    ]
    report = "\n".join(lines)
    print(report)

    RESULTS.mkdir(exist_ok=True)
    (RESULTS / "metrics.txt").write_text(report, encoding="utf-8")
    ConfusionMatrixDisplay(cm, display_labels=["Légitime", "Phishing"]).plot(cmap="Blues", values_format="d")
    plt.title("Matrice de confusion (jeu de test)")
    plt.savefig(RESULTS / "confusion_matrix.png", dpi=120, bbox_inches="tight")

    # Modèle final ré-entraîné sur toutes les données, puis sauvegardé
    final = build_model().fit(X, y)
    joblib.dump({"model": final, "features": COLUMNS}, MODEL_PATH, compress=3)
    print(f"Modèle sauvegardé -> {MODEL_PATH}")


if __name__ == "__main__":
    main()
