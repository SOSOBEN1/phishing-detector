# SafeURL : détection d'URL de phishing par IA

Application web Flask sécurisée : inscription et connexion avec double authentification
(TOTP), contrôle d'accès par rôles (admin / user), et analyse d'URL par un modèle
d'apprentissage automatique entraîné sur le dataset PhiUSIIL.

## Installation

```bash
python -m venv venv
venv\Scripts\activate            # Windows (Linux/macOS : source venv/bin/activate)
pip install -r requirements.txt
copy .env.example .env           # puis remplir SECRET_KEY
```

## Modèle d'IA

1. Télécharger le dataset PhiUSIIL ([Kaggle](https://www.kaggle.com/datasets/ndarvind/phiusiil-phishing-url-dataset)
   ou [UCI](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset))
   et placer le CSV dans `data/PhiUSIIL_Phishing_URL_Dataset.csv`.
2. Préparer les données puis entraîner :

```bash
python app/ml/02_preparation.py
python app/ml/03_training.py
```

Résultats : `app/ml/model.joblib`, `app/ml/results/metrics.txt` (précision, rappel, F1,
matrice de confusion) et `app/ml/results/confusion_matrix.png`.

Choix méthodologiques :
- seules des caractéristiques calculables **à partir de l'URL** sont utilisées : les colonnes
  de PhiUSIIL décrivant le contenu de la page sont écartées ;
- le même fichier `app/ml/features.py` sert à l'entraînement et à l'application ;
- le découpage train/test est fait **par domaine**, pour éviter la fuite de données ;
- dans PhiUSIIL, `label = 1` signifie légitime : la cible est inversée (1 = phishing).

Résultats sur le jeu de test (domaines jamais vus à l'entraînement) : précision 0,91,
rappel 0,77, F1 0,84 (détail dans `app/ml/results/metrics.txt`).

**Limite connue :** PhiUSIIL ne contient presque pas de grands sites côté légitime, alors
que de nombreuses pages de phishing sont hébergées sur `docs.google.com`, `sites.google.com`
ou `*.github.io`. Le modèle associe donc les n-grammes « google » ou « github » au phishing,
et des sites connus comme `google.com` peuvent être signalés à tort. Pistes : liste blanche
de domaines populaires (ex. Tranco), ou enrichissement du jeu d'entraînement.

## Lancement

```bash
flask --app run create-admin admin@exemple.com   # crée le premier administrateur
python run.py                                    # http://127.0.0.1:5000
```

À la première connexion, chaque utilisateur scanne un QR code avec une application
d'authentification (Google Authenticator, Microsoft Authenticator, FreeOTP…).

> Après une mise à jour du modèle de données, supprimer `instance/app.db` (développement).

## Sécurité

| Mesure | Implémentation |
|---|---|
| Mots de passe | Hachage scrypt (Werkzeug), 8 caractères minimum, lettre + chiffre |
| MFA | TOTP (PyOTP) obligatoire, QR code, tolérance ±30 s, anti-rejeu du code |
| RBAC | Rôles `user` / `admin`, décorateur `admin_required` (403 + journalisation) |
| Sessions | Flask-Login (`session_protection="strong"`), session régénérée à la connexion, cookies HttpOnly / SameSite / Secure |
| CSRF | Flask-WTF `CSRFProtect` sur tous les formulaires POST |
| Force brute | Flask-Limiter : 5 tentatives / minute sur connexion, MFA, inscription, compte |
| Journaux | Table `SecurityLog` : connexions, échecs, MFA, accès refusés, actions admin |
| XSS / clickjacking | Échappement Jinja, CSP sans script inline, `X-Frame-Options: DENY`, `nosniff` |
| Injection SQL | Requêtes via l'ORM SQLAlchemy |
| Configuration | Secret dans `.env` (non versionné), mode debug désactivé par défaut |

## Structure

```
app/
  __init__.py     factory, configuration, commande create-admin
  auth.py         inscription, connexion, étape MFA, déconnexion
  account.py      paramètres du compte (mot de passe, MFA)
  admin.py        gestion des comptes, journaux de sécurité
  security.py     RBAC, journalisation, vérification TOTP, en-têtes HTTP
  routes.py       tableau de bord, analyse d'URL, historique
  ml/             features, préparation, entraînement, prédiction
```
