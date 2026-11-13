import os

from app import create_app

app = create_app()

if __name__ == "__main__":
    # Jamais de mode debug par défaut : le débogueur Werkzeug permet d'exécuter du code
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
