# app/ml.py
import joblib
from pathlib import Path

from .features import simple_phishing_score  # pour les explications


# chemin vers model.joblib (1 dossier au-dessus de app/)
MODEL_PATH = Path(__file__).resolve().parent.parent / "model.joblib"


class PhishingModel:
    def __init__(self, model_path: Path = MODEL_PATH):
        if not model_path.exists():
            raise RuntimeError(
                f"Modèle ML introuvable : {model_path}. "
                "Lance d'abord `python train_model.py` à la racine du projet."
            )
        data = joblib.load(model_path)
        self.vectorizer = data["vectorizer"]
        self.classifier = data["classifier"]

    def predict(self, subject: str, body: str, url: str):
        """
        Retourne :
        - probabilité (issue du modèle ML)
        - liste d'explications (issues des heuristiques)
        - features URL (domain, tld, etc.)
        """
        text = (subject or "") + " " + (body or "")
        X_vec = self.vectorizer.transform([text])
        proba_ml = float(self.classifier.predict_proba(X_vec)[0, 1])

        # On réutilise nos heuristiques pour construire les explications
        _, explanations, url_feats = simple_phishing_score(subject, body, url)

        return proba_ml, explanations, url_feats


# instance globale utilisée par l'API
phishing_model = PhishingModel()
