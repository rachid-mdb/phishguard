import random
from datetime import datetime, timedelta

import pandas as pd
from pymongo import MongoClient

from app.config import MONGO_URI, DB_NAME
from app.ml import phishing_model


def random_ip():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))


def main():
    client = MongoClient(MONGO_URI)
    db = client[DB_NAME]
    logs_collection = db["logs"]

    # Charger le dataset de base (text, label)
    df = pd.read_csv("dataset.csv")
    df = df.dropna(subset=["text"])

    # Séparer phishing / legit si besoin
    rows = df.to_dict(orient="records")

    docs = []
    now = datetime.utcnow()

    # nb de répétitions (tu peux augmenter pour tester les performances)
    repeats = 100  # 100 * 20 lignes = 2000 logs par exemple

    for _ in range(repeats):
        for row in rows:
            text = row["text"]
            label_raw = row.get("label", 0)
            try:
                label_int = int(label_raw)
            except Exception:
                label_int = 0

            # simpliste : subject = premières 60 lettres, body = le reste
            subject = text[:60]
            body = text[60:]

            # URL factice / simplifiée
            url = ""
            if label_int == 1:
                url = f"http://{random_ip()}/login.php"
            else:
                url = "https://www.exemple-safe.fr/info"

            # prédiction ML
            proba, explanations, url_feats = phishing_model.predict(subject, body, url)
            verdict = "phishing" if proba >= 0.5 else "legit"

            # timestamp aléatoire sur les 30 derniers jours
            delta_days = random.randint(0, 30)
            ts = now - timedelta(days=delta_days, hours=random.randint(0, 23))

            doc = {
                "timestamp": ts,
                "subject": subject,
                "body": body,
                "url": url,
                "probability": float(proba),
                "verdict": verdict,
                "label": None,
                "features": explanations,
                "domain": url_feats["domain"],
                "tld": url_feats["tld"],
                "has_ip": url_feats["has_ip"],
                "url_length": url_feats["url_length"],
                "num_dots": url_feats["num_dots"],
                "source_ip": random_ip(),
            }
            docs.append(doc)

    if docs:
        result = logs_collection.insert_many(docs)
        print(f"Insertion terminée : {len(result.inserted_ids)} logs insérés.")


if __name__ == "__main__":
    main()
