import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib


def main():
    # 1) Charger le dataset
    df = pd.read_csv("dataset.csv")

    # Nettoyage simple
    df = df.dropna(subset=["text", "label"])
    df["label"] = df["label"].astype(int)

    X = df["text"]
    y = df["label"]

    # 2) Split train / test
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    # 3) TF-IDF
    vectorizer = TfidfVectorizer(
        max_features=5000,
        ngram_range=(1, 2)
        # pas de stop_words pour gérer FR + EN
    )

    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)

    # 4) Modèle de classification
    clf = LogisticRegression(max_iter=1000)
    clf.fit(X_train_vec, y_train)

    # 5) Évaluation rapide
    y_pred = clf.predict(X_test_vec)
    print(classification_report(y_test, y_pred))

    # 6) Sauvegarde du modèle
    joblib.dump(
        {"vectorizer": vectorizer, "classifier": clf},
        "model.joblib"
    )
    print("✅ Modèle sauvegardé dans model.joblib")


if __name__ == "__main__":
    main()
