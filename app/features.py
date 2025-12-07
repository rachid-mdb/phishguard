# app/features.py
from urllib.parse import urlparse
import re

# Quelques mots souvent utilisés dans le phishing (anglais + un peu français)
SUSPICIOUS_WORDS = [
    "verify", "verification", "account", "bank", "password",
    "urgent", "immediately", "security", "login", "update",
    "confirm", "paypal", "btc", "crypto",
    "compte", "urgence", "confirmer", "sécurité"
]

# Regex pour détecter une IP dans le domaine
IP_REGEX = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


def extract_url_features(url: str) -> dict:
    """Analyse basique de l'URL et retourne quelques infos."""
    if not url:
        return {
            "domain": None,
            "tld": None,
            "has_ip": False,
            "url_length": 0,
            "num_dots": 0,
        }

    parsed = urlparse(url)
    # si l'URL est un peu cassée, on prend path comme fallback
    netloc = parsed.netloc or parsed.path

    domain = netloc.split(":")[0]  # on enlève le port éventuel
    parts = domain.split(".")
    tld = parts[-1] if len(parts) > 1 else None

    has_ip = bool(IP_REGEX.match(domain))

    return {
        "domain": domain,
        "tld": tld,
        "has_ip": has_ip,
        "url_length": len(url),
        "num_dots": url.count("."),
    }


def suspicious_words_count(text: str) -> int:
    """Compte le nombre de mots 'sensibles' présents dans le texte."""
    text_lower = text.lower()
    return sum(1 for w in SUSPICIOUS_WORDS if w in text_lower)


def simple_phishing_score(subject: str, body: str, url: str) -> tuple[float, list[str], dict]:
    """
    Calcule une probabilité simplifiée (0–1) + une liste d'explications
    à partir de règles très simples. Ce sera remplacé plus tard par le modèle ML.
    """
    full_text = (subject or "") + " " + (body or "")
    url_feats = extract_url_features(url or "")

    explanations: list[str] = []

    # 1) Mots suspects
    count = suspicious_words_count(full_text)
    score_words = min(count * 0.12, 0.6)  # max 0.6
    if count > 0:
        explanations.append(f"{count} mot(s) sensible(s) détecté(s) dans le texte")

    # 2) URL avec IP
    score_ip = 0.25 if url_feats["has_ip"] else 0.0
    if url_feats["has_ip"]:
        explanations.append("URL contient une adresse IP")

    # 3) TLD suspects
    suspicious_tlds = {"ru", "cn", "xyz", "top", "club"}
    score_tld = 0.15 if url_feats["tld"] in suspicious_tlds else 0.0
    if url_feats["tld"] in suspicious_tlds:
        explanations.append(f"TLD potentiellement suspect: .{url_feats['tld']}")

    # 4) URL très longue
    score_length = 0.1 if url_feats["url_length"] > 80 else 0.0
    if url_feats["url_length"] > 80:
        explanations.append("URL très longue (> 80 caractères)")

    # Score final
    score = score_words + score_ip + score_tld + score_length
    score = max(0.0, min(1.0, score))  # clamp 0–1

    if not explanations:
        explanations.append("Aucune caractéristique très suspecte détectée")

    return score, explanations, url_feats
