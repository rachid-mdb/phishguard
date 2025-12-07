# app/main.py

from datetime import datetime
from typing import List, Optional
import csv
import io

from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from bson import ObjectId  # fourni avec pymongo

from .db import logs_collection
from .schemas import (
    DetectRequest,
    DetectResponse,
    LogOut,
    ReportRequest,
    ImportResult,
)
from .ml import phishing_model  # modèle ML

app = FastAPI(title="PhishGuard API")

# =========================
#   CORS
# =========================
# Origines autorisées (ton frontend Render + localhost)
origins = [
    "http://localhost",
    "http://127.0.0.1",
    "http://127.0.0.1:8000",
    "http://127.0.0.1:5500",
    "https://phishguard-1-nqbz.onrender.com",  # ton frontend Render
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
# =========================


def oid(id_str: str) -> ObjectId:
    """Convertit une string en ObjectId ou renvoie une erreur 400."""
    try:
        return ObjectId(id_str)
    except Exception:
        raise HTTPException(status_code=400, detail="log_id invalide")


@app.get("/")
def read_root():
    return {"message": "PhishGuard API is running"}


@app.get("/health")
def health_check():
    return {"status": "ok"}


@app.get("/db/ping")
def db_ping():
    """Test de connexion à MongoDB."""
    try:
        doc = {
            "type": "ping",
            "timestamp": datetime.utcnow(),
            "message": "Test connexion MongoDB",
        }
        result = logs_collection.insert_one(doc)
        return {"status": "ok", "inserted_id": str(result.inserted_id)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur MongoDB : {e}")


# =========================
#   DÉTECTION /api/detect
# =========================

@app.post("/api/detect", response_model=DetectResponse)
def detect(req: DetectRequest):
    """
    Analyse un email/URL avec le modèle ML (TF-IDF + Logistic Regression),
    enregistre le résultat dans MongoDB, et renvoie la prédiction.
    """
    try:
        # 1) Appel du modèle ML pour obtenir la probabilité + explications
        proba, explanations, url_feats = phishing_model.predict(
            req.subject or "",
            req.body or "",
            req.url or "",
        )
        verdict = "phishing" if proba >= 0.5 else "legit"

        # 2) Construction du document à stocker en base
        now = datetime.utcnow()
        doc = {
            "timestamp": now,
            "subject": req.subject or "",
            "body": req.body or "",
            "url": req.url or "",
            "probability": float(proba),
            "verdict": verdict,
            "label": None,  # sera rempli plus tard via /api/report
            "features": explanations,
            "domain": url_feats["domain"],
            "tld": url_feats["tld"],
            "has_ip": url_feats["has_ip"],
            "url_length": url_feats["url_length"],
            "num_dots": url_feats["num_dots"],
            "source_ip": None,
        }

        # 3) Insertion en BD
        result = logs_collection.insert_one(doc)

        # 4) Réponse API
        return DetectResponse(
            probability=float(proba),
            verdict=verdict,
            features=explanations,
            log_id=str(result.inserted_id),
        )

    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Erreur pendant la détection : {e}"
        )


# =========================
#   LISTER LES LOGS
# =========================

@app.get("/api/logs", response_model=List[LogOut])
def list_logs(
    limit: int = 100,
    verdict: Optional[str] = None,
    label: Optional[str] = None,
    min_prob: Optional[float] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
):
    """
    Retourne la liste des logs, avec filtres :
    - verdict: "phishing" ou "legit"
    - label: "fp", "fn", "tp", "tn"
    - min_prob: probabilité minimale
    - start_date / end_date: dates ISO (ex: 2025-11-26T00:00:00)
    """
    query: dict = {}

    if verdict:
        query["verdict"] = verdict
    if label:
        query["label"] = label
    if min_prob is not None:
        query["probability"] = {"$gte": min_prob}
    if start_date or end_date:
        query["timestamp"] = {}
        if start_date:
            query["timestamp"]["$gte"] = datetime.fromisoformat(start_date)
        if end_date:
            query["timestamp"]["$lte"] = datetime.fromisoformat(end_date)

    cursor = logs_collection.find(query).sort("timestamp", -1).limit(limit)

    logs: list[LogOut] = []
    for d in cursor:
        logs.append(
            LogOut(
                id=str(d["_id"]),
                timestamp=d["timestamp"].isoformat(),
                subject=d.get("subject", ""),
                body=d.get("body", ""),
                url=d.get("url", ""),
                probability=float(d.get("probability", 0.0)),
                verdict=d.get("verdict", ""),
                label=d.get("label"),
                domain=d.get("domain"),
                source_ip=d.get("source_ip"),
            )
        )

    return logs


# =========================
#   REPORT /api/report
# =========================

@app.post("/api/report")
def report(req: ReportRequest):
    """
    Permet de marquer un log comme :
    - fp = faux positif
    - fn = faux négatif
    - tp = vrai positif
    - tn = vrai négatif
    """
    if req.label not in {"fp", "fn", "tp", "tn"}:
        raise HTTPException(status_code=400, detail="label invalide (fp, fn, tp, tn)")

    result = logs_collection.update_one(
        {"_id": oid(req.log_id)},
        {"$set": {"label": req.label}},
    )

    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="log introuvable")

    return {"status": "ok", "updated": int(result.modified_count)}


# =========================
#   DELETE /api/logs/{id}
# =========================

@app.delete("/api/logs/{log_id}")
def delete_log(log_id: str):
    """Supprime un log par son ID."""
    result = logs_collection.delete_one({"_id": oid(log_id)})

    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="log introuvable")

    return {"status": "deleted"}


# =========================
#   IMPORT CSV
# =========================

@app.post("/api/import_csv", response_model=ImportResult)
async def import_csv(file: UploadFile = File(...)):
    """
    Importer un CSV avec colonnes au minimum :
    - subject
    - body
    - url (optionnelle)
    - label (optionnelle, 0/1 ou fp/fn/tp/tn)

    Pour chaque ligne, on:
    - calcule la probabilité avec le modèle ML
    - déduit le verdict
    - insère dans la collection logs
    """
    try:
        content_bytes = await file.read()
        content_str = content_bytes.decode("utf-8")
        reader = csv.DictReader(io.StringIO(content_str))

        docs = []
        now = datetime.utcnow()

        for row in reader:
            subject = row.get("subject", "") or ""
            body = row.get("body", "") or ""
            url = row.get("url", "") or ""
            label_raw = (
                row.get("label", "").strip() if row.get("label") is not None else ""
            )

            # Modèle ML
            proba, explanations, url_feats = phishing_model.predict(subject, body, url)
            verdict = "phishing" if proba >= 0.5 else "legit"

            # label (optionnel)
            label = None
            if label_raw != "":
                try:
                    # ex: 1/0 -> phishing/legit
                    val = int(label_raw)
                    label = "tp" if (val == 1 and verdict == "phishing") else None
                except ValueError:
                    # si c'est déjà fp/fn/tp/tn
                    label = label_raw

            doc = {
                "timestamp": now,
                "subject": subject,
                "body": body,
                "url": url,
                "probability": float(proba),
                "verdict": verdict,
                "label": label,
                "features": explanations,
                "domain": url_feats["domain"],
                "tld": url_feats["tld"],
                "has_ip": url_feats["has_ip"],
                "url_length": url_feats["url_length"],
                "num_dots": url_feats["num_dots"],
                "source_ip": None,
            }
            docs.append(doc)

        inserted = 0
        if docs:
            result = logs_collection.insert_many(docs)
            inserted = len(result.inserted_ids)

        return ImportResult(inserted=inserted)

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur pendant l'import CSV : {e}")


# =========================
#   EXPORT CSV
# =========================

@app.get("/api/export_csv")
def export_csv(
    verdict: Optional[str] = None,
    label: Optional[str] = None,
):
    """
    Exporte les logs au format CSV.
    Filtres possibles :
    - verdict ("phishing" / "legit")
    - label ("fp" / "fn" / "tp" / "tn")
    """
    try:
        query: dict = {}
        if verdict:
            query["verdict"] = verdict
        if label:
            query["label"] = label

        cursor = logs_collection.find(query).sort("timestamp", -1)

        output = io.StringIO()
        writer = csv.writer(output)
        # entêtes CSV
        writer.writerow(
            [
                "id",
                "timestamp",
                "subject",
                "body",
                "url",
                "probability",
                "verdict",
                "label",
                "domain",
                "source_ip",
            ]
        )

        for d in cursor:
            writer.writerow(
                [
                    str(d.get("_id")),
                    d.get("timestamp").isoformat() if d.get("timestamp") else "",
                    d.get("subject", ""),
                    d.get("body", ""),
                    d.get("url", ""),
                    d.get("probability", ""),
                    d.get("verdict", ""),
                    d.get("label", ""),
                    d.get("domain", ""),
                    d.get("source_ip", ""),
                ]
            )

        csv_data = output.getvalue()
        output.close()

        return Response(
            content=csv_data,
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=phishguard_logs.csv"},
        )

    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Erreur pendant l'export CSV : {e}"
        )
