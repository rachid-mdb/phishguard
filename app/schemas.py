# app/schemas.py
from pydantic import BaseModel
from typing import List, Optional


class DetectRequest(BaseModel):
    subject: Optional[str] = ""
    body: Optional[str] = ""
    url: Optional[str] = ""


class DetectResponse(BaseModel):
    probability: float       # probabilité que ce soit du phishing (0–1)
    verdict: str             # "phishing" ou "legit"
    features: List[str]      # explications (mots suspects, IP, TLD...)
    log_id: str              # id du document enregistré en BD


class LogOut(BaseModel):
    """Format d'un log renvoyé au frontend."""
    id: str
    timestamp: str
    subject: str
    body: str
    url: str
    probability: float
    verdict: str
    label: Optional[str] = None
    domain: Optional[str] = None
    source_ip: Optional[str] = None


class ReportRequest(BaseModel):
    """Pour marquer un log comme faux positif / vrai positif, etc."""
    log_id: str           # _id MongoDB
    label: str            # "fp", "fn", "tp", "tn"


class ImportResult(BaseModel):
    """Réponse pour /api/import_csv."""
    inserted: int         # nombre de lignes insérées
