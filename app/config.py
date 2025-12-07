import os
from dotenv import load_dotenv

# Charge les variables du fichier .env à la racine du projet
load_dotenv()

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
DB_NAME = os.getenv("DB_NAME", "phishguard")