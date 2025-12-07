from pymongo import MongoClient
from .config import MONGO_URI, DB_NAME

client = MongoClient(MONGO_URI)
db = client[DB_NAME]

# Collections que l'on va utiliser dans le projet
logs_collection = db["logs"]
dataset_collection = db["dataset"]