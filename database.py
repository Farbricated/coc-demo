# coc-demo/database.py

from pymongo import MongoClient
from pymongo.errors import ConnectionFailure
from datetime import datetime
import os

# This assumes you have a .env file in the 'assets' directory
from dotenv import load_dotenv
dotenv_path = os.path.join(os.path.dirname(__file__), 'assets', '.env')
load_dotenv(dotenv_path=dotenv_path)

MONGO_URI = os.getenv("MONGO_URI")

try:
    client = MongoClient(MONGO_URI)
    client.admin.command('ismaster')
    print("MongoDB connection successful.")
except ConnectionFailure as e:
    print(f"Could not connect to MongoDB: {e}")
    client = None

db = client['coc_database'] if client is not None else None
evidence_collection = db['evidence_records'] if db is not None else None


def save_evidence_record(record_data):
    if evidence_collection is None: return None
    try:
        return evidence_collection.insert_one(record_data).inserted_id
    except Exception as e:
        print(f"Error saving to DB: {e}")
        return None

def find_evidence_by_hash(image_hash):
    if evidence_collection is None: return None
    return evidence_collection.find_one({"image_hash": image_hash})

def get_evidence_stats():
    if evidence_collection is None: return {"total": 0, "High": 0, "Medium": 0, "Low": 0}
    pipeline = [{"$group": {"_id": "$risk_level", "count": {"$sum": 1}}}]
    risk_counts = {item["_id"]: item["count"] for item in evidence_collection.aggregate(pipeline)}
    return {
        "total": evidence_collection.count_documents({}),
        "High": risk_counts.get("High", 0),
        "Medium": risk_counts.get("Medium", 0),
        "Low": risk_counts.get("Low", 0),
    }

def get_recent_evidence(limit=5):
    if evidence_collection is None: return []
    return list(evidence_collection.find({}, {"analysis_data": 0}).sort("timestamp_utc", -1).limit(limit))

