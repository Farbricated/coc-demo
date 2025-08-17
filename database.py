# coc-demo/database.py

from pymongo import MongoClient
from pymongo.errors import ConnectionFailure
import os
from datetime import datetime

# It's best practice to use an environment variable for your connection string.
MONGO_URI = "mongodb+srv://fab:zfZ4o24ge9kPdpEo@coc.wdx4a64.mongodb.net/?retryWrites=true&w=majority&appName=coc"

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
    """Saves a new evidence record to the database."""
    if evidence_collection is None:
        return None
    
    record_data["timestamp_utc"] = datetime.utcnow()
    try:
        result = evidence_collection.insert_one(record_data)
        return result.inserted_id
    except Exception as e:
        print(f"Error saving to DB: {e}")
        return None

def find_evidence_by_hash(image_hash):
    """Finds an evidence record by its image hash."""
    if evidence_collection is None:
        return None
    return evidence_collection.find_one({"image_hash": image_hash})

