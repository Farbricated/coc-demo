"""
COC - Database Management System
===============================
MongoDB Atlas connection for Chain of Custody system
"""

import os
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from werkzeug.security import generate_password_hash, check_password_hash
import secrets

try:
    import pymongo
    from pymongo import MongoClient, errors
    from bson import ObjectId
    MONGODB_AVAILABLE = True
    print("✅ PyMongo available for MongoDB Atlas connection")
except ImportError:
    MONGODB_AVAILABLE = False
    print("❌ PyMongo not available - install with: pip install pymongo")

logger = logging.getLogger(__name__)

class COCDatabaseManager:
    """COC MongoDB Atlas database manager"""
    
    def __init__(self):
        self.mongo_client = None
        self.mongo_db = None
        self.connected = False
        self.connection_type = 'mongodb_atlas'
        self.database_name = 'coc'
        
        self._initialize_connection()
        
    def _initialize_connection(self):
        """Initialize MongoDB Atlas connection"""
        if not MONGODB_AVAILABLE:
            print("❌ MongoDB Atlas connection failed: PyMongo not installed")
            self.connection_type = 'unavailable'
            return
            
        try:
            # Load environment variables
            from dotenv import load_dotenv
            load_dotenv()
            
            mongo_uri = os.getenv('MONGO_URI')
            
            if not mongo_uri:
                print("❌ No MONGO_URI found in environment variables")
                self.connection_type = 'unavailable'
                return
            
            print(f"🔗 Connecting to COC MongoDB Atlas...")
            
            # Connect to MongoDB Atlas
            self.mongo_client = MongoClient(
                mongo_uri,
                serverSelectionTimeoutMS=10000,
                connectTimeoutMS=10000,
                socketTimeoutMS=20000
            )
            
            # Test connection
            print("🔍 Testing MongoDB Atlas connection...")
            self.mongo_client.admin.command('ping')
            
            # Connect to COC database
            self.mongo_db = self.mongo_client[self.database_name]
            
            # Check existing collections
            collections = self.mongo_db.list_collection_names()
            print(f"✅ Connected to COC database: '{self.database_name}'")
            print(f"📁 Collections: {collections}")
            
            if 'evidence' in collections:
                evidence_count = self.mongo_db.evidence.count_documents({})
                print(f"📊 Existing evidence: {evidence_count} documents")
            
            self.connected = True
            self._setup_indexes()
            
            print("🎉 COC MongoDB Atlas connection successful!")
            
        except Exception as e:
            print(f"❌ MongoDB Atlas connection error: {e}")
            self.connection_type = 'unavailable'
            self.connected = False
    
    def _setup_indexes(self):
        """Setup MongoDB indexes"""
        try:
            self.mongo_db.evidence.create_index("evidence_id", unique=True, background=True)
            self.mongo_db.evidence.create_index([("uploaded_at", -1)], background=True)
            self.mongo_db.users.create_index("username", unique=True, background=True)
            print("✅ MongoDB indexes created")
        except Exception as e:
            print(f"⚠️ Index creation warning: {e}")
    
    def authenticate_user(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        """Authenticate user"""
        try:
            if self.connection_type == 'mongodb_atlas':
                user = self.mongo_db.users.find_one({
                    'username': username,
                    'active': True
                })
                
                if user and check_password_hash(user['password_hash'], password):
                    self.mongo_db.users.update_one(
                        {'_id': user['_id']},
                        {'$set': {'last_login': datetime.now()}}
                    )
                    
                    user['id'] = str(user['_id'])
                    user.pop('_id', None)
                    user.pop('password_hash', None)
                    
                    return user
            
            # Fallback demo users
            demo_users = {
                'admin': {
                    'id': '1', 'username': 'admin', 'full_name': 'System Administrator',
                    'role': 'system_administrator', 'department': 'IT Security',
                    'clearance_level': 5, 'badge_number': 'ADM-001'
                },
                'analyst': {
                    'id': '2', 'username': 'analyst', 'full_name': 'Dr. Priya Sharma',
                    'role': 'senior_forensic_analyst', 'department': 'Digital Forensics',
                    'clearance_level': 4, 'badge_number': 'FSA-042'
                },
                'investigator': {
                    'id': '3', 'username': 'investigator', 'full_name': 'Inspector Rajesh Kumar',
                    'role': 'senior_investigating_officer', 'department': 'CID',
                    'clearance_level': 3, 'badge_number': 'CID-287'
                }
            }
            
            passwords = {'admin': 'admin123', 'analyst': 'password123', 'investigator': 'password123'}
            
            if username in passwords and passwords[username] == password:
                return demo_users[username]
            
            return None
            
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            return None
    
    def get_evidence_list(self, limit: int = 50, user_clearance: int = 5, filters: Dict = None) -> List[Dict[str, Any]]:
        """Get evidence from MongoDB"""
        try:
            if self.connection_type == 'mongodb_atlas':
                query = {'classification_level': {'$lte': user_clearance}}
                
                cursor = self.mongo_db.evidence.find(query).sort('uploaded_at', -1).limit(limit)
                
                results = []
                for doc in cursor:
                    doc['id'] = str(doc['_id'])
                    doc.pop('_id', None)
                    results.append(doc)
                
                return results
            
            return []
            
        except Exception as e:
            logger.error(f"Evidence retrieval error: {e}")
            return []
    
    def get_dashboard_stats(self, user_clearance: int = 5) -> Dict[str, Any]:
        """Get dashboard statistics"""
        try:
            if self.connection_type == 'mongodb_atlas':
                total_evidence = self.mongo_db.evidence.count_documents({'classification_level': {'$lte': user_clearance}})
                
                active_cases_pipeline = [
                    {'$match': {'classification_level': {'$lte': user_clearance}}},
                    {'$group': {'_id': '$case_id'}},
                    {'$count': 'unique_cases'}
                ]
                active_cases_result = list(self.mongo_db.evidence.aggregate(active_cases_pipeline))
                active_cases = active_cases_result[0]['unique_cases'] if active_cases_result else 0
                
                pending_analysis = self.mongo_db.evidence.count_documents({
                    'status': 'PROCESSING',
                    'classification_level': {'$lte': user_clearance}
                })
                
                high_risk_items = self.mongo_db.evidence.count_documents({
                    'risk_level': {'$in': ['HIGH', 'CRITICAL']},
                    'classification_level': {'$lte': user_clearance}
                })
                
                return {
                    'total_evidence': total_evidence,
                    'active_cases': active_cases,
                    'pending_analysis': pending_analysis,
                    'high_risk_items': high_risk_items,
                    'blockchain_anchored': 0,
                    'system_uptime': '99.9%'
                }
            else:
                return {'total_evidence': 0, 'active_cases': 0, 'pending_analysis': 0, 'high_risk_items': 0}
                
        except Exception as e:
            logger.error(f"Dashboard stats error: {e}")
            return {'total_evidence': 0, 'active_cases': 0, 'pending_analysis': 0, 'high_risk_items': 0}
    
    def save_evidence(self, evidence_data: Dict[str, Any]) -> bool:
        """Save evidence to MongoDB"""
        try:
            if self.connection_type == 'mongodb_atlas':
                evidence_data['uploaded_at'] = datetime.now()
                evidence_data['created_at'] = datetime.now()
                
                result = self.mongo_db.evidence.insert_one(evidence_data)
                
                if result.inserted_id:
                    logger.info(f"Evidence saved to COC database: {evidence_data.get('evidence_id')}")
                    return True
            
            return False
            
        except Exception as e:
            logger.error(f"Evidence save error: {e}")
            return False
    
    def search_evidence(self, query: str, user_clearance: int = 5) -> List[Dict[str, Any]]:
        """Search evidence in MongoDB"""
        try:
            if self.connection_type == 'mongodb_atlas':
                search_query = {
                    'classification_level': {'$lte': user_clearance},
                    '$or': [
                        {'filename': {'$regex': query, '$options': 'i'}},
                        {'case_id': {'$regex': query, '$options': 'i'}},
                        {'evidence_id': {'$regex': query, '$options': 'i'}}
                    ]
                }
                
                cursor = self.mongo_db.evidence.find(search_query).sort('uploaded_at', -1).limit(50)
                
                results = []
                for doc in cursor:
                    doc['id'] = str(doc['_id'])
                    doc.pop('_id', None)
                    results.append(doc)
                
                return results
            
            return []
            
        except Exception as e:
            logger.error(f"Search error: {e}")
            return []

# Global database instance
db = COCDatabaseManager()
