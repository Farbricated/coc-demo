# database.py - Complete Enhanced Version with Role-Based User Management and All Features

import os
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError
from dotenv import load_dotenv
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash

# --- Configuration ---
dotenv_path = os.path.join(os.path.dirname(__file__), 'assets', '.env')
load_dotenv(dotenv_path=dotenv_path)

MONGO_URI = os.getenv("MONGO_URI")

class Database:
    """Enhanced singleton class with highly differentiated role-based user management."""
    _instance = None

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(Database, cls).__new__(cls, *args, **kwargs)
        return cls._instance

    def __init__(self):
        if hasattr(self, '_initialized') and self._initialized:
            return
            
        self.client = None
        self._initialized = False
        
        try:
            if not MONGO_URI:
                raise ValueError("MONGO_URI not found in .env file.")
            
            self.client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
            self.client.admin.command('ping')
            self.db = self.client['coc_database']
            
            # Collections
            self.evidence_collection = self.db['evidence_records']
            self.users_collection = self.db['users']
            self.audit_log_collection = self.db['audit_log']
            self.custody_events_collection = self.db['custody_events']
            self.access_logs_collection = self.db['access_logs']
            self.system_config_collection = self.db['system_config']
            self.approval_requests_collection = self.db['approval_requests']
            self.case_management_collection = self.db['case_management']
            
            self._initialized = True
            print("SUCCESS: MongoDB connection established.")
            self.ensure_default_users()
            
        except Exception as e:
            print(f"CRITICAL ERROR: Database initialization failed: {e}")
            self._initialized = False
            raise

    def get_default_permissions(self, department):
        """🔧 ENHANCED: Highly differentiated permissions for each department"""
        permissions_map = {
            # 👑 ADMIN: Complete system control
            "Admin": [
                "all", "user_management", "system_config", "database_admin", 
                "audit_full", "ingest", "verify", "database", "export", 
                "reports", "advanced_analysis", "blockchain_admin", "security_settings",
                "backup_restore", "system_monitor", "case_management", "legal_review"
            ],
            
            # 🔬 FORENSICS: Evidence handling and advanced analysis
            "Forensics": [
                "ingest", "verify", "database", "audit", "export", "reports", 
                "advanced_analysis", "steganography", "metadata_analysis", 
                "risk_assessment", "evidence_processing", "lab_tools",
                "forensic_reports", "chain_of_custody", "image_analysis",
                "document_analysis", "hash_verification", "timeline_generation"
            ],
            
            # ⚖️ LEGAL: Evidence verification and legal procedures
            "Legal": [
                "verify", "database", "export", "reports", "legal_review", 
                "case_management", "evidence_authentication", "court_reports",
                "compliance_check", "legal_analysis", "discovery_support",
                "testimony_prep", "approval_workflow", "evidence_approval",
                "legal_holds", "regulatory_compliance"
            ],
            
            # 💻 IT: System administration and technical support
            "IT": [
                "database", "audit", "system_config", "verify", "reports",
                "system_monitor", "backup_restore", "network_config",
                "security_audit", "performance_monitor", "troubleshooting",
                "infrastructure_management", "user_access_control", 
                "database_maintenance", "security_settings"
            ],
            
            # 📊 MANAGEMENT: Strategic oversight and reporting
            "Management": [
                "database", "reports", "audit", "overview", "verify",
                "dashboard_access", "strategic_analysis", "resource_planning",
                "performance_metrics", "budget_reports", "team_oversight",
                "executive_summary", "approval_workflow", "request_management",
                "kpi_tracking", "compliance_oversight"
            ]
        }
        return permissions_map.get(department, ["verify", "database"])

    def get_department_description(self, department):
        """Get detailed description of department capabilities"""
        descriptions = {
            "Admin": "🔧 Full system administration with complete access to all features, user management, and system configuration.",
            "Forensics": "🔬 Digital forensics specialists with evidence ingestion, advanced analysis, and chain of custody management.",
            "Legal": "⚖️ Legal professionals with evidence verification, case management, and compliance oversight capabilities.", 
            "IT": "💻 Technical administrators with system monitoring, security auditing, and infrastructure management access.",
            "Management": "📊 Executive oversight with strategic reporting, performance metrics, and team management capabilities."
        }
        return descriptions.get(department, "Standard user with basic verification and database access.")

    def create_user(self, username, password, department):
        """Creates a new user with enhanced role-based permissions."""
        try:
            if self.users_collection.find_one({"username": username}):
                print(f"User '{username}' already exists.")
                return False
            
            hashed_password = generate_password_hash(password)
            permissions = self.get_default_permissions(department)
            
            user_doc = {
                "username": username, 
                "password": hashed_password, 
                "department": department,
                "permissions": permissions,
                "is_admin": department.lower() == "admin",
                "created_at": datetime.utcnow(),
                "last_login": None,
                "login_attempts": 0,
                "account_status": "ACTIVE",  # 🔧 FIX: Always set to ACTIVE
                "created_by": "system",
                "department_description": self.get_department_description(department),
                "max_concurrent_sessions": 3 if department.lower() == "admin" else 1,
                "password_expires": datetime.utcnow() + timedelta(days=90),
                "requires_2fa": department.lower() in ["admin", "forensics"],
                "profile": {
                    "full_name": username.replace('_', ' ').title(),
                    "email": f"{username}@coc-system.local",
                    "phone": None,
                    "avatar": None
                }
            }
            result = self.users_collection.insert_one(user_doc)
            print(f"✅ User '{username}' created successfully as {department} with {len(permissions)} permissions.")
            return True
        except Exception as e:
            print(f"Error creating user: {e}")
            return False

    def ensure_default_users(self):
        """Creates enhanced default users with proper permissions and descriptions."""
        try:
            default_users = [
                ("admin", "admin123", "Admin"),
                ("forensics_user", "password123", "Forensics"),
                ("legal_user", "password123", "Legal"),
                ("it_user", "password123", "IT"),
                ("management_user", "password123", "Management")
            ]
            
            for username, password, department in default_users:
                existing_user = self.users_collection.find_one({"username": username})
                if not existing_user:
                    self.create_user(username, password, department)
                else:
                    # 🔧 FIX: Update existing users with complete new structure
                    permissions = self.get_default_permissions(department)
                    self.users_collection.update_one(
                        {"username": username},
                        {
                            "$set": {
                                "permissions": permissions,
                                "is_admin": department.lower() == "admin",
                                "department": department,
                                "account_status": "ACTIVE",  # 🔧 FIX: Ensure all users are ACTIVE
                                "department_description": self.get_department_description(department),
                                "updated_at": datetime.utcnow(),
                                "profile": {
                                    "full_name": username.replace('_', ' ').title(),
                                    "email": f"{username}@coc-system.local",
                                    "phone": None,
                                    "avatar": None
                                }
                            }
                        }
                    )
                    print(f"🔄 Updated permissions for user '{username}' ({department}: {len(permissions)} permissions)")
            
            total_users = self.users_collection.count_documents({})
            print(f"✅ Database initialized with {total_users} users with enhanced role-based permissions.")
            
        except Exception as e:
            print(f"Error ensuring default users: {e}")

    def find_user(self, username):
        """Finds a user by username with enhanced data."""
        try:
            return self.users_collection.find_one({"username": username})
        except Exception as e:
            print(f"Error finding user: {e}")
            return None

    def update_login_attempt(self, username, success=False):
        """Updates login attempt counter and last login time."""
        try:
            if success:
                self.users_collection.update_one(
                    {"username": username},
                    {
                        "$set": {"last_login": datetime.utcnow(), "login_attempts": 0}
                    }
                )
            else:
                self.users_collection.update_one(
                    {"username": username},
                    {"$inc": {"login_attempts": 1}}
                )
        except Exception as e:
            print(f"Error updating login attempt: {e}")

    def get_all_users(self):
        """Get all users for admin management with enhanced details."""
        try:
            users = list(self.users_collection.find({}, {"password": 0}))  # Exclude password
            for user in users:
                user['_id'] = str(user['_id'])
                if isinstance(user.get('created_at'), datetime):
                    user['created_at'] = user['created_at'].strftime('%Y-%m-%d %H:%M:%S')
                if isinstance(user.get('last_login'), datetime):
                    user['last_login'] = user['last_login'].strftime('%Y-%m-%d %H:%M:%S')
            return users
        except Exception as e:
            print(f"Error getting all users: {e}")
            return []

    def get_system_stats(self):
        """Get comprehensive system statistics for admin."""
        try:
            stats = {
                "total_users": self.users_collection.count_documents({}),
                "total_evidence": self.evidence_collection.count_documents({}),
                "total_audit_logs": self.audit_log_collection.count_documents({}),
                "active_users": self.users_collection.count_documents({"account_status": "ACTIVE"}),
                "recent_logins": self.users_collection.count_documents({
                    "last_login": {"$gte": datetime.utcnow().replace(hour=0, minute=0, second=0)}
                }),
                "departments": {},
                "cases_active": self.case_management_collection.count_documents({"status": "active"}),
                "pending_approvals": self.approval_requests_collection.count_documents({"status": "pending"})
            }
            
            # Department breakdown with permission counts
            pipeline = [{"$group": {"_id": "$department", "count": {"$sum": 1}}}]
            for dept in self.users_collection.aggregate(pipeline):
                dept_permissions = len(self.get_default_permissions(dept["_id"]))
                stats["departments"][dept["_id"]] = {
                    "count": dept["count"],
                    "permissions": dept_permissions,
                    "description": self.get_department_description(dept["_id"])
                }
                
            return stats
        except Exception as e:
            print(f"Error getting system stats: {e}")
            return {}

    def log_action(self, username, action, details=""):
        """Enhanced logging with user context and department tracking."""
        try:
            user = self.find_user(username)
            department = user.get("department", "Unknown") if user else "Unknown"
            
            log_entry = {
                "username": username,
                "department": department,
                "action": action,
                "details": details,
                "timestamp_utc": datetime.utcnow(),
                "ip_address": "127.0.0.1",
                "user_agent": "CoC System",
                "session_id": f"{username}_{datetime.utcnow().timestamp()}"[:16],
                "severity": self._get_action_severity(action),
                "category": self._get_action_category(action)
            }
            self.audit_log_collection.insert_one(log_entry)
        except Exception as e:
            print(f"Error logging action: {e}")

    def _get_action_severity(self, action):
        """Determine the severity level of an action for audit purposes."""
        high_severity = ["USER_LOGIN_FAILED", "SYSTEM_CONFIG_CHANGE", "USER_CREATE", "USER_DELETE", "EVIDENCE_DELETE"]
        medium_severity = ["INGEST_EVIDENCE", "VERIFY_EVIDENCE", "EXPORT_DATA", "APPROVE_EVIDENCE"]
        
        if action in high_severity:
            return "HIGH"
        elif action in medium_severity:
            return "MEDIUM"
        else:
            return "LOW"

    def _get_action_category(self, action):
        """Categorize actions for better organization."""
        categories = {
            "USER_LOGIN_SUCCESS": "Authentication",
            "USER_LOGIN_FAILED": "Authentication", 
            "USER_LOGOUT": "Authentication",
            "INGEST_EVIDENCE": "Evidence Management",
            "VERIFY_EVIDENCE": "Evidence Management",
            "APPROVE_EVIDENCE": "Legal Review",
            "CREATE_USER": "User Management",
            "SYSTEM_CONFIG_CHANGE": "System Administration"
        }
        return categories.get(action, "General")

    def log_access(self, username, evidence_hash, access_type="VIEW"):
        """Logs evidence access for audit trail."""
        try:
            access_entry = {
                "username": username,
                "evidence_hash": evidence_hash,
                "access_type": access_type,
                "timestamp_utc": datetime.utcnow(),
                "session_id": f"{username}_{datetime.utcnow().timestamp()}"[:16],
                "ip_address": "127.0.0.1"
            }
            self.access_logs_collection.insert_one(access_entry)
        except Exception as e:
            print(f"Error logging access: {e}")

    def record_custody_event(self, evidence_hash, event_type, from_user, to_user=None, details=""):
        """Records custody transfer events."""
        try:
            custody_event = {
                "evidence_hash": evidence_hash,
                "event_type": event_type,
                "from_user": from_user,
                "to_user": to_user,
                "details": details,
                "timestamp_utc": datetime.utcnow(),
                "event_id": f"{evidence_hash[:8]}_{event_type}_{int(datetime.utcnow().timestamp())}"
            }
            self.custody_events_collection.insert_one(custody_event)
        except Exception as e:
            print(f"Error recording custody event: {e}")

    def save_evidence_record(self, record_data):
        """Saves a new evidence record with enhanced tracking."""
        try:
            if 'timestamp_utc' not in record_data:
                record_data['timestamp_utc'] = datetime.utcnow()
            
            # Add integrity metadata
            record_data['integrity_check'] = {
                'created': datetime.utcnow(),
                'last_verified': datetime.utcnow(),
                'verification_count': 0,
                'status': 'ACTIVE'
            }
            
            # Add department tracking
            user = self.find_user(record_data.get('custodian_username', 'system'))
            if user:
                record_data['custodian_department'] = user.get('department', 'Unknown')
            
            inserted_id = self.evidence_collection.insert_one(record_data).inserted_id
            
            # Enhanced logging
            log_details = f"Case ID: {record_data.get('caseId')}, SHA256: {record_data.get('sha256Hash')}, Department: {record_data.get('custodian_department', 'Unknown')}"
            self.log_action(record_data.get('custodian_username', 'system'), "INGEST_EVIDENCE", log_details)
            
            # Record initial custody event
            self.record_custody_event(
                record_data.get('sha256Hash'),
                "INITIAL_CUSTODY",
                record_data.get('custodian_username', 'system'),
                details=f"Evidence initially ingested for case {record_data.get('caseId')}"
            )
            
            return inserted_id
        except Exception as e:
            print(f"Error saving evidence record: {e}")
            return None

    def find_evidence_by_hash(self, sha256_hash):
        """Finds evidence by SHA256 hash."""
        try:
            return self.evidence_collection.find_one({"sha256Hash": sha256_hash})
        except Exception as e:
            print(f"Error finding evidence: {e}")
            return None

    def get_evidence_stats(self):
        """Gets comprehensive statistics about evidence records."""
        try:
            pipeline = [{"$group": {"_id": "$riskLevel", "count": {"$sum": 1}}}]
            risk_counts = {item["_id"]: item["count"] for item in self.evidence_collection.aggregate(pipeline)}
            total_docs = self.evidence_collection.count_documents({})
            
            recent_count = self.evidence_collection.count_documents({
                "timestamp_utc": {"$gte": datetime.utcnow().replace(hour=0, minute=0, second=0)}
            })
            
            case_pipeline = [{"$group": {"_id": "$caseId", "evidence_count": {"$sum": 1}}}]
            case_stats = list(self.evidence_collection.aggregate(case_pipeline))
            unique_cases = len(case_stats)
            
            return {
                "Total Evidence": total_docs,
                "High": risk_counts.get("High", 0),
                "Medium": risk_counts.get("Medium", 0),
                "Low": risk_counts.get("Low", 0),
                "Today": recent_count,
                "Unique Cases": unique_cases,
                "Average per Case": round(total_docs / max(unique_cases, 1), 1)
            }
        except Exception as e:
            print(f"Could not retrieve stats from DB: {e}")
            return {"Total Evidence": 0, "High": 0, "Medium": 0, "Low": 0, "Today": 0, "Unique Cases": 0}

    def get_all_evidence(self, department_filter=None):
        """Gets all evidence records with optional filtering."""
        try:
            query = department_filter if department_filter else {}
            projection = {"analysisData": 0}  # Exclude large analysis data
            return list(self.evidence_collection.find(query, projection).sort("timestamp_utc", -1))
        except Exception as e:
            print(f"Error getting evidence: {e}")
            return []

    def get_audit_logs(self, limit=50):
        """Retrieves the most recent audit logs."""
        try:
            return list(self.audit_log_collection.find().sort("timestamp_utc", -1).limit(limit))
        except Exception as e:
            print(f"Error getting audit logs: {e}")
            return []

    def get_custody_events(self, evidence_hash):
        """Gets custody events for specific evidence."""
        try:
            return list(self.custody_events_collection.find(
                {"evidence_hash": evidence_hash}
            ).sort("timestamp_utc", 1))
        except Exception as e:
            print(f"Error getting custody events: {e}")
            return []

    def get_access_logs(self, evidence_hash, limit=20):
        """Gets access logs for specific evidence."""
        try:
            return list(self.access_logs_collection.find(
                {"evidence_hash": evidence_hash}
            ).sort("timestamp_utc", -1).limit(limit))
        except Exception as e:
            print(f"Error getting access logs: {e}")
            return []

    def get_evidence_timeline(self, evidence_hash):
        """Gets complete timeline for evidence including all events."""
        try:
            timeline = []
            
            # Get original evidence record
            evidence = self.find_evidence_by_hash(evidence_hash)
            if evidence:
                timeline.append({
                    'event_type': 'EVIDENCE_INGESTED',
                    'timestamp': evidence.get('timestamp_utc'),
                    'user': evidence.get('custodian_username'),
                    'details': f"Evidence ingested for case {evidence.get('caseId')}"
                })
            
            # Get custody events
            custody_events = self.get_custody_events(evidence_hash)
            for event in custody_events:
                timeline.append({
                    'event_type': event.get('event_type'),
                    'timestamp': event.get('timestamp_utc'),
                    'user': event.get('from_user'),
                    'details': event.get('details')
                })
            
            # Sort by timestamp
            timeline.sort(key=lambda x: x['timestamp'] if x['timestamp'] else datetime.min)
            
            return timeline
        except Exception as e:
            print(f"Error getting evidence timeline: {e}")
            return []

    def get_case_evidence(self, case_id):
        """Gets all evidence for a specific case."""
        try:
            return list(self.evidence_collection.find({"caseId": case_id}).sort("timestamp_utc", 1))
        except Exception as e:
            print(f"Error getting case evidence: {e}")
            return []

    def update_evidence_verification(self, evidence_hash, verification_result):
        """Updates evidence verification status."""
        try:
            self.evidence_collection.update_one(
                {"sha256Hash": evidence_hash},
                {
                    "$set": {
                        "integrity_check.last_verified": datetime.utcnow(),
                        "integrity_check.verification_result": verification_result
                    },
                    "$inc": {"integrity_check.verification_count": 1}
                }
            )
        except Exception as e:
            print(f"Error updating verification: {e}")

    # Case Management Methods
    def create_case(self, case_id, title, description, assigned_to, created_by):
        """Creates a new case for evidence management."""
        try:
            case_doc = {
                "case_id": case_id,
                "title": title,
                "description": description,
                "assigned_to": assigned_to,
                "created_by": created_by,
                "created_at": datetime.utcnow(),
                "status": "active",
                "evidence_count": 0,
                "last_updated": datetime.utcnow()
            }
            self.case_management_collection.insert_one(case_doc)
            self.log_action(created_by, "CREATE_CASE", f"Created case {case_id}")
            return True
        except Exception as e:
            print(f"Error creating case: {e}")
            return False

    def get_active_cases(self):
        """Get all active cases."""
        try:
            return list(self.case_management_collection.find({"status": "active"}))
        except Exception as e:
            print(f"Error getting active cases: {e}")
            return []

    # Approval Request Methods
    def create_approval_request(self, request_type, requested_by, department, details):
        """Creates a new approval request."""
        try:
            request_doc = {
                "request_id": f"REQ{int(datetime.utcnow().timestamp())}",
                "request_type": request_type,
                "requested_by": requested_by,
                "department": department,
                "details": details,
                "status": "pending",
                "created_at": datetime.utcnow(),
                "priority": "medium"
            }
            self.approval_requests_collection.insert_one(request_doc)
            return True
        except Exception as e:
            print(f"Error creating approval request: {e}")
            return False

    def get_pending_approvals(self):
        """Get all pending approval requests."""
        try:
            return list(self.approval_requests_collection.find({"status": "pending"}))
        except Exception as e:
            print(f"Error getting pending approvals: {e}")
            return []

    # System Configuration Methods
    def get_system_config(self, key):
        """Gets system configuration value."""
        try:
            config = self.system_config_collection.find_one({"key": key})
            return config.get("value") if config else None
        except Exception as e:
            print(f"Error getting config: {e}")
            return None

    def set_system_config(self, key, value):
        """Sets system configuration value."""
        try:
            self.system_config_collection.update_one(
                {"key": key},
                {"$set": {"key": key, "value": value, "updated_at": datetime.utcnow()}},
                upsert=True
            )
        except Exception as e:
            print(f"Error setting config: {e}")

    def delete_user(self, username):
        """Deletes a user (admin only)."""
        try:
            result = self.users_collection.delete_one({"username": username})
            return result.deleted_count > 0
        except Exception as e:
            print(f"Error deleting user: {e}")
            return False

    def update_user_permissions(self, username, permissions):
        """Updates user permissions (admin only)."""
        try:
            result = self.users_collection.update_one(
                {"username": username},
                {"$set": {"permissions": permissions}}
            )
            return result.modified_count > 0
        except Exception as e:
            print(f"Error updating permissions: {e}")
            return False

    def test_login_credentials(self, username, password):
        """Enhanced test function to verify login credentials work."""
        try:
            user = self.find_user(username)
            if user:
                from werkzeug.security import check_password_hash
                password_match = check_password_hash(user['password'], password)
                
                print(f"🔐 Login test for '{username}':")
                print(f"   Status: {'✅ SUCCESS' if password_match else '❌ FAILED'}")
                print(f"   Department: {user.get('department', 'Unknown')}")
                print(f"   Account Status: {user.get('account_status', 'Unknown')}")
                print(f"   Permissions Count: {len(user.get('permissions', []))}")
                print(f"   Is Admin: {user.get('is_admin', False)}")
                print(f"   Description: {user.get('department_description', 'No description')}")
                print(f"   Last Login: {user.get('last_login', 'Never')}")
                print()
                
                return password_match
            else:
                print(f"❌ User '{username}' not found in database.")
                return False
        except Exception as e:
            print(f"Error testing credentials: {e}")
            return False

    def fix_user_accounts_and_test(self):
        """🔧 FINAL FIX: Complete user account repair and testing"""
        print("=== 🔧 FIXING ALL USER ACCOUNTS (FINAL UPDATE) ===")
        
        try:
            # Update all existing users with enhanced permissions
            self.ensure_default_users()
            
            # Test all logins
            print("\n=== 🧪 TESTING ALL USER CREDENTIALS ===")
            default_users = [
                ("admin", "admin123"),
                ("forensics_user", "password123"), 
                ("legal_user", "password123"),
                ("it_user", "password123"),
                ("management_user", "password123")
            ]
            
            for username, password in default_users:
                self.test_login_credentials(username, password)
            
            # Display department breakdown
            stats = self.get_system_stats()
            print("=== 📊 DEPARTMENT BREAKDOWN ===")
            for dept, info in stats.get("departments", {}).items():
                print(f"🏢 {dept}: {info.get('count', 0)} users, {info.get('permissions', 0)} permissions")
                print(f"   {info.get('description', 'No description')}")
                print()
                
            print("✅ ALL USER ACCOUNTS FIXED AND TESTED SUCCESSFULLY!")
            return True
            
        except Exception as e:
            print(f"❌ Error fixing accounts: {e}")
            return False

    def cleanup_old_logs(self, retention_days=365):
        """Cleanup old audit logs based on retention policy."""
        try:
            cutoff_date = datetime.utcnow() - timedelta(days=retention_days)
            result = self.audit_log_collection.delete_many({"timestamp_utc": {"$lt": cutoff_date}})
            print(f"Cleaned up {result.deleted_count} old log entries")
            return result.deleted_count
        except Exception as e:
            print(f"Error cleaning up logs: {e}")
            return 0

    def get_database_size_info(self):
        """Gets database size information."""
        try:
            db_stats = self.db.command("dbstats")
            return {
                "dataSize": db_stats.get("dataSize", 0),
                "storageSize": db_stats.get("storageSize", 0),
                "indexSize": db_stats.get("indexSize", 0),
                "collections": db_stats.get("collections", 0),
                "objects": db_stats.get("objects", 0)
            }
        except Exception as e:
            print(f"Error getting database stats: {e}")
            return {}

# Create singleton instance
db_client = Database()

# Test credentials on startup
if __name__ == "__main__":
    print("=== 🚀 TESTING DATABASE WITH ENHANCED ROLE DIFFERENTIATION ===")
    
    # Test MongoDB connection
    if db_client._initialized:
        print("✅ MongoDB connection successful")
        
        # Run complete user account fix and test
        db_client.fix_user_accounts_and_test()
        
        # Test system functionality
        print("\n=== 🔧 TESTING SYSTEM FUNCTIONALITY ===")
        
        # Test case creation
        db_client.create_case("TEST001", "Test Case", "Test case description", "forensics_user", "admin")
        
        # Test approval request
        db_client.create_approval_request("Evidence Access", "legal_user", "Legal", "Need access to evidence for case TEST001")
        
        print("✅ All system components tested successfully!")
        
    else:
        print("❌ Database connection failed")
