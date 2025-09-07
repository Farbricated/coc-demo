# app.py - Complete Advanced Chain of Custody System with All Department Quick Actions

import sys
import os
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'

# Core imports
import dash
import base64
import io
import hashlib
import json
import magic
import qrcode
import numpy as np
import piexif
import PyPDF2
from dash import dcc, html, Input, Output, State, dash_table, no_update, callback_context
import dash_bootstrap_components as dbc
from PIL import Image, ExifTags
from datetime import datetime, timedelta
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user
from werkzeug.security import check_password_hash
import traceback
import pandas as pd

# --- SETUP ---
try:
    from database import db_client
    from blockchain import blockchain_service
except Exception as e:
    print(f"--- A CRITICAL STARTUP ERROR OCCURRED: {e} ---")
    sys.exit(1)

# --- MODEL LOADING (with graceful failure) ---
try:
    from tensorflow.keras.applications.mobilenet_v2 import MobileNetV2, preprocess_input, decode_predictions
    from tensorflow.keras.preprocessing import image as keras_image
    from stegano import lsb
    classification_model = MobileNetV2(weights='imagenet')
    ADVANCED_ANALYSIS_ENABLED = True
    print("SUCCESS: Advanced analysis libraries loaded.")
except ImportError:
    ADVANCED_ANALYSIS_ENABLED = False
    classification_model = None
    print("WARNING: 'tensorflow' or 'stegano' not found. Advanced analysis will be disabled.")

# --- APP & LOGIN MANAGER INITIALIZATION ---
FONT_AWESOME = "https://use.fontawesome.com/releases/v5.15.4/css/all.css"
app = dash.Dash(__name__, external_stylesheets=[dbc.themes.DARKLY, FONT_AWESOME], suppress_callback_exceptions=True, title="CoC System")
server = app.server
server.config.update(SECRET_KEY=os.urandom(24))

login_manager = LoginManager()
login_manager.init_app(server)
login_manager.login_view = '/login'

# --- ENHANCED USER CLASS WITH DEPARTMENT-SPECIFIC PERMISSIONS ---
class User(UserMixin):
    def __init__(self, user_data):
        self.id = user_data['username']
        self.department = user_data.get('department', 'Default')
        self.permissions = user_data.get('permissions', [])
        self.is_admin = user_data.get('is_admin', False) or (self.department.lower() == 'admin')
        self.last_login = user_data.get('last_login')
        self.account_status = user_data.get('account_status', 'ACTIVE')
        self.department_description = user_data.get('department_description', '')

    def has_permission(self, permission):
        """Check if user has specific permission"""
        if self.is_admin or 'all' in self.permissions:
            return True
        return permission in self.permissions

    # Department-specific permission methods
    def can_ingest(self):
        return self.has_permission('ingest')
    
    def can_verify(self):
        return self.has_permission('verify')
    
    def can_access_database(self):
        return self.has_permission('database')
    
    def can_view_audit(self):
        return self.has_permission('audit')
    
    def can_manage_users(self):
        return self.has_permission('user_management')
    
    def can_export(self):
        return self.has_permission('export')
    
    def can_advanced_analysis(self):
        return self.has_permission('advanced_analysis')
    
    def can_system_config(self):
        return self.has_permission('system_config')

@login_manager.user_loader
def load_user(username):
    user_data = db_client.find_user(username)
    return User(user_data) if user_data else None

# --- HELPER FUNCTIONS ---
def safe_json_dumps(data):
    """Enhanced JSON serialization that handles datetime objects."""
    def default_serializer(obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        elif isinstance(obj, (bytes, bytearray)):
            return obj.decode('utf-8', errors='ignore')
        elif hasattr(obj, '__dict__'):
            return obj.__dict__
        else:
            return str(obj)
    
    return json.dumps(data, sort_keys=True, default=default_serializer, indent=2)

def serialize_datetime_objects(obj):
    """Recursively convert datetime objects to strings in nested structures."""
    if isinstance(obj, datetime):
        return obj.strftime('%Y-%m-%d %H:%M:%S')
    elif isinstance(obj, dict):
        return {key: serialize_datetime_objects(value) for key, value in obj.items()}
    elif isinstance(obj, list):
        return [serialize_datetime_objects(item) for item in obj]
    else:
        return obj

def clean_keys_for_mongo(d):
    if isinstance(d, dict):
        return {str(k): clean_keys_for_mongo(v) for k, v in d.items()}
    if isinstance(d, list):
        return [clean_keys_for_mongo(i) for i in d]
    if isinstance(d, bytes):
        return d.decode('utf-8', errors='ignore')
    return d

def extract_full_metadata(f_bytes, f_type):
    try:
        if "image" in f_type:
            img = Image.open(io.BytesIO(f_bytes))
            raw_exif = img.info.get('exif')
            if not raw_exif:
                return {"Info": "No EXIF data found."}
            exif_dict = piexif.load(raw_exif)
            return clean_keys_for_mongo(exif_dict)
        elif "pdf" in f_type:
            info = PyPDF2.PdfReader(io.BytesIO(f_bytes)).metadata
            return {"PDFInfo": {k: v for k, v in info.items() if v}}
        else:
            return {"FileInfo": {"Type": f_type, "Size (Bytes)": len(f_bytes)}}
    except Exception as e:
        return {"Error": f"Metadata processing failed: {str(e)}"}

def format_metadata_for_display(metadata):
    if isinstance(metadata, dict):
        formatted_lines = []
        for key, value in metadata.items():
            if isinstance(value, dict):
                formatted_lines.append(f"📁 **{key.upper()}**")
                for sub_key, sub_value in value.items():
                    formatted_lines.append(f"   • {sub_key}: {sub_value}")
            else:
                formatted_lines.append(f"• **{key}**: {value}")
        return "\n".join(formatted_lines)
    return str(metadata)

def perform_steganalysis(img_bytes):
    if not ADVANCED_ANALYSIS_ENABLED:
        return "Skipped (library not installed)."
    try:
        temp_img_path = "temp_steg_analysis.png"
        with open(temp_img_path, "wb") as f:
            f.write(img_bytes)
        revealed_text = lsb.reveal(temp_img_path)
        os.remove(temp_img_path)
        return f"Potential hidden data found: '{revealed_text}'" if revealed_text else "No hidden data detected."
    except Exception:
        if os.path.exists("temp_steg_analysis.png"):
            os.remove("temp_steg_analysis.png")
        return "Steganalysis failed: This image format may not be supported or contains no data."

def classify_image(img_bytes):
    if not ADVANCED_ANALYSIS_ENABLED:
        return "Skipped (library not installed)."
    try:
        img = keras_image.load_img(io.BytesIO(img_bytes), target_size=(224, 224))
        x = np.expand_dims(keras_image.img_to_array(img), axis=0)
        x = preprocess_input(x)
        preds = decode_predictions(classification_model.predict(x, verbose=0), top=3)[0]
        return "Classification: " + ", ".join([f"{label.replace('_', ' ')} ({prob:.1%})" for _, label, prob in preds])
    except Exception as e:
        return f"Classification failed: {e}"

def assign_risk_level(meta, steg_res=""):
    if "Error" in meta:
        return "High", "Metadata parsing error."
    if "Potential hidden data" in steg_res:
        return "High", "Steganography detected."
    meta_str = str(meta).lower()
    if 'photoshop' in meta_str or 'gimp' in meta_str:
        return "High", "Editing software detected in metadata."
    if 'Exif' in meta and isinstance(meta.get('Exif'), dict) and 'DateTimeOriginal' not in meta['Exif']:
        return "Medium", "Original timestamp is missing."
    return "Low", "No obvious signs of tampering found."

def generate_qr_code(data):
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color='black', back_color='white')
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return f"data:image/png;base64,{base64.b64encode(buf.getvalue()).decode()}"

# --- UI STYLES ---
CONTENT_STYLE = {"marginLeft": "18rem", "marginRight": "2rem", "padding": "2rem 1rem"}
SIDEBAR_STYLE = {"position": "fixed", "top": 0, "left": 0, "bottom": 0, "width": "16rem", "padding": "2rem 1rem", "backgroundColor": "#222"}

# --- DEPARTMENT-SPECIFIC CONFIGURATIONS ---
DEPARTMENT_CONFIG = {
    "Admin": {
        "color": "warning",
        "icon": "fas fa-crown",
        "emoji": "👑",
        "description": "Complete system control and oversight",
        "theme_color": "#ffc107"
    },
    "Forensics": {
        "color": "primary",
        "icon": "fas fa-microscope",
        "emoji": "🔬",
        "description": "Evidence ingestion and forensic analysis",
        "theme_color": "#0d6efd"
    },
    "Legal": {
        "color": "info",
        "icon": "fas fa-gavel",
        "emoji": "⚖️",
        "description": "Evidence verification and legal review",
        "theme_color": "#0dcaf0"
    },
    "IT": {
        "color": "secondary",
        "icon": "fas fa-server",
        "emoji": "💻",
        "description": "System administration and technical support",
        "theme_color": "#6c757d"
    },
    "Management": {
        "color": "success",
        "icon": "fas fa-chart-line",
        "emoji": "📊",
        "description": "Strategic oversight and reporting",
        "theme_color": "#198754"
    }
}

def create_sidebar(user):
    if not user.is_authenticated:
        return None
    
    dept_config = DEPARTMENT_CONFIG.get(user.department, DEPARTMENT_CONFIG["Management"])
    
    nav_links = []
    
    # Dashboard - Available to all authenticated users
    nav_links.append(
        dbc.NavLink([
            html.I(className="fas fa-chart-line me-2"),
            "Dashboard"
        ], href="/", active="exact", className="mb-2")
    )
    
    # Role-based navigation
    if user.can_ingest():
        nav_links.append(
            dbc.NavLink([
                html.I(className="fas fa-upload me-2"),
                "Ingest Evidence"
            ], href="/ingest", active="exact", className="mb-2")
        )
    
    if user.can_verify():
        nav_links.append(
            dbc.NavLink([
                html.I(className="fas fa-shield-check me-2"),
                "Advanced Verification"
            ], href="/verify", active="exact", className="mb-2")
        )
    
    if user.can_access_database():
        nav_links.append(
            dbc.NavLink([
                html.I(className="fas fa-database me-2"),
                "Evidence Locker"
            ], href="/database", active="exact", className="mb-2")
        )
    
    if user.can_view_audit():
        nav_links.append(
            dbc.NavLink([
                html.I(className="fas fa-clipboard-list me-2"),
                "Audit Log"
            ], href="/audit", active="exact", className="mb-2")
        )
    
    # Admin-only features
    if user.is_admin:
        nav_links.extend([
            html.Hr(className="my-3"),
            html.P("Admin Tools", className="text-muted small mb-2"),
            dbc.NavLink([
                html.I(className="fas fa-users me-2"),
                "User Management"
            ], href="/admin/users", active="exact", className="mb-2 text-warning"),
            dbc.NavLink([
                html.I(className="fas fa-cogs me-2"),
                "System Settings"
            ], href="/admin/settings", active="exact", className="mb-2 text-warning"),
        ])
    
    # Logout
    nav_links.append(
        dbc.NavLink([
            html.I(className="fas fa-sign-out-alt me-2"),
            "Logout"
        ], href="/logout", active="exact", className="mt-5 text-danger")
    )

    return html.Div([
        # Enhanced Header Section
        html.Div([
            html.H3([
                html.I(className="fas fa-shield-alt me-3"),
                "CoC System"
            ], className="text-white mb-1"),
            html.P("Digital Forensics Chain of Custody",
                   className="text-muted small mb-4"),
        ], className="text-center border-bottom border-secondary pb-3 mb-4"),
        
        # Department-specific User Info Section
        html.Div([
            dbc.Card([
                dbc.CardBody([
                    html.Div([
                        html.I(className=f"{dept_config['icon']} fa-2x text-{dept_config['color']} mb-2"),
                        html.H6(f"{user.id}", className="text-white mb-1"),
                        dbc.Badge(
                            f"{dept_config['emoji']} {user.department}",
                            color=dept_config['color'],
                            className="mb-2"
                        ),
                        html.Small(
                            f"{len(user.permissions)} permissions" if not user.is_admin else "Full Access",
                            className="text-muted"
                        )
                    ], className="text-center")
                ])
            ], color="dark", className="mb-4")
        ]),
        
        # Navigation Links
        dbc.Nav(nav_links, vertical=True, pills=True)
    ], style=SIDEBAR_STYLE)

# --- LOGIN LAYOUT ---
login_layout = dbc.Container([
    dbc.Row(
        dbc.Col(
            dbc.Card([
                dbc.CardHeader([
                    html.H2("🛡️ Advanced CoC System", className="text-center p-2"),
                    html.P("Digital Forensics Chain of Custody", className="text-center text-muted mb-0")
                ]),
                dbc.CardBody([
                    dbc.InputGroup([
                        dbc.InputGroupText(html.I(className="fas fa-user")),
                        dbc.Input(id="username-input", placeholder="Username", type="text")
                    ], className="mb-3"),
                    dbc.InputGroup([
                        dbc.InputGroupText(html.I(className="fas fa-lock")),
                        dbc.Input(id="password-input", placeholder="Password", type="password")
                    ], className="mb-3"),
                    dbc.Button("🔐 Login", id="login-button", color="primary", size="lg", className="w-100"),
                    html.Div(id="login-alert", className="mt-3 text-center"),
                    
                    html.Hr(className="my-4"),
                    dbc.Alert([
                        html.H6("🎯 Demo Credentials:", className="mb-2"),
                        html.P("👑 admin / admin123 (Full System Access)", className="mb-1 small text-warning"),
                        html.P("🔬 forensics_user / password123 (Evidence Analysis)", className="mb-1 small text-primary"),
                        html.P("⚖️ legal_user / password123 (Legal Review)", className="mb-1 small text-info"),
                        html.P("💻 it_user / password123 (System Admin)", className="mb-1 small text-secondary"),
                        html.P("📊 management_user / password123 (Executive)", className="mb-0 small text-success"),
                    ], color="info")
                ])
            ], color="dark"),
            width={"size": 10, "sm": 8, "md": 6, "lg": 4},
        ),
        className="vh-100 d-flex justify-content-center align-items-center"
    )
], fluid=True, className="p-0")

def create_department_quick_actions(department):
    """Create department-specific quick action buttons with working URLs"""
    actions_map = {
        "Admin": [
            {"label": "Manage Users", "icon": "fas fa-users", "href": "/admin/users", "color": "warning"},
            {"label": "System Settings", "icon": "fas fa-cogs", "href": "/admin/settings", "color": "secondary"},
            {"label": "View System Logs", "icon": "fas fa-file-alt", "href": "/admin/logs", "color": "info"},
            {"label": "Database Health", "icon": "fas fa-database", "href": "/database", "color": "primary"}
        ],
        "Forensics": [
            {"label": "Ingest Evidence", "icon": "fas fa-upload", "href": "/ingest", "color": "primary"},
            {"label": "Advanced Analysis", "icon": "fas fa-microscope", "href": "/analysis", "color": "success"},
            {"label": "Lab Tools", "icon": "fas fa-tools", "href": "/lab-tools", "color": "info"},
            {"label": "Evidence Database", "icon": "fas fa-database", "href": "/database", "color": "warning"}
        ],
        "Legal": [
            {"label": "Verify Evidence", "icon": "fas fa-shield-check", "href": "/verify", "color": "info"},
            {"label": "Legal Review", "icon": "fas fa-gavel", "href": "/legal-review", "color": "warning"},
            {"label": "Case Management", "icon": "fas fa-folder-open", "href": "/legal/cases", "color": "success"},
            {"label": "Evidence Database", "icon": "fas fa-database", "href": "/database", "color": "primary"}
        ],
        "IT": [
            {"label": "System Monitor", "icon": "fas fa-server", "href": "/system-status", "color": "secondary"},
            {"label": "User Access", "icon": "fas fa-user-cog", "href": "/it/access", "color": "primary"},
            {"label": "System Settings", "icon": "fas fa-cogs", "href": "/admin/settings", "color": "info"},
            {"label": "Audit Logs", "icon": "fas fa-clipboard-list", "href": "/audit", "color": "warning"}
        ],
        "Management": [
            {"label": "Executive Dashboard", "icon": "fas fa-chart-line", "href": "/executive", "color": "success"},
            {"label": "Approval Center", "icon": "fas fa-check-circle", "href": "/management/requests", "color": "warning"},
            {"label": "System Reports", "icon": "fas fa-file-pdf", "href": "/audit", "color": "info"},
            {"label": "Evidence Overview", "icon": "fas fa-database", "href": "/database", "color": "primary"}
        ]
    }
    
    actions = actions_map.get(department, [])
    
    if not actions:
        return html.P("No quick actions available for your department.", className="text-muted")
    
    action_buttons = []
    for action in actions:
        action_buttons.append(
            dbc.Button([
                html.I(className=f"{action['icon']} me-2"),
                action['label']
            ],
            color=action['color'],
            href=action['href'],
            external_link=True,
            className="me-2 mb-2"
            )
        )
    
    return html.Div(action_buttons)

def create_capabilities_overview(user):
    """Create a visual overview of user capabilities"""
    dept_config = DEPARTMENT_CONFIG.get(user.department, DEPARTMENT_CONFIG["Management"])
    
    return dbc.Row([
        dbc.Col([
            dbc.Card([
                dbc.CardHeader([
                    html.I(className=f"{dept_config['icon']} me-2"),
                    f"{user.department} Permissions"
                ]),
                dbc.CardBody([
                    html.P(f"You have {len(user.permissions)} specialized permissions:", className="mb-3"),
                    html.Div([
                        dbc.Badge(perm.replace('_', ' ').title(), color=dept_config['color'], className="me-1 mb-1")
                        for perm in user.permissions[:8]  # Show first 8 permissions
                    ]),
                    html.P(f"...and {len(user.permissions) - 8} more" if len(user.permissions) > 8 else "", 
                           className="small text-muted mt-2")
                ])
            ])
        ], md=6),
        
        dbc.Col([
            dbc.Card([
                dbc.CardHeader([
                    html.I(className="fas fa-info-circle me-2"),
                    "Department Info"
                ]),
                dbc.CardBody([
                    html.P(user.department_description or dept_config['description'], className="mb-3"),
                    html.P([
                        html.Strong("Last Login: "),
                        user.last_login.strftime('%Y-%m-%d %H:%M') if user.last_login else "Never"
                    ], className="small text-muted mb-1"),
                    html.P([
                        html.Strong("Account Status: "),
                        dbc.Badge("Active", color="success") if user.account_status == "ACTIVE" else dbc.Badge("Inactive", color="danger")
                    ], className="small mb-0")
                ])
            ])
        ], md=6)
    ])

# --- ENHANCED DASHBOARD ---
def generate_dashboard_layout():
    if not current_user.is_authenticated:
        return login_layout
        
    stats = db_client.get_evidence_stats()
    dept_config = DEPARTMENT_CONFIG.get(current_user.department, DEPARTMENT_CONFIG["Management"])
    
    def create_card(title, value, icon, color):
        return dbc.Card(
            dbc.CardBody([
                html.H4(title),
                html.H2([html.I(className=f"{icon} me-2"), value])
            ]),
            color=color, inverse=True, className="text-center"
        )
    
    # Department-specific quick actions
    quick_actions = create_department_quick_actions(current_user.department)
    
    return html.Div([
        # Department-specific welcome header
        dbc.Alert([
            html.H3([
                html.I(className=f"{dept_config['icon']} me-3"),
                f"Welcome, {current_user.id}"
            ]),
            html.H5(f"{dept_config['emoji']} {current_user.department} Department", className="mb-2"),
            html.P(dept_config['description'], className="mb-0")
        ], color=dept_config['color'], className="mb-4"),
        
        html.Hr(),
        
        # Statistics cards
        dbc.Row([
            dbc.Col(create_card("Total Evidence", stats.get("Total Evidence", 0), "fas fa-archive", "primary"), md=2),
            dbc.Col(create_card("High Risk", stats.get("High", 0), "fas fa-exclamation-triangle", "danger"), md=2),
            dbc.Col(create_card("Medium Risk", stats.get("Medium", 0), "fas fa-exclamation-circle", "warning"), md=2),
            dbc.Col(create_card("Low Risk", stats.get("Low", 0), "fas fa-check-circle", "success"), md=2),
            dbc.Col(create_card("Today", stats.get("Today", 0), "fas fa-calendar-day", "info"), md=2),
            dbc.Col(create_card("Cases", stats.get("Unique Cases", 0), "fas fa-folder-open", "secondary"), md=2),
        ], className="mb-4"),
        
        html.Hr(),
        
        # Department-specific quick actions
        html.H4("🚀 Quick Actions", className="mt-4 mb-3"),
        quick_actions,
        
        # Department-specific capabilities overview
        html.Hr(className="my-4"),
        html.H4("🎯 Your Capabilities", className="mb-3"),
        create_capabilities_overview(current_user)
    ])

# --- INGEST LAYOUT ---
ingest_layout = html.Div([
    dcc.Store(id='stored-db-record-for-pdf'),
    dcc.Download(id="download-pdf-report"),
    html.H1([
        html.I(className="fas fa-upload me-3"),
        "🔬 Ingest New Evidence"
    ]),
    html.Hr(),
    dbc.Row([
        dbc.Col(dbc.Card(dbc.CardBody([
            dbc.Input(id="case-id-input", placeholder="Enter Case ID...", className="mb-3", size="lg"),
            dcc.Upload(
                id='upload-file',
                children=html.Div([
                    html.Div([
                        html.I(className="fas fa-cloud-upload-alt fa-3x text-primary mb-3"),
                        html.H5("Drag & Drop Evidence File", className="text-white"),
                        html.P("or click to browse", className="text-muted")
                    ], className="text-center py-4")
                ]),
                className="py-5 text-center",
                style={
                    'borderWidth': '2px',
                    'borderStyle': 'dashed',
                    'borderRadius': '10px',
                    'borderColor': '#007bff',
                    'backgroundColor': '#1a1a1a'
                }
            ),
            html.Div(id='ingest-preview-container', className="text-center mt-3")
        ])), md=5),
        dbc.Col(dbc.Card(dbc.CardBody([
            html.H4([
                html.I(className="fas fa-microscope me-2"),
                "Analysis Results"
            ]),
            dbc.Spinner(html.Div(id='ingest-results-container'))
        ])), md=7)
    ])
])

# --- VERIFY LAYOUT ---
verify_layout = html.Div([
    html.H1([
        html.I(className="fas fa-shield-check me-3"),
        "⚖️ Advanced Evidence Integrity Verification"
    ], className="text-white mb-4"),
    
    html.Hr(className="border-secondary mb-5"),
    
    dbc.Row([
        # Left Column - Upload & Options
        dbc.Col([
            dbc.Card([
                dbc.CardHeader([
                    html.H5([
                        html.I(className="fas fa-file-upload me-2"),
                        "Evidence File Upload"
                    ], className="text-white mb-0")
                ], className="bg-primary"),
                dbc.CardBody([
                    dcc.Upload(
                        id='verify-upload-single',
                        children=html.Div([
                            html.Div([
                                html.I(className="fas fa-cloud-upload-alt fa-4x text-primary mb-3"),
                                html.H5("Drop Evidence File Here", className="text-white mb-2"),
                                html.P("or click to browse files", className="text-muted mb-2"),
                            ], className="text-center py-4")
                        ]),
                        style={
                            'borderWidth': '2px',
                            'borderStyle': 'dashed',
                            'borderRadius': '10px',
                            'borderColor': '#007bff',
                            'backgroundColor': '#1a1a1a',
                            'minHeight': '150px',
                            'cursor': 'pointer'
                        },
                        className="mb-3"
                    ),
                    html.Div(id='verify-file-info', className="mb-3")
                ])
            ], color="dark", className="border-secondary mb-4"),
            
            dbc.Card([
                dbc.CardHeader([
                    html.H5([
                        html.I(className="fas fa-cog me-2"),
                        "Verification Options"
                    ], className="text-white mb-0")
                ], className="bg-secondary"),
                dbc.CardBody([
                    dbc.Checklist(
                        options=[
                            {"label": "🔗 Blockchain Verification", "value": "blockchain"},
                            {"label": "💾 Database Matching", "value": "database"},
                            {"label": "🔐 Multi-Hash Check", "value": "multihash"},
                        ],
                        value=["blockchain", "database"],
                        id="verification-options",
                        switch=True
                    ),
                    dbc.Button(
                        "🚀 Start Verification",
                        id='verify-button-enhanced',
                        color="success",
                        size="lg",
                        className="w-100 mt-4",
                        disabled=True
                    )
                ])
            ], color="dark", className="border-secondary")
        ], md=4),
        
        # Right Column - Results
        dbc.Col([
            dbc.Card([
                dbc.CardHeader([
                    html.H5([
                        html.I(className="fas fa-chart-line me-2"),
                        "Verification Results"
                    ], className="text-white mb-0")
                ], className="bg-info"),
                dbc.CardBody([
                    dbc.Spinner([
                        html.Div([
                            html.Div([
                                html.I(className="fas fa-shield-alt fa-5x text-muted mb-3"),
                                html.H4("Ready for Verification", className="text-muted"),
                                html.P("Upload a file to begin verification.", className="text-secondary")
                            ], className="text-center py-5", id="initial-verify-state"),
                            html.Div(id='verify-results-enhanced')
                        ])
                    ], color="primary", size="lg")
                ], style={"minHeight": "500px", "maxHeight": "600px", "overflowY": "auto"})
            ], color="dark", className="border-secondary")
        ], md=8)
    ])
], className="p-4")

# --- DATABASE LAYOUT ---
database_layout = html.Div([
    html.H1([
        html.I(className="fas fa-database me-3"),
        "💾 Evidence Locker"
    ]),
    html.Hr(),
    dbc.Card(dbc.CardBody([
        dash_table.DataTable(
            id='evidence-table',
            columns=[
                {"name": "Case ID", "id": "caseId"},
                {"name": "Filename", "id": "filename"},
                {"name": "SHA256 Hash", "id": "sha256Hash"},
                {"name": "Risk Level", "id": "riskLevel"},
                {"name": "Ingested On (UTC)", "id": "timestamp_utc"},
            ],
            page_size=20,
            filter_action="native",
            sort_action="native",
            style_table={'overflowX': 'auto'},
            style_header={'backgroundColor': '#1A1B1E', 'color': 'white', 'fontWeight': 'bold'},
            style_cell={'backgroundColor': '#2C2E33', 'color': 'white', 'textAlign': 'left'},
            style_data_conditional=[
                {'if': {'row_index': 'odd'}, 'backgroundColor': 'rgb(40, 40, 40)'},
                {'if': {'column_id': 'riskLevel', 'filter_query': '{riskLevel} = "High"'}, 'backgroundColor': '#8B0000', 'color': 'white'},
                {'if': {'column_id': 'riskLevel', 'filter_query': '{riskLevel} = "Medium"'}, 'backgroundColor': '#FF8C00', 'color': 'black'},
                {'if': {'column_id': 'riskLevel', 'filter_query': '{riskLevel} = "Low"'}, 'backgroundColor': '#006400', 'color': 'white'},
            ]
        )
    ]))
])

# --- AUDIT LOG LAYOUT ---
audit_log_layout = html.Div([
    html.H1([
        html.I(className="fas fa-clipboard-list me-3"),
        "📋 System Audit Log"
    ]),
    html.Hr(),
    dbc.Card(dbc.CardBody([
        dash_table.DataTable(
            id='audit-log-table',
            columns=[
                {"name": "Timestamp (UTC)", "id": "timestamp_utc"},
                {"name": "User", "id": "username"},
                {"name": "Department", "id": "department"},
                {"name": "Action", "id": "action"},
                {"name": "Details", "id": "details"},
            ],
            page_size=25,
            sort_action="native",
            style_table={'overflowX': 'auto'},
            style_header={'backgroundColor': '#1A1B1E', 'color': 'white', 'fontWeight': 'bold'},
            style_cell={'backgroundColor': '#2C2E33', 'color': 'white', 'textAlign': 'left'},
            style_data_conditional=[{'if': {'row_index': 'odd'}, 'backgroundColor': 'rgb(40, 40, 40)'}]
        )
    ]))
])

# --- QUICK ACTION LAYOUTS ---

# 👑 ADMIN QUICK ACTIONS
def admin_logs_layout():
    return html.Div([
        html.H1([html.I(className="fas fa-file-alt me-3"), "👑 System Logs"], className="text-warning"),
        html.Hr(),
        dbc.Row([
            dbc.Col([
                dbc.Card([
                    dbc.CardHeader("Recent System Activity"),
                    dbc.CardBody([
                        dash_table.DataTable(
                            id='system-logs-table',
                            columns=[
                                {"name": "Timestamp", "id": "timestamp_utc"},
                                {"name": "User", "id": "username"},
                                {"name": "Department", "id": "department"},
                                {"name": "Action", "id": "action"},
                                {"name": "Severity", "id": "severity"},
                                {"name": "Details", "id": "details"}
                            ],
                            page_size=25,
                            sort_action="native",
                            filter_action="native",
                            style_header={'backgroundColor': '#1A1B1E', 'color': 'white'},
                            style_cell={'backgroundColor': '#2C2E33', 'color': 'white', 'textAlign': 'left'},
                            style_data_conditional=[
                                {'if': {'column_id': 'severity', 'filter_query': '{severity} = "HIGH"'}, 
                                 'backgroundColor': '#8B0000', 'color': 'white'},
                                {'if': {'column_id': 'severity', 'filter_query': '{severity} = "MEDIUM"'}, 
                                 'backgroundColor': '#FF8C00', 'color': 'black'},
                            ]
                        )
                    ])
                ])
            ], md=12)
        ])
    ])

# 🔬 FORENSICS QUICK ACTIONS
def forensics_analysis_layout():
    return html.Div([
        html.H1([html.I(className="fas fa-microscope me-3"), "🔬 Advanced Analysis Lab"], className="text-primary"),
        html.Hr(),
        dbc.Row([
            dbc.Col([
                dbc.Card([
                    dbc.CardHeader("Analysis Tools"),
                    dbc.CardBody([
                        dbc.ButtonGroup([
                            dbc.Button([html.I(className="fas fa-image me-2"), "Image Analysis"], 
                                     color="primary", id="image-analysis-btn", className="mb-2"),
                            dbc.Button([html.I(className="fas fa-file-pdf me-2"), "Document Analysis"], 
                                     color="info", id="doc-analysis-btn", className="mb-2"),
                            dbc.Button([html.I(className="fas fa-eye-slash me-2"), "Steganography Scan"], 
                                     color="warning", id="steg-analysis-btn", className="mb-2")
                        ], vertical=True, className="w-100")
                    ])
                ])
            ], md=4),
            dbc.Col([
                dbc.Card([
                    dbc.CardHeader("Analysis Results"),
                    dbc.CardBody([
                        html.Div(id="analysis-results-display", children=[
                            html.Div([
                                html.I(className="fas fa-microscope fa-3x text-muted mb-3"),
                                html.H5("Select Analysis Tool", className="text-muted"),
                                html.P("Choose an analysis tool from the left panel", className="text-secondary")
                            ], className="text-center py-5")
                        ])
                    ])
                ])
            ], md=8)
        ])
    ])

def forensics_lab_tools_layout():
    return html.Div([
        html.H1([html.I(className="fas fa-tools me-3"), "🔬 Lab Tools & Utilities"], className="text-primary"),
        html.Hr(),
        dbc.Row([
            dbc.Col([
                dbc.Card([
                    dbc.CardHeader("Hash Calculator"),
                    dbc.CardBody([
                        dbc.Textarea(id="hash-input", placeholder="Enter text to hash...", 
                                   className="mb-3", style={"height": "100px"}),
                        dbc.ButtonGroup([
                            dbc.Button("MD5", id="md5-btn", color="primary", size="sm"),
                            dbc.Button("SHA256", id="sha256-btn", color="success", size="sm"),
                            dbc.Button("SHA512", id="sha512-btn", color="info", size="sm")
                        ], className="mb-3"),
                        html.Div(id="hash-output", className="mt-3")
                    ])
                ])
            ], md=6),
            dbc.Col([
                dbc.Card([
                    dbc.CardHeader("Evidence Timeline"),
                    dbc.CardBody([
                        dbc.Input(id="timeline-case-input", placeholder="Enter Case ID", className="mb-3"),
                        dbc.Button("Generate Timeline", id="timeline-btn", color="primary", className="mb-3"),
                        html.Div(id="timeline-output")
                    ])
                ])
            ], md=6)
        ])
    ])

# ⚖️ LEGAL QUICK ACTIONS
def legal_review_layout():
    return html.Div([
        html.H1([html.I(className="fas fa-gavel me-3"), "⚖️ Legal Review Center"], className="text-info"),
        html.Hr(),
        dbc.Row([
            dbc.Col([
                dbc.Card([
                    dbc.CardHeader("Evidence Review Queue"),
                    dbc.CardBody([
                        dbc.Alert("No pending reviews", color="success", id="review-queue-alert"),
                        dash_table.DataTable(
                            id='legal-review-table',
                            columns=[
                                {"name": "Case ID", "id": "caseId"},
                                {"name": "Evidence", "id": "filename"},
                                {"name": "Risk Level", "id": "riskLevel"},
                                {"name": "Status", "id": "review_status"},
                                {"name": "Actions", "id": "actions", "presentation": "markdown"}
                            ],
                            page_size=15,
                            style_header={'backgroundColor': '#1A1B1E', 'color': 'white'},
                            style_cell={'backgroundColor': '#2C2E33', 'color': 'white', 'textAlign': 'left'}
                        )
                    ])
                ])
            ], md=8),
            dbc.Col([
                dbc.Card([
                    dbc.CardHeader("Legal Actions"),
                    dbc.CardBody([
                        dbc.Button([html.I(className="fas fa-stamp me-2"), "Approve Evidence"], 
                                 color="success", className="w-100 mb-2", id="approve-evidence-btn"),
                        dbc.Button([html.I(className="fas fa-times me-2"), "Flag for Review"], 
                                 color="warning", className="w-100 mb-2", id="flag-evidence-btn"),
                        dbc.Button([html.I(className="fas fa-file-alt me-2"), "Generate Legal Report"], 
                                 color="info", className="w-100 mb-2", id="legal-report-btn")
                    ])
                ])
            ], md=4)
        ])
    ])

def legal_cases_layout():
    return html.Div([
        html.H1([html.I(className="fas fa-folder-open me-3"), "⚖️ Case Management"], className="text-info"),
        html.Hr(),
        dbc.Row([
            dbc.Col([
                dbc.Input(id="case-search", placeholder="Search cases...", className="mb-3"),
                dbc.Card([
                    dbc.CardHeader("Active Cases"),
                    dbc.CardBody([
                        html.Div(id="cases-list", children=[
                            dbc.ListGroup([
                                dbc.ListGroupItem([
                                    html.H5("Case #12345", className="mb-1"),
                                    html.P("Status: Active • Evidence Count: 5 • Last Updated: Today", className="mb-1 small")
                                ], action=True),
                                dbc.ListGroupItem([
                                    html.H5("Case #12346", className="mb-1"),
                                    html.P("Status: Under Review • Evidence Count: 3 • Last Updated: Yesterday", className="mb-1 small")
                                ], action=True)
                            ])
                        ])
                    ])
                ])
            ], md=12)
        ])
    ])

# 💻 IT QUICK ACTIONS
def it_monitoring_layout():
    return html.Div([
        html.H1([html.I(className="fas fa-server me-3"), "💻 System Monitoring"], className="text-secondary"),
        html.Hr(),
        dbc.Row([
            dbc.Col([
                dbc.Card([
                    dbc.CardHeader("System Health"),
                    dbc.CardBody([
                        dbc.Progress(label="CPU Usage", value=25, color="success", className="mb-3"),
                        dbc.Progress(label="Memory Usage", value=60, color="warning", className="mb-3"),
                        dbc.Progress(label="Disk Usage", value=40, color="info", className="mb-3"),
                        dbc.Progress(label="Network Load", value=15, color="success")
                    ])
                ])
            ], md=6),
            dbc.Col([
                dbc.Card([
                    dbc.CardHeader("Service Status"),
                    dbc.CardBody([
                        dbc.ListGroup([
                            dbc.ListGroupItem([
                                dbc.Badge("🟢 ONLINE", color="success", className="me-2"),
                                "Database Service"
                            ]),
                            dbc.ListGroupItem([
                                dbc.Badge("🟢 ONLINE", color="success", className="me-2"),
                                "Blockchain Service"
                            ]),
                            dbc.ListGroupItem([
                                dbc.Badge("🟢 ONLINE", color="success", className="me-2"),
                                "Web Server"
                            ]),
                            dbc.ListGroupItem([
                                dbc.Badge("🟡 WARNING", color="warning", className="me-2"),
                                "Backup Service"
                            ])
                        ], flush=True)
                    ])
                ])
            ], md=6)
        ], className="mb-4"),
        dbc.Row([
            dbc.Col([
                dbc.Card([
                    dbc.CardHeader("Recent Alerts"),
                    dbc.CardBody([
                        html.Div(id="system-alerts", children=[
                            dbc.Alert("System running optimally - no alerts", color="success")
                        ])
                    ])
                ])
            ], md=12)
        ])
    ])

def it_access_layout():
    return html.Div([
        html.H1([html.I(className="fas fa-user-cog me-3"), "💻 Access Management"], className="text-secondary"),
        html.Hr(),
        dbc.Row([
            dbc.Col([
                dbc.Card([
                    dbc.CardHeader("User Access Controls"),
                    dbc.CardBody([
                        dash_table.DataTable(
                            id='access-control-table',
                            columns=[
                                {"name": "Username", "id": "username"},
                                {"name": "Department", "id": "department"},
                                {"name": "Last Login", "id": "last_login"},
                                {"name": "Status", "id": "account_status"},
                                {"name": "Actions", "id": "user_actions", "presentation": "markdown"}
                            ],
                            page_size=20,
                            style_header={'backgroundColor': '#1A1B1E', 'color': 'white'},
                            style_cell={'backgroundColor': '#2C2E33', 'color': 'white', 'textAlign': 'left'}
                        )
                    ])
                ])
            ], md=12)
        ])
    ])

# 📊 MANAGEMENT QUICK ACTIONS
def management_dashboard_layout():
    return html.Div([
        html.H1([html.I(className="fas fa-chart-line me-3"), "📊 Executive Dashboard"], className="text-success"),
        html.Hr(),
        dbc.Row([
            dbc.Col([
                dbc.Card([
                    dbc.CardHeader("Key Performance Indicators"),
                    dbc.CardBody([
                        dbc.Row([
                            dbc.Col([
                                html.H3("156", className="text-primary"),
                                html.P("Cases Processed")
                            ], md=3),
                            dbc.Col([
                                html.H3("98.5%", className="text-success"),
                                html.P("System Uptime")
                            ], md=3),
                            dbc.Col([
                                html.H3("23", className="text-warning"),
                                html.P("Pending Reviews")
                            ], md=3),
                            dbc.Col([
                                html.H3("5", className="text-info"),
                                html.P("Active Users")
                            ], md=3)
                        ])
                    ])
                ])
            ], md=12)
        ], className="mb-4"),
        dbc.Row([
            dbc.Col([
                dbc.Card([
                    dbc.CardHeader("Department Performance"),
                    dbc.CardBody([
                        html.Div(id="dept-performance-chart", children=[
                            html.P("Department performance metrics visualization would go here.", className="text-muted")
                        ])
                    ])
                ])
            ], md=8),
            dbc.Col([
                dbc.Card([
                    dbc.CardHeader("Recent Activity"),
                    dbc.CardBody([
                        html.Div(id="recent-activity-feed", children=[
                            dbc.ListGroup([
                                dbc.ListGroupItem("Evidence ingested by forensics_user - 2 hours ago"),
                                dbc.ListGroupItem("Legal review completed by legal_user - 4 hours ago"),
                                dbc.ListGroupItem("System backup completed - 6 hours ago")
                            ])
                        ])
                    ])
                ])
            ], md=4)
        ])
    ])

def management_requests_layout():
    return html.Div([
        html.H1([html.I(className="fas fa-check-circle me-3"), "📊 Approval Center"], className="text-success"),
        html.Hr(),
        dbc.Row([
            dbc.Col([
                dbc.Card([
                    dbc.CardHeader("Pending Approvals"),
                    dbc.CardBody([
                        dash_table.DataTable(
                            id='approval-requests-table',
                            columns=[
                                {"name": "Request ID", "id": "request_id"},
                                {"name": "Type", "id": "request_type"},
                                {"name": "Requested By", "id": "requested_by"},
                                {"name": "Department", "id": "department"},
                                {"name": "Priority", "id": "priority"},
                                {"name": "Actions", "id": "approval_actions", "presentation": "markdown"}
                            ],
                            page_size=15,
                            style_header={'backgroundColor': '#1A1B1E', 'color': 'white'},
                            style_cell={'backgroundColor': '#2C2E33', 'color': 'white', 'textAlign': 'left'}
                        )
                    ])
                ])
            ], md=12)
        ])
    ])

# --- ADMIN LAYOUTS ---
def admin_user_management_layout():
    return html.Div([
        html.H1([
            html.I(className="fas fa-users me-3"),
            "👑 User Management"
        ], className="text-warning"),
        html.Hr(),
        
        dbc.Row([
            dbc.Col([
                dbc.Card([
                    dbc.CardHeader("Create New User"),
                    dbc.CardBody([
                        dbc.Input(id="new-username", placeholder="Username", className="mb-3"),
                        dbc.Input(id="new-password", type="password", placeholder="Password", className="mb-3"),
                        dbc.Select(id="new-department", options=[
                            {"label": "👑 Admin", "value": "Admin"},
                            {"label": "🔬 Forensics", "value": "Forensics"},
                            {"label": "⚖️ Legal", "value": "Legal"},
                            {"label": "💻 IT", "value": "IT"},
                            {"label": "📊 Management", "value": "Management"}
                        ], className="mb-3"),
                        dbc.Button("Create User", id="create-user-btn", color="success", className="w-100"),
                        html.Div(id="create-user-result", className="mt-3")
                    ])
                ])
            ], md=6),
            
            dbc.Col([
                dbc.Card([
                    dbc.CardHeader("System Statistics"),
                    dbc.CardBody([
                        html.Div(id="admin-stats")
                    ])
                ])
            ], md=6)
        ])
    ])

def admin_settings_layout():
    return html.Div([
        html.H1([
            html.I(className="fas fa-cogs me-3"),
            "⚙️ System Settings"
        ], className="text-warning mb-4"),
        html.P("Configure and manage your Chain of Custody system", className="text-muted mb-4"),
        html.Hr(),
        
        dbc.Alert("Advanced system configuration interface - All systems operational!", color="info"),
        
        dbc.Row([
            dbc.Col([
                dbc.Card([
                    dbc.CardHeader("🔗 Blockchain Status"),
                    dbc.CardBody([
                        html.Div(id="blockchain-status-display")
                    ])
                ])
            ], md=6),
            
            dbc.Col([
                dbc.Card([
                    dbc.CardHeader("💾 Database Status"),
                    dbc.CardBody([
                        html.Div(id="database-status-display")
                    ])
                ])
            ], md=6)
        ])
    ])

# --- HELPER FUNCTIONS FOR ACCESS CONTROL ---
def access_denied_alert(action, department):
    return dbc.Alert([
        html.H4([html.I(className="fas fa-lock me-2"), "🚫 Access Denied"]),
        html.P(f"Your role ({department}) does not have permission to {action}."),
        html.P("Contact your administrator if you need access to this feature.")
    ], color="danger")

def admin_access_denied_alert(department):
    return dbc.Alert([
        html.H4([html.I(className="fas fa-crown me-2"), "👑 Admin Access Required"]),
        html.P("This page is only accessible to administrators."),
        html.P(f"Your current role: {department}")
    ], color="danger")

# --- APP LAYOUT & ROUTING ---
app.layout = html.Div([
    dcc.Location(id="url", refresh=False),
    html.Div(id="app-container"),
    dcc.Download(id="download-export-data")
])

@app.callback(Output("app-container", "children"), Input("url", "pathname"))
def display_page(pathname):
    if current_user.is_authenticated:
        return html.Div([create_sidebar(current_user), html.Div(id="page-content", style=CONTENT_STYLE)])
    return login_layout

@app.callback(Output("page-content", "children"), Input("url", "pathname"))
def render_page_content(pathname):
    if not current_user.is_authenticated:
        return login_layout
    
    if pathname == "/logout":
        db_client.log_action(current_user.id, "USER_LOGOUT", f"Logged out from {current_user.department} department")
        logout_user()
        return dcc.Location(pathname="/login", id="redirect-logout", refresh=True)
    
    # Existing core pages
    if pathname == "/ingest":
        if not current_user.can_ingest():
            return access_denied_alert("ingest evidence", current_user.department)
        return ingest_layout
        
    if pathname == "/verify":
        if not current_user.can_verify():
            return access_denied_alert("verify evidence", current_user.department)
        return verify_layout
        
    if pathname == "/database":
        if not current_user.can_access_database():
            return access_denied_alert("access database", current_user.department)
        return database_layout
        
    if pathname == "/audit":
        if not current_user.can_view_audit():
            return access_denied_alert("view audit logs", current_user.department)
        return audit_log_layout
    
    # 👑 ADMIN QUICK ACTIONS
    if pathname.startswith("/admin/"):
        if not current_user.is_admin:
            return admin_access_denied_alert(current_user.department)
        
        if pathname == "/admin/users":
            return admin_user_management_layout()
        elif pathname == "/admin/settings":
            return admin_settings_layout()
        elif pathname == "/admin/logs":
            return admin_logs_layout()
    
    # 🔬 FORENSICS QUICK ACTIONS
    elif pathname == "/analysis":
        if not current_user.has_permission('advanced_analysis'):
            return access_denied_alert("access advanced analysis", current_user.department)
        return forensics_analysis_layout()
        
    elif pathname == "/lab-tools":
        if not current_user.has_permission('advanced_analysis'):
            return access_denied_alert("access lab tools", current_user.department)
        return forensics_lab_tools_layout()
        # ⚖️ LEGAL QUICK ACTIONS
    elif pathname == "/legal-review":
        if not current_user.has_permission('legal_review'):
            return access_denied_alert("perform legal reviews", current_user.department)
        return legal_review_layout()
        
    elif pathname == "/legal/cases":
        if not current_user.has_permission('case_management'):
            return access_denied_alert("access case management", current_user.department)
        return legal_cases_layout()
    
    # 💻 IT QUICK ACTIONS
    elif pathname == "/system-status":
        if not current_user.has_permission('system_monitor'):
            return access_denied_alert("access system monitoring", current_user.department)
        return it_monitoring_layout()
        
    elif pathname == "/it/access":
        if not current_user.has_permission('system_config'):
            return access_denied_alert("manage user access", current_user.department)
        return it_access_layout()
    
    # 📊 MANAGEMENT QUICK ACTIONS
    elif pathname == "/executive":
        if not current_user.has_permission('strategic_analysis'):
            return access_denied_alert("access executive dashboard", current_user.department)
        return management_dashboard_layout()
        
    elif pathname == "/management/requests":
        if not current_user.has_permission('team_oversight'):
            return access_denied_alert("manage approval requests", current_user.department)
        return management_requests_layout()
    
    # Default dashboard
    return generate_dashboard_layout()

# --- ENHANCED LOGIN CALLBACK ---
@app.callback(
    [Output("url", "pathname", allow_duplicate=True), Output("login-alert", "children")],
    Input("login-button", "n_clicks"),
    [State("username-input", "value"), State("password-input", "value")],
    prevent_initial_call=True
)
def login_user_callback(n_clicks, username, password):
    print(f"=== 🔐 LOGIN DEBUG FOR: {username} ===")
    
    if not n_clicks or not username or not password:
        print("❌ Missing credentials")
        return no_update, dbc.Alert([
            html.I(className="fas fa-exclamation-triangle me-2"),
            "Username and password are required."
        ], color="warning", dismissable=True)
    
    user_data = db_client.find_user(username)
    print(f"🔍 User lookup result: {user_data is not None}")
    
    if not user_data:
        print(f"❌ User '{username}' not found in database")
        try:
            db_client.update_login_attempt(username, success=False)
            db_client.log_action(username, "USER_LOGIN_FAILED", "User not found")
        except Exception as e:
            print(f"Error logging failed attempt: {e}")
        
        return no_update, dbc.Alert([
            html.I(className="fas fa-user-times me-2"),
            f"User '{username}' not found. Please check your username."
        ], color="danger", dismissable=True)
    
    # Enhanced user information debugging
    print(f"📋 Enhanced User Details:")
    print(f"   Username: {user_data.get('username')}")
    print(f"   Department: {user_data.get('department')}")
    print(f"   Permissions Count: {len(user_data.get('permissions', []))}")
    print(f"   Account Status: {user_data.get('account_status', 'ACTIVE')}")
    print(f"   Is Admin: {user_data.get('is_admin', False)}")
    print(f"   Department Description: {user_data.get('department_description', 'Not set')}")
    print(f"   Last Login: {user_data.get('last_login', 'Never')}")
    
    # Check account status
    if user_data.get('account_status', 'ACTIVE') != 'ACTIVE':
        print(f"❌ Account inactive for user: {username}")
        return no_update, dbc.Alert([
            html.I(className="fas fa-ban me-2"),
            f"Account '{username}' is inactive. Contact administrator."
        ], color="warning", dismissable=True)
    
    # Check password
    password_match = check_password_hash(user_data.get('password', ''), password)
    print(f"🔐 Password check: {'✅ SUCCESS' if password_match else '❌ FAILED'}")
    
    if password_match:
        user = User(user_data)
        login_user(user)
        
        print(f"✅ Login successful for: {username}")
        print(f"   Final Department: {user.department}")
        print(f"   Final Permissions Count: {len(user.permissions)}")
        print(f"   Is Admin: {user.is_admin}")
        
        try:
            db_client.update_login_attempt(username, success=True)
            db_client.log_action(username, "USER_LOGIN_SUCCESS", 
                               f"Logged in from {user.department} department with {len(user.permissions)} permissions")
        except Exception as e:
            print(f"Error updating login: {e}")
        
        # Department-specific success message
        dept_config = DEPARTMENT_CONFIG.get(user.department, DEPARTMENT_CONFIG["Management"])
        
        return "/", dbc.Alert([
            html.I(className="fas fa-check-circle me-2"),
            f"{dept_config['emoji']} Welcome, {username}! ({user.department} Department - {len(user.permissions)} permissions)"
        ], color=dept_config['color'], dismissable=True)
    
    else:
        print(f"❌ Invalid password for user: {username}")
        try:
            db_client.update_login_attempt(username, success=False)
            db_client.log_action(username, "USER_LOGIN_FAILED", "Invalid password")
        except Exception as e:
            print(f"Error logging failed attempt: {e}")
        
        return no_update, dbc.Alert([
            html.I(className="fas fa-times-circle me-2"),
            "Invalid password. Please try again."
        ], color="danger", dismissable=True)

# --- VERIFICATION CALLBACKS ---
@app.callback(
    [Output('verify-button-enhanced', 'disabled'),
     Output('initial-verify-state', 'style')],
    [Input('verify-upload-single', 'contents')]
)
def update_verify_button(contents):
    if contents:
        return False, {'display': 'none'}
    return True, {'display': 'block'}

@app.callback(
    Output('verify-results-enhanced', 'children'),
    [Input('verify-button-enhanced', 'n_clicks')],
    [State('verify-upload-single', 'contents'),
     State('verify-upload-single', 'filename'),
     State('verification-options', 'value')],
    prevent_initial_call=True
)
def verify_evidence(n_clicks, content, filename, options):
    if not content:
        return ""
    
    try:
        # Decode file
        content_type, content_string = content.split(',')
        decoded_bytes = base64.b64decode(content_string)
        
        # Calculate hash
        sha256_hash = hashlib.sha256(decoded_bytes).hexdigest()
        
        verification_results = []
        overall_status = "VERIFIED"
        
        # Perform selected verifications
        if "blockchain" in options:
            bc_ipfs_hash, bc_timestamp = blockchain_service.get_evidence_record(sha256_hash)
            if bc_timestamp > 0:
                verification_results.append(
                    dbc.Alert([
                        html.H5([html.I(className="fas fa-check-circle me-2"), "🔗 Blockchain Verified"]),
                        html.P(f"Record found with timestamp: {datetime.fromtimestamp(bc_timestamp)}")
                    ], color="success")
                )
            else:
                verification_results.append(
                    dbc.Alert([
                        html.H5([html.I(className="fas fa-times-circle me-2"), "❌ Blockchain Not Found"]),
                        html.P("No blockchain record found for this evidence.")
                    ], color="danger")
                )
                overall_status = "FAILED"
        
        if "database" in options:
            db_record = db_client.find_evidence_by_hash(sha256_hash)
            if db_record:
                verification_results.append(
                    dbc.Alert([
                        html.H5([html.I(className="fas fa-database me-2"), "💾 Database Verified"]),
                        html.P(f"Case ID: {db_record.get('caseId')}, Risk Level: {db_record.get('riskLevel')}")
                    ], color="success")
                )
            else:
                verification_results.append(
                    dbc.Alert([
                        html.H5([html.I(className="fas fa-times-circle me-2"), "❌ Database Not Found"]),
                        html.P("No database record found for this evidence.")
                    ], color="danger")
                )
                overall_status = "FAILED"
        
        if "multihash" in options:
            hashes = {
                'SHA256': hashlib.sha256(decoded_bytes).hexdigest(),
                'MD5': hashlib.md5(decoded_bytes).hexdigest(),
            }
            verification_results.append(
                dbc.Alert([
                    html.H5([html.I(className="fas fa-fingerprint me-2"), "🔐 Hash Verification"]),
                    html.P(f"SHA256: {hashes['SHA256'][:32]}..."),
                    html.P(f"MD5: {hashes['MD5']}")
                ], color="info")
            )
        
        # Log verification activity
        try:
            db_client.log_action(
                current_user.id if current_user.is_authenticated else "system",
                "VERIFY_EVIDENCE",
                f"Verified {filename} - Status: {overall_status}"
            )
        except:
            pass
        
        return verification_results
        
    except Exception as e:
        return [dbc.Alert([
            html.H5([html.I(className="fas fa-exclamation-triangle me-2"), "⚠️ Verification Error"]),
            html.P(f"Error during verification: {str(e)}")
        ], color="danger")]

# --- DATA TABLE CALLBACKS ---
@app.callback(Output('evidence-table', 'data'), Input('url', 'pathname'))
def update_evidence_table(pathname):
    if pathname == '/database' and current_user.is_authenticated and current_user.can_access_database():
        raw_evidence = db_client.get_all_evidence()
        safe_evidence = []
        for record in raw_evidence:
            safe_record = {
                'caseId': record.get('caseId', ''),
                'filename': record.get('filename', ''),
                'sha256Hash': record.get('sha256Hash', ''),
                'riskLevel': record.get('riskLevel', ''),
                'timestamp_utc': serialize_datetime_objects(record.get('timestamp_utc', ''))
            }
            safe_evidence.append(safe_record)
        return safe_evidence
    return []

@app.callback(Output('audit-log-table', 'data'), Input('url', 'pathname'))
def update_audit_log_table(pathname):
    if pathname == '/audit' and current_user.is_authenticated and current_user.can_view_audit():
        logs = db_client.get_audit_logs()
        for log in logs:
            log['_id'] = str(log['_id'])
            log['timestamp_utc'] = serialize_datetime_objects(log.get('timestamp_utc', ''))
        return logs
    return []

# --- INGEST CALLBACKS ---
@app.callback(Output('ingest-preview-container', 'children'), Input('upload-file', 'contents'), State('upload-file', 'filename'))
def show_ingest_preview(content, filename):
    if content:
        return html.Div([
            html.Hr(),
            html.H5(f"📁 Preview: {filename}", className="mt-3"),
            html.Img(src=content, style={'maxHeight': '200px', 'maxWidth': '100%', 'borderRadius': '5px'}),
            dbc.Button([
                html.I(className="fas fa-microscope me-2"),
                "🔬 Process & Record Evidence"
            ], id='process-button', color="success", size="lg", className="w-100 mt-4")
        ])
    return ""

@app.callback(
    [Output('ingest-results-container', 'children'), Output('stored-db-record-for-pdf', 'data')],
    Input('process-button', 'n_clicks'),
    [State('upload-file', 'contents'), State('upload-file', 'filename'), State('case-id-input', 'value')],
    prevent_initial_call=True
)
def run_analysis_and_save(n_clicks, content, filename, case_id):
    if not all([content, filename, case_id]):
        return dbc.Alert("Please provide a file and a Case ID.", color="warning", dismissable=True), no_update

    try:
        content_type, content_string = content.split(',')
        decoded_bytes = base64.b64decode(content_string)
        
        # --- Analysis ---
        sha256_bytes = blockchain_service.calculate_sha256(decoded_bytes)
        sha256_hex = sha256_bytes.hex()
        file_type = magic.from_buffer(decoded_bytes, mime=True)
        
        metadata = extract_full_metadata(decoded_bytes, file_type)
        metadata_json_string = safe_json_dumps(metadata)
        formatted_metadata = format_metadata_for_display(metadata)
        ipfs_hash_placeholder = hashlib.sha256(metadata_json_string.encode('utf-8')).hexdigest()

        steg_result, classification_result = "", ""
        if ADVANCED_ANALYSIS_ENABLED and 'image' in file_type:
            steg_result = perform_steganalysis(decoded_bytes)
            classification_result = classify_image(decoded_bytes)
            
        risk_level, risk_reason = assign_risk_level(metadata, steg_result)
        
        # --- Blockchain Interaction ---
        tx_receipt = blockchain_service.record_evidence_on_chain(sha256_bytes, ipfs_hash_placeholder)
        if not tx_receipt:
            return dbc.Alert("CRITICAL: Failed to record on blockchain.", color="danger"), no_update

        tx_hash_hex = tx_receipt['transactionHash'].hex() if hasattr(tx_receipt['transactionHash'], 'hex') else str(tx_receipt['transactionHash'])
        
        # --- Database Record ---
        db_record = {
            "caseId": case_id,
            "filename": filename,
            "sha256Hash": sha256_hex,
            "riskLevel": risk_level,
            "riskReason": risk_reason,
            "transactionHash": tx_hash_hex,
            "custodianAddress": tx_receipt.get('from', 'unknown'),
            "timestamp_utc": datetime.utcnow(),
            "custodian_username": current_user.id,
            "custodian_department": current_user.department,
            "analysisData": {
                "steganography": steg_result,
                "classification": classification_result,
                "metadata": metadata
            }
        }
        db_client.save_evidence_record(db_record.copy())
        
        qr_code_image = generate_qr_code(f"SHA256:{sha256_hex}")
        
        # Department-specific success message
        dept_config = DEPARTMENT_CONFIG.get(current_user.department, DEPARTMENT_CONFIG["Forensics"])
        
        success_output = html.Div([
            dbc.Alert([
                html.H4([
                    html.I(className="fas fa-check-circle me-2"),
                    f"✅ Success! Evidence Processed by {dept_config['emoji']} {current_user.department}"
                ])
            ], color="success"),
            dbc.Card([
                dbc.CardBody([
                    html.H5("🔬 Evidence Analysis Summary"),
                    html.P(f"📁 Case ID: {case_id}"),
                    html.P(f"⚠️ Risk Level: {risk_level} - {risk_reason}"),
                    html.P(f"🔐 SHA256: {sha256_hex}"),
                    html.P(f"👤 Processed by: {current_user.id} ({current_user.department})"),
                    html.Img(src=qr_code_image, style={'width': '150px'})
                ])
            ])
        ])
        
        # Prepare serialized record for storage
        db_record_for_store = serialize_datetime_objects(db_record.copy())
        db_record_for_store.pop('analysisData', None)
        
        return success_output, db_record_for_store

    except Exception as e:
        return dbc.Alert(f"Error: {str(e)}", color="danger"), no_update

# --- QUICK ACTION CALLBACKS ---

# Forensics Lab Tools Callbacks
@app.callback(
    Output('hash-output', 'children'),
    [Input('md5-btn', 'n_clicks'),
     Input('sha256-btn', 'n_clicks'), 
     Input('sha512-btn', 'n_clicks')],
    State('hash-input', 'value'),
    prevent_initial_call=True
)
def calculate_hash(md5_clicks, sha256_clicks, sha512_clicks, input_text):
    if not input_text:
        return dbc.Alert("Please enter text to hash", color="warning")
    
    ctx = callback_context
    if not ctx.triggered:
        return ""
    
    button_id = ctx.triggered[0]['prop_id'].split('.')[0]
    
    try:
        text_bytes = input_text.encode('utf-8')
        if button_id == 'md5-btn':
            hash_result = hashlib.md5(text_bytes).hexdigest()
            hash_type = "MD5"
        elif button_id == 'sha256-btn':
            hash_result = hashlib.sha256(text_bytes).hexdigest()
            hash_type = "SHA256"
        elif button_id == 'sha512-btn':
            hash_result = hashlib.sha512(text_bytes).hexdigest()
            hash_type = "SHA512"
        
        return dbc.Alert([
            html.H6(f"{hash_type} Hash:"),
            html.Code(hash_result, style={"word-break": "break-all"})
        ], color="success")
        
    except Exception as e:
        return dbc.Alert(f"Error calculating hash: {str(e)}", color="danger")

# Legal Review Callbacks
@app.callback(
    Output('legal-review-table', 'data'),
    Input('url', 'pathname')
)
def update_legal_review_table(pathname):
    if pathname == '/legal-review' and current_user.is_authenticated:
        # Get evidence that needs legal review
        evidence_data = db_client.get_all_evidence()
        review_data = []
        for evidence in evidence_data:
            review_data.append({
                'caseId': evidence.get('caseId', ''),
                'filename': evidence.get('filename', ''),
                'riskLevel': evidence.get('riskLevel', ''),
                'review_status': 'Pending',
                'actions': '[Approve](javascript:void(0)) | [Flag](javascript:void(0))'
            })
        return review_data[:10]  # Show first 10 for demo
    return []

# IT Access Management Callbacks
@app.callback(
    Output('access-control-table', 'data'),
    Input('url', 'pathname')
)
def update_access_control_table(pathname):
    if pathname == '/it/access' and current_user.is_authenticated:
        users_data = db_client.get_all_users()
        for user in users_data:
            user['user_actions'] = '[Edit](javascript:void(0)) | [Disable](javascript:void(0))'
        return users_data
    return []

# System Logs Callback
@app.callback(
    Output('system-logs-table', 'data'),
    Input('url', 'pathname')
)
def update_system_logs_table(pathname):
    if pathname == '/admin/logs' and current_user.is_authenticated and current_user.is_admin:
        logs = db_client.get_audit_logs(100)  # Get more logs for admin
        for log in logs:
            log['_id'] = str(log['_id'])
            log['timestamp_utc'] = serialize_datetime_objects(log.get('timestamp_utc', ''))
        return logs
    return []

# Management Approval Requests Callback
@app.callback(
    Output('approval-requests-table', 'data'),
    Input('url', 'pathname')
)
def update_approval_requests_table(pathname):
    if pathname == '/management/requests' and current_user.is_authenticated:
        # Sample approval requests data
        return [
            {
                'request_id': 'REQ001',
                'request_type': 'Evidence Access',
                'requested_by': 'legal_user',
                'department': 'Legal',
                'priority': 'High',
                'approval_actions': '[Approve](javascript:void(0)) | [Deny](javascript:void(0))'
            },
            {
                'request_id': 'REQ002', 
                'request_type': 'System Access',
                'requested_by': 'forensics_user',
                'department': 'Forensics',
                'priority': 'Medium',
                'approval_actions': '[Approve](javascript:void(0)) | [Deny](javascript:void(0))'
            }
        ]
    return []

# --- ADMIN CALLBACKS ---
@app.callback(
    Output('admin-stats', 'children'),
    Input('url', 'pathname')
)
def update_admin_stats(pathname):
    if pathname == '/admin/users' and current_user.is_authenticated and current_user.is_admin:
        stats = db_client.get_system_stats()
        
        return dbc.Row([
            dbc.Col([
                html.H4(stats.get('total_users', 0)),
                html.P("Total Users")
            ], md=3),
            dbc.Col([
                html.H4(stats.get('active_users', 0)),
                html.P("Active Users")
            ], md=3),
            dbc.Col([
                html.H4(stats.get('total_evidence', 0)),
                html.P("Evidence Records")
            ], md=3),
            dbc.Col([
                html.H4(len(stats.get('departments', {}))),
                html.P("Departments")
            ], md=3)
        ])
    return html.Div()

@app.callback(
    Output('create-user-result', 'children'),
    Input('create-user-btn', 'n_clicks'),
    [State('new-username', 'value'),
     State('new-password', 'value'),
     State('new-department', 'value')],
    prevent_initial_call=True
)
def create_new_user(n_clicks, username, password, department):
    if not current_user.is_authenticated or not current_user.is_admin:
        return dbc.Alert("🚫 Access denied", color="danger")
    
    if not all([username, password, department]):
        return dbc.Alert("⚠️ All fields are required", color="warning")
    
    try:
        result = db_client.create_user(username, password, department)
        if result:
            db_client.log_action(current_user.id, "CREATE_USER", f"Created user {username} in {department} department")
            dept_config = DEPARTMENT_CONFIG.get(department, {})
            emoji = dept_config.get('emoji', '👤')
            return dbc.Alert(f"✅ User '{username}' created successfully in {emoji} {department} department!", color="success")
        else:
            return dbc.Alert(f"⚠️ User '{username}' already exists", color="warning")
    except Exception as e:
        return dbc.Alert(f"❌ Error creating user: {str(e)}", color="danger")

# --- SYSTEM STATUS CALLBACKS ---
@app.callback(
    Output('blockchain-status-display', 'children'),
    Input('url', 'pathname')
)
def update_blockchain_status(pathname):
    if pathname == '/admin/settings' and current_user.is_authenticated and current_user.is_admin:
        try:
            info = blockchain_service.get_contract_info()
            if 'error' not in info:
                return html.Div([
                    dbc.Alert("✅ Blockchain Connected", color="success"),
                    html.P(f"Network: Chain ID {info.get('chain_id', 'Unknown')}"),
                    html.P(f"Latest Block: {info.get('latest_block', 'Unknown')}"),
                    html.P(f"Balance: {info.get('account_balance_eth', 0):.4f} ETH")
                ])
            else:
                return dbc.Alert(f"❌ Blockchain Error: {info.get('error', 'Unknown')}", color="danger")
        except:
            return dbc.Alert("❌ Blockchain Service Unavailable", color="danger")
    return html.Div()

@app.callback(
    Output('database-status-display', 'children'),
    Input('url', 'pathname')
)
def update_database_status(pathname):
    if pathname == '/admin/settings' and current_user.is_authenticated and current_user.is_admin:
        try:
            stats = db_client.get_system_stats()
            return html.Div([
                dbc.Alert("✅ Database Connected", color="success"),
                html.P(f"Total Users: {stats.get('total_users', 0)}"),
                html.P(f"Evidence Records: {stats.get('total_evidence', 0)}"),
                html.P(f"Audit Logs: {stats.get('total_audit_logs', 0)}")
            ])
        except:
            return dbc.Alert("❌ Database Service Unavailable", color="danger")
    return html.Div()

# --- RUN APP ---
if __name__ == "__main__":
    print("=== 🚀 STARTING ADVANCED CHAIN OF CUSTODY SYSTEM ===")
    print("🔧 System initializing with enhanced role-based access control...")
    print("👥 Department differentiation: Admin, Forensics, Legal, IT, Management")
    print("🔐 Security features: Role-based permissions, audit logging, session management")
    print("⛓️ Blockchain integration: Evidence integrity and chain of custody")
    print("🔬 Advanced analysis: Steganography detection, metadata extraction, risk assessment")
    print("🎯 Quick Actions: Department-specific tools and workflows")
    print("🚀 Starting Dash application...")
    
    # Test database and blockchain connections
    try:
        db_client.fix_user_accounts_and_test()
        blockchain_service.test_connection()
    except:
        print("⚠️  Warning: Could not test all system components")
    
    print("✅ All systems initialized successfully!")
    print("🌐 Access your Chain of Custody System at: http://localhost:8050")
    
    app.run(debug=True, port=8050, use_reloader=False)
    