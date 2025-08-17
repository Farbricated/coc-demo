# --- IMPORTS ---
import sys
import os
import dash
from dash import dcc, html, Input, Output, State, dash_table
import dash_bootstrap_components as dbc
import base64
import io
import json
import hashlib
from PIL import Image
from datetime import datetime

# This line tells Python to add the current script's directory to the list of places to look for modules.
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
from database import save_evidence_record, find_evidence_by_hash, client as mongo_client, evidence_collection
from blockchain import record_hash_on_blockchain, get_evidence_timestamp, is_connected

# --- APP INITIALIZATION ---
FONT_AWESOME = "https://use.fontawesome.com/releases/v5.15.4/css/all.css"
app = dash.Dash(__name__, external_stylesheets=[dbc.themes.DARKLY, FONT_AWESOME], suppress_callback_exceptions=True)

# --- REUSABLE STYLING ---
CONTENT_STYLE = {"padding": "2rem 1rem", "background-color": "#1a1a1a", "min-height": "100vh"}

# --- SIDEBAR LAYOUT ---
sidebar = html.Div(
    [
        html.H2([html.I(className="fas fa-shield-alt me-2"), "COC Demo"], className="display-5 text-white"),
        html.P("Chain of Custody", className="text-white-50"),
        html.Hr(className="text-white"),
        dbc.Nav(
            [
                dbc.NavLink([html.I(className="fas fa-tachometer-alt me-2"), "Dashboard"], href="/", active="exact"),
                dbc.NavLink([html.I(className="fas fa-upload me-2"), "Upload Evidence"], href="/upload", active="exact"),
                dbc.NavLink([html.I(className="fas fa-check-circle me-2"), "Verify Evidence"], href="/verify", active="exact"),
                dbc.NavLink([html.I(className="fas fa-database me-2"), "Evidence Database"], href="/database", active="exact"),
            ],
            vertical=True, pills=True,
        ),
    ],
    className="d-flex flex-column p-3 text-white bg-dark",
)

# --- PAGE-SPECIFIC LAYOUTS ---

def generate_dashboard_layout():
    mongo_status = bool(mongo_client)
    if mongo_status:
        try: mongo_client.admin.command('ping')
        except Exception: mongo_status = False

    def create_status_card(title, is_connected, icon_class):
        status_text = "Connected" if is_connected else "Disconnected"
        status_icon = f"fas {icon_class} me-2 text-success" if is_connected else f"fas {icon_class} me-2 text-danger"
        return dbc.Card(dbc.CardBody([html.H5(title), html.P([html.I(className=status_icon), f" {status_text}"], className="small")]), className="h-100")

    return html.Div([
        html.H1("System Dashboard", className="mb-4"),
        dbc.Row([
            dbc.Col(create_status_card("MongoDB Atlas", mongo_status, "fa-database"), md=4),
            dbc.Col(create_status_card("Ganache Blockchain", is_connected, "fa-link"), md=4),
        ], className="mb-4"),
    ])

upload_layout = html.Div([
    html.H1("Upload New Evidence", className="mb-4"),
    html.P("Select an image to begin the analysis and record its chain of custody."),
    dbc.Card(dbc.CardBody([
        dcc.Upload(id='upload-image', children=['Drag and Drop or ', html.A('Select an Image')], className="py-5 text-center", style={'borderWidth': '2px', 'borderStyle': 'dashed', 'borderRadius': '5px'}),
        html.Div(id='preview-and-process-button-container', className="text-center"),
    ])),
    dbc.Spinner(html.Div(id='analysis-results-container', className="mt-4"))
])

verify_layout = html.Div([
    html.H1("Verify Evidence Integrity", className="mb-4"),
    html.P("Upload an image to verify its hash against the database and blockchain records."),
    dbc.Card(dbc.CardBody([
        dcc.Upload(id='verify-upload', children=['Drag and Drop or ', html.A('Select an Image to Verify')], className="py-5 text-center", style={'borderWidth': '2px', 'borderStyle': 'dashed', 'borderRadius': '5px'}),
        html.Div(id='verify-preview-container', className="text-center mt-3"),
        dbc.Button([html.I(className="fas fa-check-double me-2"), "Verify"], id='verify-button', color="success", size="lg", className="w-100 mt-3", disabled=True)
    ])),
    dbc.Spinner(html.Div(id='verify-result-container', className="mt-4"))
])

database_layout = html.Div([
    html.H1("Evidence Database", className="mb-4"),
    html.P("Browse and search all evidence records stored in the database."),
    dbc.Card(dbc.CardBody([
        dash_table.DataTable(
            id='evidence-table',
            columns=[
                {"name": "Filename", "id": "filename"}, {"name": "Image Hash", "id": "image_hash"}, {"name": "Timestamp (UTC)", "id": "timestamp_utc"},
            ],
            data=[],
            style_header={'backgroundColor': '#1a1a1a', 'color': 'white', 'fontWeight': 'bold'},
            style_cell={'backgroundColor': 'rgba(255,255,255,0.05)', 'color': 'white', 'border': '1px solid #444'},
            style_table={'overflowX': 'auto'},
            page_size=15, filter_action="native", sort_action="native",
        )
    ]))
])

error_404_layout = dbc.Row(dbc.Col(html.Div([
    html.H1("404: Not Found", className="text-danger"), html.P("The page you were looking for doesn't exist."),
    dbc.Button("Go to Dashboard", href="/", color="primary"),
], className="text-center"), width=12), className="justify-content-center align-items-center h-100")

# --- APP LAYOUT & ROUTING ---
content_area = html.Div([dcc.Location(id="url"), html.Div(id="page-content", style=CONTENT_STYLE)])
app.layout = dbc.Container([dbc.Row([dbc.Col(sidebar, width=2), dbc.Col(content_area, width=10)])], fluid=True, className="p-0")

@app.callback(Output("page-content", "children"), [Input("url", "pathname")])
def render_page_content(pathname):
    if pathname == "/": return generate_dashboard_layout()
    elif pathname == "/upload": return upload_layout
    elif pathname == "/verify": return verify_layout
    elif pathname == "/database": return database_layout
    return error_404_layout

# --- CALLBACKS ---

# Database Page
@app.callback(Output('evidence-table', 'data'), Input('url', 'pathname'))
def update_evidence_table(pathname):
    if pathname == '/database' and evidence_collection is not None:
        records = list(evidence_collection.find({}, {"analysis_data": 0, "_id": 0}).sort("timestamp_utc", -1))
        for record in records:
            if 'timestamp_utc' in record and isinstance(record['timestamp_utc'], datetime):
                record['timestamp_utc'] = record['timestamp_utc'].strftime('%Y-%m-%d %H:%M:%S')
        return records
    return []

# Verify Page
@app.callback([Output('verify-preview-container', 'children'), Output('verify-button', 'disabled')], Input('verify-upload', 'contents'), State('verify-upload', 'filename'))
def show_verify_preview(content, filename):
    if content:
        preview = html.Div([html.P(filename), html.Img(src=content, style={'maxHeight': '200px', 'borderRadius': '5px'})])
        return preview, False
    return None, True

@app.callback(Output('verify-result-container', 'children'), Input('verify-button', 'n_clicks'), State('verify-upload', 'contents'))
def perform_verification(n_clicks, content):
    if not n_clicks or not content: return ""
    
    decoded_image = base64.b64decode(content.split(',')[1])
    image_hash_to_verify = hashlib.sha256(decoded_image).hexdigest()

    db_record = find_evidence_by_hash(image_hash_to_verify)
    blockchain_timestamp = get_evidence_timestamp(image_hash_to_verify)

    db_card = dbc.Card([dbc.CardHeader("Database Verification"), dbc.CardBody([html.H4("✅ Found" if db_record else "❌ Not Found", className="text-success" if db_record else "text-danger"), html.Pre(json.dumps(db_record, default=str, indent=2)) if db_record else ""])])
    bc_card = dbc.Card([dbc.CardHeader("Blockchain Verification"), dbc.CardBody([html.H4("✅ Found" if blockchain_timestamp > 0 else "❌ Not Found", className="text-success" if blockchain_timestamp > 0 else "text-danger"), html.P(f"Recorded at: {datetime.utcfromtimestamp(blockchain_timestamp).strftime('%Y-%m-%d %H:%M:%S UTC')}" if blockchain_timestamp > 0 else "")])])

    return dbc.Row([dbc.Col(db_card, md=6), dbc.Col(bc_card, md=6)], className="mt-4")

# Upload Page
@app.callback(Output('preview-and-process-button-container', 'children'), Input('upload-image', 'contents'), State('upload-image', 'filename'))
def show_upload_preview(content, filename):
    if content:
        return html.Div([
            html.Hr(), html.H5("Image Preview: " + filename),
            html.Img(src=content, style={'maxHeight': '300px', 'borderRadius': '5px', 'margin': '10px'}),
            dbc.Button([html.I(className="fas fa-cogs me-2"), "Process & Record"], id='process-button', color="primary", size="lg", className="w-100 mt-3")
        ])
    return ""

@app.callback(Output('analysis-results-container', 'children'), Input('process-button', 'n_clicks'), [State('upload-image', 'contents'), State('upload-image', 'filename')])
def run_analysis_and_save(n_clicks, content, filename):
    if not n_clicks or not content: return ""
    
    decoded_image = base64.b64decode(content.split(',')[1])
    image_hash = hashlib.sha256(decoded_image).hexdigest()

    final_record = {"filename": filename, "image_hash": image_hash, "analysis_data": {}, "metadata_hash": ""} # Placeholder for analysis
    record_id = save_evidence_record(final_record)
    
    if not record_id: return dbc.Alert("❌ Failed to save to database.", color="danger")
    
    tx_hash = record_hash_on_blockchain(image_hash)
    if not tx_hash: return dbc.Alert("✅ Saved to DB but ❌ failed to record on blockchain.", color="warning")

    return dbc.Alert(f"✅ Success! DB ID: {record_id}, TX Hash: {tx_hash}", color="success")

# --- RUN APP ---
if __name__ == "__main__":
    app.run(debug=False)
