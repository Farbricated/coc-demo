# --- IMPORTS ---
import sys, os, dash, base64, io, json, hashlib
from dash import dcc, html, Input, Output, State, dash_table
import dash_bootstrap_components as dbc
from PIL import Image, ExifTags
from datetime import datetime
import piexif

# --- SETUP ---
# Add the app's root directory to the Python path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
from database import (save_evidence_record, find_evidence_by_hash, get_evidence_stats, 
                      get_recent_evidence, client as mongo_client, evidence_collection)
from blockchain import record_hash_on_blockchain, get_evidence_timestamp, is_connected

# --- APP INITIALIZATION ---
FONT_AWESOME = "https://use.fontawesome.com/releases/v5.15.4/css/all.css"
app = dash.Dash(__name__, external_stylesheets=[dbc.themes.DARKLY, FONT_AWESOME], suppress_callback_exceptions=True, title="CoC Evidence Management")

# --- STYLING ---
CONTENT_STYLE = {
    "marginLeft": "18rem",
    "marginRight": "2rem",
    "padding": "2rem 1rem",
}
SIDEBAR_STYLE = {
    "position": "fixed", "top": 0, "left": 0, "bottom": 0,
    "width": "16rem", "padding": "2rem 1rem", "backgroundColor": "#222",
}

# --- HELPER FUNCTIONS (Optimized Risk Assessment) ---
def extract_full_metadata(image_bytes):
    try:
        image = Image.open(io.BytesIO(image_bytes))
        raw_exif = image.info.get('exif')
        if not raw_exif:
            return {"Error": "No EXIF data found in the image."}
        exif_dict = piexif.load(raw_exif)
        full_metadata = {}
        for ifd_name in exif_dict:
            if ifd_name == "thumbnail": continue
            tag_group = {}
            for tag_id, value in exif_dict[ifd_name].items():
                tag_name = ExifTags.TAGS.get(tag_id, f"UnknownTag-{tag_id}")
                if isinstance(value, bytes): value = value.decode(errors='ignore')
                tag_group[tag_name] = value
            ifd_label = {"0th": "Image", "Exif": "ExifData", "GPS": "GPSInfo"}.get(ifd_name, ifd_name)
            full_metadata[ifd_label] = tag_group
        return full_metadata
    except Exception as e:
        return {"Error": f"Failed to process metadata: {e}"}

def assign_risk_level(metadata):
    if "Error" in metadata or not metadata:
        return "High", "Critical error: No EXIF metadata found."
    image_data = metadata.get("Image", {})
    software = image_data.get('Software', '')
    if any(editor.lower() in software.lower() for editor in ['Photoshop', 'GIMP', 'Paint.NET']):
        return "High", f"Image explicitly lists modification software: {software}."
    exif_data = metadata.get("ExifData", {})
    if 'DateTimeOriginal' in exif_data and not ('Make' in image_data or 'Model' in image_data):
        return "Medium", "Timestamp exists, but camera make/model metadata is missing, suggesting potential alteration."
    if 'DateTimeOriginal' not in exif_data:
        return "Medium", "Original creation timestamp (DateTimeOriginal) is missing."
    return "Low", "No obvious signs of tampering found in metadata."

def get_map_iframe(gps_info):
    if not gps_info: return None
    try:
        def to_decimal(dms, ref):
            d, m, s = (i[0]/i[1] for i in dms); dec = d + (m/60.0) + (s/3600.0)
            return -dec if ref in ['S','W'] else dec
        lat = to_decimal(gps_info['GPSLatitude'], gps_info['GPSLatitudeRef'])
        lon = to_decimal(gps_info['GPSLongitude'], gps_info['GPSLongitudeRef'])
        map_src = f"https://maps.google.com/maps?q={lat},{lon}&hl=en&z=14&output=embed"
        return html.Iframe(src=map_src, width="100%", height="300", style={"border": 0})
    except: return None

# --- UI LAYOUT DEFINITIONS ---
sidebar = html.Div([
    html.H2([html.I(className="fas fa-shield-alt me-2"), "CoC System"], className="display-5 text-white"),
    html.P("Evidence Integrity Platform", className="text-white-50"),
    html.Hr(className="text-white"),
    dbc.Nav([
        dbc.NavLink([html.I(className="fas fa-chart-line me-2"), "Dashboard"], href="/", active="exact"),
        dbc.NavLink([html.I(className="fas fa-upload me-2"), "Ingest Evidence"], href="/upload", active="exact"),
        dbc.NavLink([html.I(className="fas fa-check-double me-2"), "Verify Integrity"], href="/verify", active="exact"),
        dbc.NavLink([html.I(className="fas fa-database me-2"), "Evidence Locker"], href="/database", active="exact"),
    ], vertical=True, pills=True)
], style=SIDEBAR_STYLE)

def generate_dashboard_layout():
    stats = get_evidence_stats()
    recent_evidence = get_recent_evidence()
    def create_metric_card(title, value, color): return dbc.Card(dbc.CardBody([html.H4(title, className="card-title"), html.H2(value)]), color=color, inverse=True, className="mb-4")
    recent_table = dash_table.DataTable(
        data=[{**item, '_id': str(item['_id']), 'timestamp_utc': item['timestamp_utc'].strftime('%Y-%m-%d %H:%M:%S')} for item in recent_evidence],
        columns=[{"name": "Case ID", "id": "case_id"}, {"name": "Filename", "id": "filename"}, {"name": "Risk", "id": "risk_level"}, {"name": "Timestamp", "id": "timestamp_utc"}],
        style_header={'backgroundColor': '#1A1B1E', 'color': 'white'}, style_cell={'backgroundColor': '#2C2E33', 'color': 'white', 'textAlign': 'left'}, style_as_list_view=True
    )
    return html.Div([
        html.H1("System Dashboard", className="mb-4"),
        dbc.Row([
            dbc.Col(create_metric_card("Total Evidence", stats['total'], "primary"), md=3),
            dbc.Col(create_metric_card("High Risk", stats['High'], "danger"), md=3),
            dbc.Col(create_metric_card("Medium Risk", stats['Medium'], "warning"), md=3),
            dbc.Col(create_metric_card("Low Risk", stats['Low'], "success"), md=3),
        ]),
        html.Hr(), html.H3("Recent Activity"), dbc.Card(dbc.CardBody(recent_table))])

upload_layout = html.Div([
    html.H1("Ingest New Evidence", className="mb-4"),
    html.P("Begin the chain of custody by uploading a digital asset for analysis and blockchain registration."),
    dbc.Card(dbc.CardBody([
        dbc.Input(id="case-id-input", placeholder="Enter Case ID (e.g., C2025-001)", type="text", className="mb-3"),
        dcc.Upload(id='upload-image', children=['Drag and Drop or ', html.A('Select an Image')], className="py-5 text-center", style={'borderWidth': '2px', 'borderStyle': 'dashed'}),
        html.Div(id='preview-and-process-button-container', className="text-center mt-3"),
    ])),
    dbc.Spinner(html.Div(id='analysis-results-container', className="mt-4"))])

verify_layout = html.Div([
    html.H1("Verify Evidence Integrity", className="mb-4"),
    html.P("Validate an asset by comparing its live hash against the official database and blockchain records."),
    dbc.Card(dbc.CardBody([
        dcc.Upload(id='verify-upload', children=['Drag and Drop or ', html.A('Select Image to Verify')], className="py-5 text-center", style={'borderWidth': '2px', 'borderStyle': 'dashed'}),
        html.Div(id='verify-preview-container', className="text-center mt-3"),
        dbc.Button([html.I(className="fas fa-check-double me-2"), "Verify"], id='verify-button', color="success", size="lg", className="w-100 mt-3", disabled=True)
    ])),
    dbc.Spinner(html.Div(id='verify-result-container', className="mt-4"))])

database_layout = html.Div([
    html.H1("Evidence Locker", className="mb-4"),
    html.P("Browse, search, and filter all evidence records ingested into the system."),
    dbc.Card(dbc.CardBody([dash_table.DataTable(
        id='evidence-table',
        columns=[{"name": c.replace("_", " ").title(), "id": c} for c in ["case_id", "filename", "image_hash", "risk_level", "timestamp_utc"]],
        style_header={'backgroundColor': '#1A1B1E', 'color': 'white'}, style_cell={'backgroundColor': '#2C2E33', 'color': 'white'}, style_as_list_view=True,
        page_size=20, filter_action="native", sort_action="native",
    )]))])

# --- MAIN APP LAYOUT & ROUTING ---
app.layout = html.Div([dcc.Location(id="url"), sidebar, html.Div(id="page-content", style=CONTENT_STYLE)])

@app.callback(Output("page-content", "children"), Input("url", "pathname"))
def render_page_content(pathname):
    if pathname == "/": return generate_dashboard_layout()
    elif pathname == "/upload": return upload_layout
    elif pathname == "/verify": return verify_layout
    elif pathname == "/database": return database_layout
    return html.Div([html.H1("404: Not Found", className="text-danger"), html.P(f"The path '{pathname}' was not found.")], className="text-center py-5")

# --- CALLBACKS ---
@app.callback(Output('evidence-table', 'data'), Input('url', 'pathname'))
def update_evidence_table(pathname):
    if pathname == '/database' and evidence_collection is not None:
        records = list(evidence_collection.find({}, {"analysis_data": 0, "_id": 0}).sort("timestamp_utc", -1))
        for r in records: r['timestamp_utc'] = r['timestamp_utc'].strftime('%Y-%m-%d %H:%M:%S')
        return records
    return []

@app.callback(Output('preview-and-process-button-container', 'children'), Input('upload-image', 'contents'), State('upload-image', 'filename'))
def show_upload_preview(content, filename):
    if content:
        return html.Div([
            html.Hr(), html.H5("Preview: " + filename),
            html.Img(src=content, style={'maxHeight': '300px', 'borderRadius': '5px'}),
            dbc.Button([html.I(className="fas fa-cogs me-2"), "Process & Record"], id='process-button', color="primary", size="lg", className="w-100 mt-3")])
    return ""

@app.callback(Output('verify-preview-container', 'children'), Input('verify-upload', 'contents'), State('verify-upload', 'filename'))
def show_verify_preview(content, filename):
    if content:
        return html.Div([
            html.Hr(), html.H5("Preview: " + filename),
            html.Img(src=content, style={'maxHeight': '300px', 'borderRadius': '5px'}),
        ])
    return ""

@app.callback(Output('verify-button', 'disabled'), Input('verify-upload', 'contents'))
def enable_verify_button(contents):
    return not contents

@app.callback(
    Output('analysis-results-container', 'children'),
    Input('process-button', 'n_clicks'),
    [State('upload-image', 'contents'), State('upload-image', 'filename'), State('case-id-input', 'value')]
)
def run_analysis_and_save(n_clicks, content, filename, case_id):
    if not n_clicks or not content: return ""
    if not case_id: return dbc.Alert("A Case ID is required.", color="warning")
    decoded_bytes = base64.b64decode(content.split(',')[1])
    image_hash = hashlib.sha256(decoded_bytes).hexdigest()
    metadata = extract_full_metadata(decoded_bytes)
    risk_level, risk_reason = assign_risk_level(metadata)
    map_frame = get_map_iframe(metadata.get("GPSInfo"))
    final_record = {"case_id": case_id, "filename": filename, "image_hash": image_hash, "timestamp_utc": datetime.utcnow(), "risk_level": risk_level, "risk_reason": risk_reason, "analysis_data": {"full_metadata": metadata}}
    record_id = save_evidence_record(final_record)
    if not record_id: return dbc.Alert("Error: Could not save to database.", color="danger")
    tx_hash = record_hash_on_blockchain(image_hash)
    if not tx_hash: return dbc.Alert("Warning: Saved to DB but failed to record on blockchain.", color="warning")
    hash_card = dbc.Card([dbc.CardHeader("Cryptographic Hashes"), dbc.CardBody([html.P(["Image (SHA-256): ", html.Code(image_hash)]), html.P(["Blockchain TX: ", html.Code(tx_hash)])])])
    risk_card = dbc.Card([dbc.CardHeader("Risk Assessment"), dbc.CardBody(dbc.Alert(f"{risk_level}: {risk_reason}", color={"Low": "success", "Medium": "warning", "High": "danger"}[risk_level]))])
    map_card = dbc.Card([dbc.CardHeader("Geolocation"), dbc.CardBody(map_frame if map_frame else "No GPS data found.")])
    metadata_card = dbc.Card([dbc.CardHeader("Full Extracted Metadata"), dbc.CardBody(html.Pre(json.dumps(metadata, indent=2, default=str), style={"maxHeight": "400px", "overflowY": "auto", "backgroundColor": "rgba(0,0,0,0.2)"}))])
    return html.Div([
        dbc.Alert("Success! Evidence processed and recorded.", color="success"),
        dbc.Row([dbc.Col(hash_card, md=6), dbc.Col(risk_card, md=6)], className="mb-3"),
        dbc.Row([dbc.Col(map_card, md=12, className="mb-3")]),
        dbc.Row([dbc.Col(metadata_card)])])

@app.callback(
    Output('verify-result-container', 'children'),
    Input('verify-button', 'n_clicks'),
    State('verify-upload', 'contents')
)
def perform_verification(n_clicks, content):
    if not n_clicks or not content: return ""
    image_hash_to_verify = hashlib.sha256(base64.b64decode(content.split(',')[1])).hexdigest()
    db_record = find_evidence_by_hash(image_hash_to_verify)
    blockchain_timestamp = get_evidence_timestamp(image_hash_to_verify)
    if db_record:
        db_card_body = [html.H4("✅ Match Found", className="text-success"), html.Hr(),
                        html.P(f"Filename: {db_record.get('filename')}"), html.P(f"Case ID: {db_record.get('case_id')}"),
                        html.P(f"Original Hash: {db_record.get('image_hash')}"),]
    else:
        db_card_body = [html.H4("❌ No Match Found", className="text-danger")]
    db_card = dbc.Card([dbc.CardHeader("Database Verification"), dbc.CardBody(db_card_body)])
    if blockchain_timestamp > 0:
        bc_card_body = [html.H4("✅ Match Found", className="text-success"), html.Hr(),
                        html.P(f"Recorded on-chain at: {datetime.utcfromtimestamp(blockchain_timestamp).strftime('%Y-%m-%d %H:%M:%S UTC')}"),]
    else:
        bc_card_body = [html.H4("❌ No Match Found", className="text-danger")]
    bc_card = dbc.Card([dbc.CardHeader("Blockchain Verification"), dbc.CardBody(bc_card_body)])
    if db_record and blockchain_timestamp > 0:
        integrity_alert = dbc.Alert("✅ VERIFIED: The hash of this file matches the original records in both the database and the blockchain.", color="success", className="mt-4")
    else:
        integrity_alert = dbc.Alert("❌ NOT VERIFIED: This file's hash does not match the original records. The evidence may have been altered or is not in the system.", color="danger", className="mt-4")
    return html.Div([integrity_alert, dbc.Row([dbc.Col(db_card, md=6), dbc.Col(bc_card, md=6)], className="mt-3")])

# --- RUN APP ---
if __name__ == "__main__":
    app.run(debug=False, port=8050)
