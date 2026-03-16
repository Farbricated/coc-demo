#!/usr/bin/env python3
"""
🇮🇳 COC — Chain of Custody Evidence Management System
=======================================================
Single-file edition | SQLite · Groq AI · Blockchain · Section 65B
Run: python coc.py
"""

import os, sys, json, math, time, base64, hashlib, secrets, logging, sqlite3, requests
from datetime import datetime, timedelta
from pathlib import Path
from io import BytesIO
from typing import Dict, List, Optional, Any

# ── Windows UTF-8 fix ─────────────────────────────────────────────────────────
if sys.platform == "win32":
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

# ── Dirs ──────────────────────────────────────────────────────────────────────
for _d in ["logs", "data", "uploads", "reports"]:
    Path(_d).mkdir(exist_ok=True)

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s: %(message)s",
    handlers=[logging.FileHandler("logs/coc.log", encoding="utf-8"), logging.StreamHandler()],
)
logger = logging.getLogger(__name__)

# ── .env loader ───────────────────────────────────────────────────────────────
try:
    from dotenv import load_dotenv; load_dotenv()
except ImportError:
    pass

# ── Third-party imports ───────────────────────────────────────────────────────
import dash
from dash import dcc, html, Input, Output, State, callback_context, ALL
from dash.exceptions import PreventUpdate
import dash_bootstrap_components as dbc
import plotly.graph_objects as go
import pandas as pd
from flask import Flask, send_file
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import jwt, pyotp, qrcode

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.units import inch
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY
    from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                     Table, TableStyle, HRFlowable, PageBreak)
    REPORTLAB = True
except ImportError:
    REPORTLAB = False
    logger.warning("reportlab not installed — PDF reports disabled")

# ═══════════════════════════════════════════════════════════════════════════════
# ██████  ███████     ██████   █████  ███████ ███████
# ██   ██ ██         ██       ██   ██ ██      ██
# ██   ██ ███████    ██   ███ ███████ ███████ █████
# ██   ██      ██    ██    ██ ██   ██      ██ ██
# ██████  ███████     ██████  ██   ██ ███████ ███████
# ═══════════════════════════════════════════════════════════════════════════════

DB_PATH = Path("data/coc.db")

def _db():
    DB_PATH.parent.mkdir(exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn

def init_db():
    conn = _db()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL, full_name TEXT NOT NULL,
        role TEXT NOT NULL, department TEXT NOT NULL,
        badge_number TEXT, clearance_level INTEGER DEFAULT 1,
        failed_attempts INTEGER DEFAULT 0, last_login TEXT,
        created_at TEXT NOT NULL, active INTEGER DEFAULT 1
    );
    CREATE TABLE IF NOT EXISTS cases (
        id TEXT PRIMARY KEY, case_number TEXT UNIQUE NOT NULL,
        title TEXT NOT NULL, description TEXT, case_type TEXT DEFAULT 'general',
        status TEXT DEFAULT 'Open', priority TEXT DEFAULT 'MEDIUM',
        classification TEXT DEFAULT 'CONFIDENTIAL', created_by TEXT NOT NULL,
        created_at TEXT NOT NULL, updated_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS evidence (
        id TEXT PRIMARY KEY, evidence_number TEXT UNIQUE NOT NULL,
        filename TEXT NOT NULL, original_filename TEXT NOT NULL,
        file_size INTEGER NOT NULL, file_type TEXT,
        sha256_hash TEXT NOT NULL, md5_hash TEXT NOT NULL,
        case_id TEXT NOT NULL, uploaded_by TEXT NOT NULL,
        priority TEXT DEFAULT 'MEDIUM', classification TEXT DEFAULT 'CONFIDENTIAL',
        location TEXT, description TEXT,
        risk_level TEXT DEFAULT 'UNKNOWN', risk_score REAL DEFAULT 0.0,
        ai_summary TEXT, ai_threats TEXT, ai_recommendations TEXT,
        processing_time_ms INTEGER DEFAULT 0,
        blockchain_hash TEXT, blockchain_block INTEGER, tx_hash TEXT,
        status TEXT DEFAULT 'ANALYZED', uploaded_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS audit_logs (
        id TEXT PRIMARY KEY, username TEXT, action TEXT NOT NULL,
        resource_type TEXT, resource_id TEXT, details TEXT,
        timestamp TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS blockchain_records (
        id TEXT PRIMARY KEY, block_index INTEGER NOT NULL,
        block_hash TEXT NOT NULL, previous_hash TEXT NOT NULL,
        evidence_id TEXT, file_hash TEXT, uploader TEXT,
        case_id TEXT, timestamp TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS groq_cache (
        file_hash TEXT PRIMARY KEY, analysis_json TEXT NOT NULL,
        cached_at TEXT NOT NULL
    );
    """)
    conn.commit()
    _seed_users(conn)
    _seed_cases(conn)
    conn.close()
    logger.info("✅ Database ready")

def _seed_users(conn):
    users = [
        ("admin",        "admin123",   "DCP Priya Sharma, IPS",      "admin",         "National Cyber Security",    "NCSC-001", 5),
        ("analyst",      "analyst123", "Dr. Rajesh Kumar Singh",      "analyst",       "Central Forensic Science Lab","CFSL-042", 4),
        ("investigator", "invest123",  "Inspector Anita Desai, IPS",  "investigator",  "CBI Cyber Crime Division",   "CBI-187",  3),
        ("officer",      "officer123", "Sub-Inspector Suresh Patel",  "officer",       "Delhi Police Cyber Cell",    "DPC-256",  2),
        ("legal",        "legal123",   "Adv. Vikram Choudhary",       "legal",         "MeitY Legal Division",       "MEL-101",  3),
    ]
    for u, p, fn, r, d, b, cl in users:
        if not conn.execute("SELECT id FROM users WHERE username=?", (u,)).fetchone():
            conn.execute("INSERT INTO users (id,username,password_hash,full_name,role,department,badge_number,clearance_level,created_at) VALUES (?,?,?,?,?,?,?,?,?)",
                (secrets.token_hex(8), u, generate_password_hash(p), fn, r, d, b, cl, datetime.now().isoformat()))
    conn.commit()

def _seed_cases(conn):
    if conn.execute("SELECT COUNT(*) FROM cases").fetchone()[0]: return
    admin = conn.execute("SELECT id FROM users WHERE username='admin'").fetchone()
    aid = admin["id"] if admin else "system"
    now = datetime.now().isoformat()
    for cn, title, desc, ct, st, pr, cl in [
        ("APT-2024-001","State-Sponsored APT Attack on Power Grid",
         "Investigation of cyber attack on Maharashtra power infrastructure by suspected state actors.",
         "cyber_terrorism","Active","CRITICAL","TOP_SECRET"),
        ("UPI-2024-047","Multi-State UPI Fraud Network",
         "Large-scale UPI fraud operation targeting 15,000+ victims across 23 states. Loss: ₹247 Crores.",
         "financial_cybercrime","Active","HIGH","SECRET"),
        ("MUR-2024-156","Digital Evidence — High-Profile Murder Case",
         "Mobile forensics and digital reconstruction. 89% of total evidence is digital.",
         "digital_murder","Under Investigation","HIGH","CONFIDENTIAL"),
    ]:
        conn.execute("INSERT INTO cases (id,case_number,title,description,case_type,status,priority,classification,created_by,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (secrets.token_hex(8), cn, title, desc, ct, st, pr, cl, aid, now, now))
    conn.commit()

# ── DB helpers ────────────────────────────────────────────────────────────────
def db_get_user(username):
    c = _db(); r = c.execute("SELECT * FROM users WHERE username=? AND active=1",(username,)).fetchone(); c.close()
    return dict(r) if r else None

def db_update_login(username):
    c = _db(); c.execute("UPDATE users SET last_login=?,failed_attempts=0 WHERE username=?",(datetime.now().isoformat(),username)); c.commit(); c.close()

def db_inc_failed(username):
    c = _db(); c.execute("UPDATE users SET failed_attempts=failed_attempts+1 WHERE username=?",(username,)); c.commit(); c.close()

def db_reset_failed(username):
    c = _db(); c.execute("UPDATE users SET failed_attempts=0 WHERE username=?",(username,)); c.commit(); c.close()

def db_get_cases(clearance=5):
    allowed = {1:["RESTRICTED"],2:["RESTRICTED","CONFIDENTIAL"],3:["RESTRICTED","CONFIDENTIAL","SECRET"],
               4:["RESTRICTED","CONFIDENTIAL","SECRET"],5:["RESTRICTED","CONFIDENTIAL","SECRET","TOP_SECRET"]}.get(clearance,["RESTRICTED"])
    c = _db(); ph = ",".join("?"*len(allowed))
    rows = c.execute(f"SELECT * FROM cases WHERE classification IN ({ph}) ORDER BY created_at DESC", allowed).fetchall()
    c.close(); return [dict(r) for r in rows]

def db_get_case(case_id):
    c = _db(); r = c.execute("SELECT * FROM cases WHERE id=?",(case_id,)).fetchone(); c.close()
    return dict(r) if r else None

def db_create_case(title, description, case_type, priority, classification, created_by):
    cid = secrets.token_hex(8)
    prefix = {"cyber_terrorism":"APT","financial_cybercrime":"FIN","digital_murder":"HOM"}.get(case_type,"GEN")
    cn = f"{prefix}-{datetime.now().strftime('%Y')}-{secrets.token_hex(3).upper()}"
    now = datetime.now().isoformat()
    c = _db(); c.execute("INSERT INTO cases (id,case_number,title,description,case_type,priority,classification,created_by,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
        (cid,cn,title,description or "",case_type,priority,classification,created_by,now,now)); c.commit(); c.close()
    return cid

def db_save_evidence(data):
    try:
        c = _db()
        c.execute("""INSERT INTO evidence (id,evidence_number,filename,original_filename,file_size,file_type,
            sha256_hash,md5_hash,case_id,uploaded_by,priority,classification,location,description,
            risk_level,risk_score,ai_summary,ai_threats,ai_recommendations,processing_time_ms,
            blockchain_hash,blockchain_block,tx_hash,status,uploaded_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (data["id"],data["evidence_number"],data["filename"],data["original_filename"],data["file_size"],
             data.get("file_type","UNKNOWN"),data["sha256_hash"],data["md5_hash"],data["case_id"],data["uploaded_by"],
             data.get("priority","MEDIUM"),data.get("classification","CONFIDENTIAL"),data.get("location",""),
             data.get("description",""),data.get("risk_level","UNKNOWN"),data.get("risk_score",0.0),
             data.get("ai_summary",""),data.get("ai_threats",""),data.get("ai_recommendations",""),
             data.get("processing_time_ms",0),data.get("blockchain_hash",""),data.get("blockchain_block",0),
             data.get("tx_hash",""),"ANALYZED",datetime.now().isoformat()))
        c.commit(); c.close(); return True
    except Exception as e:
        logger.error(f"save_evidence: {e}"); return False

def db_get_evidence(case_id=None, limit=100):
    c = _db()
    rows = c.execute("SELECT * FROM evidence WHERE case_id=? ORDER BY uploaded_at DESC LIMIT ?" if case_id
                     else "SELECT * FROM evidence ORDER BY uploaded_at DESC LIMIT ?",
                     (case_id,limit) if case_id else (limit,)).fetchall()
    c.close(); return [dict(r) for r in rows]

def db_get_stats():
    c = _db()
    s = {k:c.execute(q).fetchone()[0] for k,q in [
        ("total_evidence","SELECT COUNT(*) FROM evidence"),
        ("total_cases","SELECT COUNT(*) FROM cases"),
        ("active_cases","SELECT COUNT(*) FROM cases WHERE status='Active'"),
        ("critical_cases","SELECT COUNT(*) FROM cases WHERE priority='CRITICAL'"),
        ("high_risk","SELECT COUNT(*) FROM evidence WHERE risk_level IN ('HIGH','CRITICAL')"),
        ("blockchain_anchored","SELECT COUNT(*) FROM evidence WHERE blockchain_hash!=''"),
        ("total_users","SELECT COUNT(*) FROM users WHERE active=1"),
    ]}
    c.close(); return s

def db_log(username, action, rtype="", rid="", details=""):
    try:
        c = _db(); c.execute("INSERT INTO audit_logs (id,username,action,resource_type,resource_id,details,timestamp) VALUES (?,?,?,?,?,?,?)",
            (secrets.token_hex(8),username,action,rtype,rid,details,datetime.now().isoformat())); c.commit(); c.close()
    except: pass

def db_get_logs(limit=30):
    c = _db(); rows = c.execute("SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT ?",(limit,)).fetchall(); c.close()
    return [dict(r) for r in rows]

def db_get_users():
    c = _db(); rows = c.execute("SELECT id,username,full_name,role,department,badge_number,clearance_level,last_login,active FROM users").fetchall(); c.close()
    return [dict(r) for r in rows]

def db_groq_cache_get(file_hash):
    c = _db(); r = c.execute("SELECT analysis_json FROM groq_cache WHERE file_hash=?",(file_hash,)).fetchone(); c.close()
    return r["analysis_json"] if r else None

def db_groq_cache_set(file_hash, json_str):
    c = _db(); c.execute("INSERT OR REPLACE INTO groq_cache (file_hash,analysis_json,cached_at) VALUES (?,?,?)",
        (file_hash,json_str,datetime.now().isoformat())); c.commit(); c.close()

def db_get_blockchain(limit=10):
    c = _db(); rows = c.execute("SELECT * FROM blockchain_records ORDER BY block_index DESC LIMIT ?",(limit,)).fetchall(); c.close()
    return [dict(r) for r in rows]

def db_save_block(block):
    c = _db(); c.execute("INSERT INTO blockchain_records (id,block_index,block_hash,previous_hash,evidence_id,file_hash,uploader,case_id,timestamp) VALUES (?,?,?,?,?,?,?,?,?)",
        (secrets.token_hex(8),block["block_index"],block["block_hash"],block["previous_hash"],
         block.get("evidence_id",""),block.get("file_hash",""),block.get("uploader",""),block.get("case_id",""),block["timestamp"])); c.commit(); c.close()

def db_last_block():
    c = _db(); r = c.execute("SELECT * FROM blockchain_records ORDER BY block_index DESC LIMIT 1").fetchone(); c.close()
    return dict(r) if r else None

# ═══════════════════════════════════════════════════════════════════════════════
# █████  ██    ██ ████████ ██   ██
# ██   ██ ██    ██    ██    ██   ██
# ███████ ██    ██    ██    ███████
# ██   ██ ██    ██    ██    ██   ██
# ██   ██  ██████     ██    ██   ██
# ═══════════════════════════════════════════════════════════════════════════════

_SECRET = os.getenv("SECRET_KEY", secrets.token_hex(32))
_TOKEN_HOURS = int(os.getenv("TOKEN_EXPIRY_HOURS", 8))
MAX_FAIL = 5

ROLE_PERMS = {
    "admin":        ["all","admin_panel","manage_cases","upload_evidence","view_reports","ai_analysis"],
    "analyst":      ["manage_cases","upload_evidence","view_reports","ai_analysis"],
    "investigator": ["manage_cases","upload_evidence","view_reports"],
    "officer":      ["upload_evidence","view_reports"],
    "legal":        ["view_reports","manage_cases"],
}

def auth_login(username, password):
    if not username or not password: return None, "Username and password required"
    user = db_get_user(username)
    if not user: return None, "Invalid credentials"
    if not user.get("active"): return None, "Account deactivated"
    if user.get("failed_attempts", 0) >= MAX_FAIL: return None, f"Account locked after {MAX_FAIL} failed attempts"
    if not check_password_hash(user["password_hash"], password):
        db_inc_failed(username)
        return None, f"Invalid credentials. {MAX_FAIL - user.get('failed_attempts',0) - 1} attempts remaining."
    db_reset_failed(username); db_update_login(username)
    db_log(username, "LOGIN", "auth", user["id"], "Successful login")
    return user, ""

def auth_make_token(user):
    return jwt.encode({
        "sub": user["id"], "username": user["username"], "role": user["role"],
        "clearance_level": user["clearance_level"], "full_name": user["full_name"],
        "department": user["department"], "badge_number": user.get("badge_number",""),
        "exp": datetime.utcnow() + timedelta(hours=_TOKEN_HOURS),
    }, _SECRET, algorithm="HS256")

def auth_verify_token(token):
    try: return jwt.decode(token, _SECRET, algorithms=["HS256"])
    except: return None

def auth_has_perm(role, perm):
    p = ROLE_PERMS.get(role, [])
    return "all" in p or perm in p

def auth_clearance_label(level):
    return {1:"RESTRICTED",2:"CONFIDENTIAL",3:"SECRET",4:"SECRET",5:"TOP SECRET"}.get(level,"RESTRICTED")

def auth_role_color(role):
    return {"admin":"danger","analyst":"success","investigator":"warning","officer":"info","legal":"secondary"}.get(role,"primary")

# ═══════════════════════════════════════════════════════════════════════════════
# ██████  ██       ██████   ██████ ██   ██  ██████ ██   ██  █████  ██ ███    ██
# ██   ██ ██      ██    ██ ██      ██  ██  ██      ██   ██ ██   ██ ██ ████   ██
# ██████  ██      ██    ██ ██      █████   ██      ███████ ███████ ██ ██ ██  ██
# ██   ██ ██      ██    ██ ██      ██  ██  ██      ██   ██ ██   ██ ██ ██  ██ ██
# ██████  ███████  ██████   ██████ ██   ██  ██████ ██   ██ ██   ██ ██ ██   ████
# ═══════════════════════════════════════════════════════════════════════════════

GENESIS = "0" * 64

def bc_anchor(evidence_id, file_hash, uploader, case_id=""):
    last = db_last_block()
    prev = last["block_hash"] if last else GENESIS
    idx  = (last["block_index"] + 1) if last else 0
    ts   = datetime.utcnow().isoformat()
    raw  = json.dumps({"index":idx,"prev":prev,"eid":evidence_id,"fhash":file_hash,"ts":ts,"uploader":uploader},sort_keys=True)
    bh   = hashlib.sha256(raw.encode()).hexdigest()
    tx   = "0x" + hashlib.sha256((bh + secrets.token_hex(4)).encode()).hexdigest()
    db_save_block({"block_index":idx,"block_hash":bh,"previous_hash":prev,
                   "evidence_id":evidence_id,"file_hash":file_hash,"uploader":uploader,"case_id":case_id,"timestamp":ts})
    return {"success":True,"block_index":idx,"block_hash":bh,"tx_hash":tx,"timestamp":ts}

def bc_stats():
    records = db_get_blockchain(10000)
    if not records: return {"total_blocks":0,"latest_block":None}
    latest = max(records, key=lambda r: r["block_index"])
    return {"total_blocks":len(records),"latest_block":latest["block_index"],
            "latest_hash":latest["block_hash"][:16]+"...","latest_timestamp":latest["timestamp"]}

def bc_verify_chain():
    records = sorted(db_get_blockchain(10000), key=lambda r: r["block_index"])
    if not records: return {"valid":True,"blocks":0,"message":"Empty chain"}
    errors = []
    for i, b in enumerate(records):
        prev = records[i-1]["block_hash"] if i > 0 else GENESIS
        raw  = json.dumps({"index":b["block_index"],"prev":b["previous_hash"],"eid":b.get("evidence_id",""),
                           "fhash":b.get("file_hash",""),"ts":b["timestamp"],"uploader":b.get("uploader","")},sort_keys=True)
        expected = hashlib.sha256(raw.encode()).hexdigest()
        if expected != b["block_hash"]: errors.append(f"Block #{b['block_index']}: hash mismatch")
        if b["previous_hash"] != prev:  errors.append(f"Block #{b['block_index']}: broken chain link")
    return {"valid":not errors,"blocks":len(records),"errors":errors,
            "message":"Chain integrity verified ✓" if not errors else f"{len(errors)} errors"}

# ═══════════════════════════════════════════════════════════════════════════════
# █████  ██
# ██   ██ ██
# ███████ ██
# ██   ██ ██
# ██   ██ ██
# ═══════════════════════════════════════════════════════════════════════════════

GROQ_KEY   = os.getenv("GROQ_API_KEY","")
GROQ_URL   = "https://api.groq.com/openai/v1/chat/completions"
GROQ_MODEL = "llama-3.3-70b-versatile"

_MAGIC = {b"MZ":("EXECUTABLE","Windows PE"),b"\x7fELF":("EXECUTABLE","Linux ELF"),
          b"%PDF":("DOCUMENT","PDF"),b"\xd0\xcf\x11\xe0":("DOCUMENT","MS Office"),
          b"PK\x03\x04":("ARCHIVE","ZIP"),b"Rar!":("ARCHIVE","RAR"),b"\x1f\x8b":("ARCHIVE","GZIP"),
          b"\xff\xd8\xff":("IMAGE","JPEG"),b"\x89PNG\r\n":("IMAGE","PNG"),b"GIF8":("IMAGE","GIF"),
          b"\xd4\xc3\xb2\xa1":("PCAP","Network Capture"),b"SQLite format 3":("DATABASE","SQLite"),
          b"ID3":("AUDIO","MP3"),b"RIFF":("AUDIO","WAV")}
_EXT = {"exe":"EXECUTABLE","dll":"EXECUTABLE","bat":"SCRIPT","ps1":"SCRIPT","py":"SCRIPT",
        "js":"SCRIPT","php":"SCRIPT","pdf":"DOCUMENT","doc":"DOCUMENT","docx":"DOCUMENT",
        "jpg":"IMAGE","jpeg":"IMAGE","png":"IMAGE","zip":"ARCHIVE","rar":"ARCHIVE",
        "7z":"ARCHIVE","pcap":"PCAP","mp4":"VIDEO","avi":"VIDEO","mp3":"AUDIO","wav":"AUDIO",
        "db":"DATABASE","sqlite":"DATABASE"}
_SIGS = [
    (b"powershell","HIGH","PowerShell execution"),(b"cmd.exe","HIGH","Command shell"),
    (b"CreateRemoteThread","HIGH","Remote thread injection"),(b"VirtualAlloc","MEDIUM","Memory allocation"),
    (b"WScript.Shell","HIGH","Windows Script Host"),(b"eval(","MEDIUM","Dynamic eval"),
    (b"exec(","MEDIUM","Dynamic exec"),(b"<script>","MEDIUM","Embedded script"),
    (b"<?php","MEDIUM","PHP code"),(b"backdoor","CRITICAL","Backdoor string"),
    (b"ransomware","CRITICAL","Ransomware string"),(b"keylog","HIGH","Keylogger indicator"),
    (b".onion","HIGH","Tor hidden service"),(b"HKEY_","MEDIUM","Registry access"),
    (b"CreateService","HIGH","Service creation / persistence"),
]

def ai_detect_type(data, filename):
    for magic,(ft,desc) in _MAGIC.items():
        if data[:len(magic)] == magic: return ft, desc
    ext = filename.rsplit(".",1)[-1].lower() if "." in filename else ""
    return _EXT.get(ext,"UNKNOWN"), f"{ext.upper()} file" if ext else "Unknown"

def ai_hashes(data):
    return {"md5":hashlib.md5(data).hexdigest(),"sha1":hashlib.sha1(data).hexdigest(),
            "sha256":hashlib.sha256(data).hexdigest(),"sha512":hashlib.sha512(data).hexdigest()}

def ai_entropy(data):
    s = data[:8192]
    if not s: return 0.0
    freq = {}
    for b in s: freq[b] = freq.get(b,0)+1
    n = len(s)
    return -sum((c/n)*math.log2(c/n) for c in freq.values())

def ai_scan_sigs(data):
    dl = data.lower(); found = []
    for pattern, sev, desc in _SIGS:
        if pattern.lower() in dl:
            found.append({"pattern":pattern.decode(),"severity":sev,"description":desc})
    return found

def ai_risk_score(ftype, entropy, sigs):
    score = {"EXECUTABLE":0.4,"SCRIPT":0.35,"ARCHIVE":0.2,"DOCUMENT":0.1,
             "PCAP":0.15,"DATABASE":0.1,"IMAGE":0.05,"UNKNOWN":0.25}.get(ftype,0.1)
    if entropy > 7.5: score += 0.3
    elif entropy > 6.5: score += 0.15
    for s in sigs:
        score += {"CRITICAL":0.5,"HIGH":0.3,"MEDIUM":0.15,"LOW":0.05}.get(s["severity"],0)
    return min(score, 1.0)

def ai_score_to_level(score):
    if score>=0.8: return "CRITICAL"
    if score>=0.6: return "HIGH"
    if score>=0.35: return "MEDIUM"
    if score>=0.1: return "LOW"
    return "MINIMAL"

def ai_call_groq(summary):
    if not GROQ_KEY: return None
    prompt = f"""You are a senior digital forensics analyst at India's Central Forensic Science Laboratory.
Analyze this evidence file summary and provide a forensic assessment.

FILE: {summary['filename']} | Type: {summary['ftype']} | Size: {summary['size']:,} bytes
SHA-256: {summary['sha256'][:32]}... | Entropy: {summary['entropy']:.2f}/8.0
Local Risk Score: {summary['local_risk']:.2f}/1.0 | Suspicious Patterns: {len(summary['sigs'])}
Patterns Found: {[s['description'] for s in summary['sigs'][:4]]}

Respond ONLY with this JSON (no markdown, no extra text):
{{"threat_level":"MINIMAL|LOW|MEDIUM|HIGH|CRITICAL","confidence":0.0,"summary":"2-3 sentence forensic summary",
"key_findings":["finding1","finding2"],"threats":["threat1"],"court_admissibility":"Section 65B assessment",
"recommendations":["action1","action2"]}}"""
    try:
        r = requests.post(GROQ_URL,
            headers={"Authorization":f"Bearer {GROQ_KEY}","Content-Type":"application/json"},
            json={"model":GROQ_MODEL,"messages":[{"role":"user","content":prompt}],"temperature":0.1,"max_tokens":700},
            timeout=25)
        r.raise_for_status()
        content = r.json()["choices"][0]["message"]["content"].strip()
        if content.startswith("```"): content = content.split("```")[1].lstrip("json").strip()
        return json.loads(content)
    except Exception as e:
        logger.warning(f"Groq API: {e}"); return None

def ai_fallback(summary, sigs):
    level = ai_score_to_level(summary["local_risk"])
    findings = []
    if summary["entropy"] > 7.0: findings.append(f"High entropy ({summary['entropy']:.2f}) — possible encryption/packing")
    findings += [s["description"] for s in sigs[:3]]
    if not findings: findings = ["No obvious malicious indicators in local scan"]
    recs = (["Isolate immediately","Submit to VirusTotal","Notify senior analyst"] if level in ("HIGH","CRITICAL")
            else ["Run additional scans","Verify file source","Document chain of custody"] if level=="MEDIUM"
            else ["Standard evidence processing approved"])
    return {"threat_level":level,"confidence":0.70,
            "summary":f"Local scan of {summary['filename']} ({summary['ftype']}, {summary['size']:,} bytes). Risk: {summary['local_risk']:.2f}. Groq AI unavailable — local analysis only.",
            "key_findings":findings,"threats":[s["description"] for s in sigs if s["severity"] in ("HIGH","CRITICAL")] or ["None detected"],
            "court_admissibility":"Hash values recorded. Section 65B chain of custody initiated. Full AI analysis needed for court submission.",
            "recommendations":recs,"_local_only":True}

def ai_analyze(file_data, filename):
    t0 = time.time()
    hashes = ai_hashes(file_data)
    ftype, fdesc = ai_detect_type(file_data, filename)
    entropy = ai_entropy(file_data)
    sigs = ai_scan_sigs(file_data)
    local_risk = ai_risk_score(ftype, entropy, sigs)
    summary = {"filename":filename,"size":len(file_data),"ftype":ftype,"sha256":hashes["sha256"],
               "entropy":entropy,"sigs":sigs,"local_risk":local_risk}
    # Cache check
    groq = None
    cached = db_groq_cache_get(hashes["sha256"])
    if cached:
        try: groq = json.loads(cached); groq["_from_cache"] = True
        except: pass
    if groq is None:
        groq = ai_call_groq(summary)
        if groq: db_groq_cache_set(hashes["sha256"], json.dumps(groq))
    if groq is None:
        groq = ai_fallback(summary, sigs)
    return {
        "filename":filename,"file_size":len(file_data),"file_type":ftype,"file_type_desc":fdesc,
        "hashes":hashes,"entropy":round(entropy,3),"signatures_found":len(sigs),"signatures":sigs,
        "local_risk_score":round(local_risk,3),
        "risk_level":groq.get("threat_level", ai_score_to_level(local_risk)),
        "confidence":groq.get("confidence",0.70),
        "ai_summary":groq.get("summary",""),
        "key_findings":groq.get("key_findings",[]),
        "threats":groq.get("threats",[]),
        "court_admissibility":groq.get("court_admissibility",""),
        "recommendations":groq.get("recommendations",[]),
        "groq_powered":not groq.get("_local_only",False),
        "from_cache":groq.get("_from_cache",False),
        "processing_time_ms":int((time.time()-t0)*1000),
    }

def ai_groq_narrative(case, evidence_list):
    if not GROQ_KEY: return f"Case {case.get('case_number')} — {len(evidence_list)} evidence items processed. AI narrative unavailable."
    ev_lines = "\n".join([f"- {e['original_filename']} | Risk: {e.get('risk_level','?')} | Type: {e.get('file_type','?')}" for e in evidence_list[:10]])
    prompt = f"""Write a professional 3-paragraph forensic investigation narrative for Indian law enforcement court submission (Section 65B compliant).
Case: {case.get('case_number')} — {case.get('title')} | Type: {case.get('case_type')} | Priority: {case.get('priority')}
Evidence ({len(evidence_list)} items):\n{ev_lines}\nBe formal, precise. No markdown."""
    try:
        r = requests.post(GROQ_URL,
            headers={"Authorization":f"Bearer {GROQ_KEY}","Content-Type":"application/json"},
            json={"model":GROQ_MODEL,"messages":[{"role":"user","content":prompt}],"temperature":0.2,"max_tokens":500},timeout=25)
        r.raise_for_status()
        return r.json()["choices"][0]["message"]["content"].strip()
    except Exception as e:
        logger.warning(f"Groq narrative: {e}")
        return f"Investigation of Case {case.get('case_number')} involving {len(evidence_list)} digital evidence items."

# ═══════════════════════════════════════════════════════════════════════════════
# ██████  ███████ ██████   ██████  ██████  ████████ ███████
# ██   ██ ██      ██   ██ ██    ██ ██   ██    ██    ██
# ██████  █████   ██████  ██    ██ ██████     ██    ███████
# ██   ██ ██      ██      ██    ██ ██   ██    ██         ██
# ██   ██ ███████ ██       ██████  ██   ██    ██    ███████
# ═══════════════════════════════════════════════════════════════════════════════

def rpt_generate(case, evidence_list, narrative="", officer="System"):
    if not REPORTLAB:
        return None, "reportlab not installed"
    fname = f"report_{case.get('case_number','CASE')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    fpath = str(Path("reports") / fname)

    DARK_BLUE = colors.HexColor("#1e3c72")
    GOLD      = colors.HexColor("#c8a217")
    LGray     = colors.HexColor("#f5f5f5")
    MGray     = colors.HexColor("#cccccc")
    RC = {"CRITICAL":colors.HexColor("#c0392b"),"HIGH":colors.HexColor("#e67e22"),
          "MEDIUM":colors.HexColor("#f39c12"),"LOW":colors.HexColor("#27ae60"),
          "MINIMAL":colors.HexColor("#27ae60"),"UNKNOWN":colors.gray}

    S = getSampleStyleSheet()
    sty = {
        "T":  ParagraphStyle("T",  parent=S["Title"],   fontSize=18, textColor=DARK_BLUE, alignment=TA_CENTER, fontName="Helvetica-Bold"),
        "ST": ParagraphStyle("ST", parent=S["Normal"],  fontSize=10, textColor=DARK_BLUE, alignment=TA_CENTER),
        "SH": ParagraphStyle("SH", parent=S["Normal"],  fontSize=11, textColor=colors.white, backColor=DARK_BLUE,
                              fontName="Helvetica-Bold", leftIndent=6, spaceBefore=10, spaceAfter=4),
        "B":  ParagraphStyle("B",  parent=S["Normal"],  fontSize=9,  alignment=TA_JUSTIFY, leading=13),
        "Sm": ParagraphStyle("Sm", parent=S["Normal"],  fontSize=7,  textColor=colors.gray),
        "H":  ParagraphStyle("H",  parent=S["Code"],    fontSize=7,  fontName="Courier"),
        "Bd": ParagraphStyle("Bd", parent=S["Normal"],  fontSize=9,  fontName="Helvetica-Bold"),
    }

    def header_footer(canvas, doc):
        canvas.saveState()
        w, h = A4
        canvas.setFillColor(DARK_BLUE); canvas.rect(0,h-45,w,45,fill=1,stroke=0)
        canvas.setFillColor(GOLD);      canvas.rect(0,h-48,w,3,fill=1,stroke=0)
        canvas.setFillColor(colors.white); canvas.setFont("Helvetica-Bold",11)
        canvas.drawString(0.75*inch,h-26,"COC EVIDENCE MANAGEMENT SYSTEM — GOVERNMENT OF INDIA")
        canvas.setFont("Helvetica",7)
        canvas.drawRightString(w-0.75*inch,h-18,f"Generated: {datetime.now().strftime('%d %b %Y %H:%M IST')}")
        canvas.setFillColor(DARK_BLUE); canvas.rect(0,0,w,26,fill=1,stroke=0)
        canvas.setFillColor(colors.white); canvas.setFont("Helvetica",7)
        canvas.drawString(0.75*inch,8,"Chain of custody maintained — evidence integrity verified via SHA-256 blockchain hash chain")
        canvas.drawRightString(w-0.75*inch,8,f"Page {doc.page}")
        canvas.restoreState()

    doc = SimpleDocTemplate(fpath,pagesize=A4,leftMargin=0.75*inch,rightMargin=0.75*inch,topMargin=1.1*inch,bottomMargin=0.7*inch)
    story = []

    story += [Spacer(1,0.2*inch), Paragraph("DIGITAL FORENSIC INVESTIGATION REPORT",sty["T"]),
              Paragraph("Central Forensic Science Laboratory | Ministry of Home Affairs",sty["ST"]),
              Spacer(1,0.1*inch), HRFlowable(width="100%",thickness=2,color=GOLD), Spacer(1,0.15*inch)]

    ci = [["Case Number:",case.get("case_number","N/A"),"Priority:",case.get("priority","?")],
          ["Title:",case.get("title","N/A"),"Status:",case.get("status","?")],
          ["Type:",case.get("case_type","?").replace("_"," ").title(),"Classification:",case.get("classification","?")],
          ["Date:",datetime.now().strftime("%d %b %Y"),"Evidence Items:",str(len(evidence_list))],
          ["Prepared By:",officer,"Report ID:",secrets.token_hex(4).upper()]]
    ct = Table(ci,colWidths=[1.4*inch,2.2*inch,1.4*inch,1.65*inch])
    ct.setStyle(TableStyle([("FONTNAME",(0,0),(-1,-1),"Helvetica"),("FONTNAME",(0,0),(0,-1),"Helvetica-Bold"),
        ("FONTNAME",(2,0),(2,-1),"Helvetica-Bold"),("FONTSIZE",(0,0),(-1,-1),8),
        ("ROWBACKGROUNDS",(0,0),(-1,-1),[LGray,colors.white]),("GRID",(0,0),(-1,-1),0.4,MGray),
        ("TOPPADDING",(0,0),(-1,-1),4),("BOTTOMPADDING",(0,0),(-1,-1),4)]))
    story += [ct, Spacer(1,0.2*inch)]

    if case.get("description"):
        story += [Paragraph("CASE OVERVIEW",sty["SH"]), Paragraph(case["description"],sty["B"]), Spacer(1,0.1*inch)]
    if narrative:
        story += [Paragraph("INVESTIGATION NARRATIVE",sty["SH"]),
                  Paragraph(narrative.replace("\n","<br/>"),sty["B"]), Spacer(1,0.1*inch)]

    story.append(Paragraph("EVIDENCE INVENTORY",sty["SH"]))
    eh = [["#","Evidence ID","Filename","Type","Risk","Size","Blockchain"]]
    for i,e in enumerate(evidence_list,1):
        sz = e.get("file_size",0); ss = f"{sz/1024:.1f} KB" if sz<1048576 else f"{sz/1048576:.1f} MB"
        eh.append([str(i),e.get("evidence_number","N/A"),e.get("original_filename","N/A")[:28],
                   e.get("file_type","?"),e.get("risk_level","?"),ss,"✓ Anchored" if e.get("blockchain_hash") else "○ Pending"])
    et = Table(eh,colWidths=[0.3*inch,1.3*inch,1.9*inch,0.8*inch,0.75*inch,0.75*inch,0.85*inch])
    es = [("BACKGROUND",(0,0),(-1,0),DARK_BLUE),("TEXTCOLOR",(0,0),(-1,0),colors.white),
          ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),("FONTSIZE",(0,0),(-1,-1),7.5),
          ("ALIGN",(0,0),(-1,-1),"CENTER"),("GRID",(0,0),(-1,-1),0.4,MGray),
          ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white,LGray]),
          ("TOPPADDING",(0,0),(-1,-1),3),("BOTTOMPADDING",(0,0),(-1,-1),3)]
    for i,e in enumerate(evidence_list,1):
        rc = RC.get(e.get("risk_level","UNKNOWN"),colors.gray)
        es += [("TEXTCOLOR",(4,i),(4,i),rc),("FONTNAME",(4,i),(4,i),"Helvetica-Bold")]
    et.setStyle(TableStyle(es)); story += [et, Spacer(1,0.2*inch)]

    story.append(Paragraph("DETAILED EVIDENCE",sty["SH"]))
    for e in evidence_list:
        rc = RC.get(e.get("risk_level","UNKNOWN"),colors.gray)
        story += [Spacer(1,6), Paragraph(f"Evidence: {e.get('evidence_number','N/A')} — {e.get('original_filename','N/A')}",sty["Bd"])]
        dr = [["Risk:",e.get("risk_level","?"),"Type:",e.get("file_type","?")],
              ["Size:",f"{e.get('file_size',0):,} bytes","Uploaded By:",e.get("uploaded_by","?")],
              ["Location:",e.get("location","—"),"Date:",str(e.get("uploaded_at",""))[:16]]]
        dt = Table(dr,colWidths=[0.9*inch,2.3*inch,1.2*inch,2.3*inch])
        dt.setStyle(TableStyle([("FONTNAME",(0,0),(0,-1),"Helvetica-Bold"),("FONTNAME",(2,0),(2,-1),"Helvetica-Bold"),
            ("FONTSIZE",(0,0),(-1,-1),7.5),("GRID",(0,0),(-1,-1),0.3,MGray),
            ("ROWBACKGROUNDS",(0,0),(-1,-1),[LGray,colors.white]),
            ("TOPPADDING",(0,0),(-1,-1),3),("BOTTOMPADDING",(0,0),(-1,-1),3),
            ("TEXTCOLOR",(1,0),(1,0),rc),("FONTNAME",(1,0),(1,0),"Helvetica-Bold")]))
        story.append(dt)
        if e.get("sha256_hash"):
            story += [Spacer(1,3),Paragraph(f"SHA-256: {e['sha256_hash']}",sty["H"]),
                      Paragraph(f"MD5: {e.get('md5_hash','N/A')} | Block: #{e.get('blockchain_block','—')} | TX: {str(e.get('tx_hash',''))[:24]}...",sty["H"])]
        if e.get("ai_summary"):
            story += [Spacer(1,3),Paragraph("AI Assessment:",sty["Bd"]),Paragraph(e["ai_summary"],sty["B"])]
        story.append(HRFlowable(width="100%",thickness=0.5,color=MGray,spaceAfter=3))

    # Section 65B Certificate
    story.append(PageBreak())
    story += [Paragraph("CERTIFICATE UNDER SECTION 65B",sty["T"]),
              Paragraph("Indian Evidence Act, 1872 (as amended by Information Technology Act, 2000)",sty["ST"]),
              Spacer(1,0.15*inch),HRFlowable(width="100%",thickness=2,color=GOLD),Spacer(1,0.15*inch)]
    cert = f"""I, <b>{officer}</b>, being competent to certify the electronic records mentioned herein, do hereby certify that:

1. The electronic records detailed in this report were produced by a computer during the regular course of criminal investigation activities.

2. The computer was regularly used to store and process digital evidence and was operating properly throughout the relevant period.

3. The SHA-256 cryptographic hash values computed and recorded herein constitute forensically sound identifiers of the digital evidence as received and preserved.

4. The blockchain hash chain anchoring each evidence item ensures immutability and tamper-evident storage, meeting chain of custody requirements under applicable Indian law.

5. The information contained in the electronic records was derived from information supplied to the computer in the ordinary course of investigation activities.

<b>Case Reference:</b> {case.get("case_number","N/A")} — {case.get("title","N/A")}
<b>Total Evidence Items Certified:</b> {len(evidence_list)}
<b>Date of Certification:</b> {datetime.now().strftime("%d %B %Y")}"""
    story += [Paragraph(cert,sty["B"]), Spacer(1,0.4*inch)]
    st2 = [["Signature of Certifying Officer:","","Date:"],
           [officer,"",datetime.now().strftime("%d/%m/%Y")],
           ["","",""],["Designation / Badge No.:","","Official Seal:"]]
    sigt = Table(st2,colWidths=[3*inch,0.5*inch,3.15*inch])
    sigt.setStyle(TableStyle([("FONTNAME",(0,0),(-1,-1),"Helvetica"),("FONTNAME",(0,0),(0,0),"Helvetica-Bold"),
        ("FONTNAME",(2,0),(2,0),"Helvetica-Bold"),("FONTSIZE",(0,0),(-1,-1),9),("TOPPADDING",(0,0),(-1,-1),8),
        ("LINEBELOW",(0,1),(0,1),1,colors.black),("LINEBELOW",(2,1),(2,1),1,colors.black)]))
    story += [sigt, Spacer(1,0.2*inch),
              Paragraph("This certificate is issued under Section 65B of the Indian Evidence Act, 1872. The electronic records certified herein are admissible as documentary evidence in any court of law. Tampering with this document constitutes an offence under Section 65 and 66 of the Information Technology Act, 2000.",
                        ParagraphStyle("D",fontSize=7.5,textColor=colors.gray,alignment=TA_JUSTIFY))]

    doc.build(story, onFirstPage=header_footer, onLaterPages=header_footer)
    return fpath, None

# ═══════════════════════════════════════════════════════════════════════════════
# DASH APP
# ═══════════════════════════════════════════════════════════════════════════════

server = Flask(__name__)
server.config["SECRET_KEY"] = _SECRET
server.config["MAX_CONTENT_LENGTH"] = 500 * 1024 * 1024
CORS(server)

app = dash.Dash(__name__, server=server,
    external_stylesheets=[dbc.themes.DARKLY,
        "https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css"],
    suppress_callback_exceptions=True, title="COC — Evidence Management", update_title=None)

CSS = """
body{background:#0d1117} .navbar{background:linear-gradient(135deg,#0d1b2a,#1e3c72)!important;border-bottom:3px solid #c8a217}
.sc{background:linear-gradient(135deg,#1a1a2e,#16213e);border:1px solid rgba(255,255,255,.1);border-radius:12px;transition:transform .2s,box-shadow .2s}
.sc:hover{transform:translateY(-4px);box-shadow:0 8px 25px rgba(79,172,254,.3)}
.sn{font-size:2.4rem;font-weight:900}
.uz{border:2px dashed #4facfe;border-radius:16px;padding:2.5rem;text-align:center;background:rgba(79,172,254,.05);cursor:pointer;transition:all .3s}
.uz:hover{background:rgba(79,172,254,.12);border-color:#00f2fe}
.ec{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:1rem;margin-bottom:.7rem;transition:border-color .2s}
.ec:hover{border-color:#4facfe}
.cb{background:#0d1117;border:1px solid #30363d;border-radius:8px;padding:.7rem;font-family:monospace;font-size:.75rem;margin-bottom:.5rem}
.gl{border-left:4px solid #c8a217}
.sh{color:#4facfe;font-weight:700;border-bottom:1px solid #30363d;padding-bottom:.4rem;margin-bottom:1rem}
"""

RC = {"CRITICAL":"danger","HIGH":"warning","MEDIUM":"warning","LOW":"success","MINIMAL":"success","UNKNOWN":"secondary"}
RI = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🟢","MINIMAL":"⚪","UNKNOWN":"⚫"}
PC = {"CRITICAL":"#dc3545","HIGH":"#fd7e14","MEDIUM":"#ffc107","LOW":"#198754"}

def ic(cls, **kw): return html.I(className=cls, **kw)
def bdg(txt,col="secondary"): return dbc.Badge(txt,color=col,pill=True,className="me-1")
def rbdg(rl): return bdg(f"{RI.get(rl,'⚫')} {rl}", RC.get(rl,"secondary"))
def sh(title,icls="fas fa-circle"): return html.H5([ic(icls+" me-2"),title],className="sh")

def scard(val,label,icls,col="#4facfe",w=3):
    return dbc.Col([html.Div([
        html.Div([ic(icls,style={"fontSize":"2rem","color":col,"opacity":".85"})],className="mb-2"),
        html.Div(str(val),className="sn",style={"color":col}),
        html.Div(label,style={"color":"#8b949e","fontSize":".8rem","textTransform":"uppercase","letterSpacing":"1px"}),
    ],className="sc p-3 text-center")],width=w)

# ── Login ─────────────────────────────────────────────────────────────────────
def login_page():
    portals = [
        ("admin","fas fa-crown","danger","National Coordinator","TOP SECRET · L5","DCP Priya Sharma, IPS"),
        ("analyst","fas fa-microscope","success","Forensic Scientist","SECRET · L4","Dr. Rajesh Kumar Singh"),
        ("investigator","fas fa-search","warning","CBI Investigator","SECRET · L3","Inspector Anita Desai"),
        ("officer","fas fa-shield-alt","info","Field Officer","CONFIDENTIAL · L2","SI Suresh Patel"),
        ("legal","fas fa-balance-scale","secondary","Legal Advisor","SECRET · L3","Adv. Vikram Choudhary"),
    ]
    pbtn = [dbc.Col([dbc.Button([ic(icls+" fa-2x mb-1 d-block mx-auto"),
        html.Strong(role,className="d-block"),html.Small(cl,className="text-muted d-block"),
        html.Small(name,style={"color":"#c8a217"},className="d-block"),
    ], id={"type":"pb","index":u}, color=c, outline=True, className="w-100 py-2 text-center",
       style={"height":"110px","fontSize":".78rem"})],width=12,sm=6,md=4,className="mb-2") for u,icls,c,role,cl,name in portals]

    return dbc.Container([dbc.Row([dbc.Col([
        html.Div([ic("fas fa-shield-halved fa-4x text-primary mb-3"),
                  html.H1("COC EVIDENCE SYSTEM",className="display-5 fw-bold mb-1"),
                  html.P("Chain of Custody · Blockchain · Groq AI",className="text-muted mb-3"),
                  dbc.Badge([ic("fas fa-circle-dot me-1"),"System Operational"],color="success",className="me-2"),
                  dbc.Badge([ic("fas fa-robot me-1"),"Groq AI Active" if GROQ_KEY else "Local AI Mode"],
                            color="success" if GROQ_KEY else "warning"),
                 ],className="text-center mb-4"),
        html.Div(id="la"),
        dbc.Card([dbc.CardBody([
            dbc.InputGroup([dbc.InputGroupText(ic("fas fa-user")),
                dbc.Input(id="lu",placeholder="Username",type="text",n_submit=0,className="bg-dark text-light border-secondary")],className="mb-3"),
            dbc.InputGroup([dbc.InputGroupText(ic("fas fa-lock")),
                dbc.Input(id="lp",placeholder="Password",type="password",n_submit=0,className="bg-dark text-light border-secondary")],className="mb-4"),
            dbc.Button([ic("fas fa-sign-in-alt me-2"),"Secure Login"],id="lb",color="primary",size="lg",className="w-100"),
        ])],className="mb-4 bg-dark border-secondary"),
        html.Hr(style={"borderColor":"#30363d"}),
        html.H6("Quick Access Portals",className="text-center text-muted mb-3"),
        dbc.Row(pbtn),
    ],width=12,md=8,lg=6,className="mx-auto")])],fluid=True)

# ── Main shell ────────────────────────────────────────────────────────────────
def main_page():
    return html.Div([
        dbc.Navbar([dbc.Container([
            dbc.NavbarBrand([ic("fas fa-shield-halved me-2 text-warning"),html.Span("COC ENTERPRISE",className="fw-bold")],className="fs-5"),
            dbc.Nav([html.Div(id="ni",className="d-flex align-items-center gap-3 text-light")],className="ms-auto"),
        ],fluid=True)],dark=True,className="navbar mb-0"),
        html.Div([dbc.Tabs(id="tabs",active_tab="dash",className="px-3 pt-2 border-0",children=[
            dbc.Tab(label="Dashboard",    tab_id="dash",  label_style={"color":"#8b949e"},active_label_style={"color":"#4facfe","fontWeight":"700"}),
            dbc.Tab(label="Upload",       tab_id="up",    label_style={"color":"#8b949e"},active_label_style={"color":"#4facfe","fontWeight":"700"}),
            dbc.Tab(label="Cases",        tab_id="cases", label_style={"color":"#8b949e"},active_label_style={"color":"#4facfe","fontWeight":"700"}),
            dbc.Tab(label="AI Analysis",  tab_id="ai",    label_style={"color":"#8b949e"},active_label_style={"color":"#4facfe","fontWeight":"700"}),
            dbc.Tab(label="Reports",      tab_id="rpt",   label_style={"color":"#8b949e"},active_label_style={"color":"#4facfe","fontWeight":"700"}),
            dbc.Tab(label="Admin",        tab_id="adm",   label_style={"color":"#8b949e"},active_label_style={"color":"#dc3545","fontWeight":"700"}),
        ])],style={"background":"#161b22","borderBottom":"1px solid #30363d"}),
        dbc.Container([html.Div(id="tc",className="py-4")],fluid=True,className="px-4"),
        dcc.Interval(id="ri",interval=30000,n_intervals=0),
    ])

# ── Tab renderers ─────────────────────────────────────────────────────────────
def tab_dashboard(user):
    stats = db_get_stats(); chain = bc_stats(); cases = db_get_cases(user["clearance_level"]); evidence = db_get_evidence(limit=200)
    rc = {}
    for e in evidence: rc[e.get("risk_level","UNKNOWN")] = rc.get(e.get("risk_level","UNKNOWN"),0)+1
    sc = {}
    for c in cases: sc[c.get("status","?")] = sc.get(c.get("status","?"),0)+1
    pie = go.Figure(data=[go.Pie(labels=list(rc.keys()),values=list(rc.values()),hole=0.5,
        marker_colors=["#dc3545","#fd7e14","#ffc107","#198754","#6c757d","#adb5bd"],textfont_size=10)])
    pie.update_layout(paper_bgcolor="rgba(0,0,0,0)",plot_bgcolor="rgba(0,0,0,0)",font_color="#8b949e",
        showlegend=True,legend=dict(bgcolor="rgba(0,0,0,0)"),margin=dict(l=5,r=5,t=5,b=5),height=200)
    bar = go.Figure(data=[go.Bar(x=list(sc.keys()),y=list(sc.values()),marker_color="#4facfe",opacity=.85)])
    bar.update_layout(paper_bgcolor="rgba(0,0,0,0)",plot_bgcolor="rgba(0,0,0,0)",font_color="#8b949e",
        xaxis=dict(gridcolor="#21262d"),yaxis=dict(gridcolor="#21262d"),margin=dict(l=20,r=10,t=5,b=20),height=200)
    ev_rows = [html.Tr([html.Td(e.get("evidence_number","")[:12],style={"fontFamily":"monospace","fontSize":".78rem"}),
        html.Td(e.get("original_filename","")[:25],style={"fontSize":".8rem"}),html.Td(rbdg(e.get("risk_level","?"))),
        html.Td(html.Small(e.get("uploaded_at","")[:16],className="text-muted"))]) for e in evidence[:8]]
    case_rows = [html.Tr([
        html.Td([html.Div(c.get("case_number",""),style={"fontFamily":"monospace","color":"#4facfe","fontSize":".75rem"}),
                 html.Div(c.get("title","")[:35],style={"fontSize":".82rem"})]),
        html.Td(dbc.Badge(c.get("status","?"),color="success" if c.get("status")=="Active" else "secondary",pill=True,style={"fontSize":".7rem"})),
        html.Td(html.Strong(c.get("priority","?"),style={"color":PC.get(c.get("priority","LOW"),"#6c757d"),"fontSize":".8rem"})),
    ]) for c in cases[:5]]
    return html.Div([
        dbc.Alert([html.Strong(f"Welcome, {user['full_name']}"),
            html.Span(f" | {user['department']} | Badge: {user.get('badge_number','-')} | Clearance: {auth_clearance_label(user['clearance_level'])}",className="ms-2 text-muted")],
            color="dark",className="mb-4 border-secondary gl py-2"),
        dbc.Row([scard(stats["total_evidence"],"Total Evidence","fas fa-database","#4facfe"),
                 scard(stats["total_cases"],"Total Cases","fas fa-folder-open","#c8a217"),
                 scard(stats["active_cases"],"Active Cases","fas fa-spinner","#198754"),
                 scard(stats["high_risk"],"High/Critical Risk","fas fa-exclamation-triangle","#dc3545")],className="mb-4"),
        dbc.Row([scard(stats["blockchain_anchored"],"Blockchain Anchored","fas fa-link","#6f42c1"),
                 scard(chain.get("total_blocks",0),"Chain Blocks","fas fa-cubes","#0dcaf0"),
                 scard(stats["total_users"],"Officers","fas fa-users","#fd7e14"),
                 scard("✓ Active" if GROQ_KEY else "Local","Groq AI","fas fa-robot","#198754" if GROQ_KEY else "#ffc107")],className="mb-4"),
        dbc.Row([
            dbc.Col([dbc.Card([dbc.CardBody([sh("Risk Distribution","fas fa-chart-pie"),dcc.Graph(figure=pie,config={"displayModeBar":False})])],className="bg-dark border-secondary h-100")],md=5),
            dbc.Col([dbc.Card([dbc.CardBody([sh("Case Status","fas fa-chart-bar"),dcc.Graph(figure=bar,config={"displayModeBar":False})])],className="bg-dark border-secondary h-100")],md=7),
        ],className="mb-4"),
        dbc.Row([
            dbc.Col([dbc.Card([dbc.CardBody([sh("Recent Evidence","fas fa-file-shield"),
                dbc.Table([html.Thead(html.Tr([html.Th("ID"),html.Th("File"),html.Th("Risk"),html.Th("Time")])),
                           html.Tbody(ev_rows or [html.Tr([html.Td("No evidence yet",colSpan=4,className="text-muted text-center")])])],
                dark=True,hover=True,size="sm")])],className="bg-dark border-secondary")],md=7),
            dbc.Col([dbc.Card([dbc.CardBody([sh("Active Cases","fas fa-folder"),
                dbc.Table([html.Thead(html.Tr([html.Th("Case"),html.Th("Status"),html.Th("Priority")])),
                           html.Tbody(case_rows or [html.Tr([html.Td("No cases",colSpan=3,className="text-muted text-center")])])],
                dark=True,hover=True,size="sm")])],className="bg-dark border-secondary")],md=5),
        ]),
    ])

def tab_upload(user):
    cases = db_get_cases(user["clearance_level"])
    copts = [{"label":f"{c['case_number']} — {c['title'][:35]}","value":c["id"]} for c in cases]
    return html.Div([
        html.H3([ic("fas fa-cloud-upload-alt me-2 text-primary"),"Evidence Upload & Analysis"],className="mb-4"),
        dbc.Row([
            dbc.Col([dbc.Card([dbc.CardBody([
                sh("Upload Evidence Files","fas fa-upload"),
                dcc.Upload(id="eu",children=html.Div([
                    ic("fas fa-cloud-upload-alt fa-3x text-primary mb-3 d-block"),
                    html.H5("Drag & Drop or Click to Upload"),
                    html.Small("All file types · Max 500MB",className="text-muted d-block"),
                    html.Small([ic("fas fa-robot me-1 text-success"),"Groq AI analysis on upload" if GROQ_KEY else "Local forensic analysis"],className="text-muted"),
                ],className="uz"),multiple=True),
                html.Hr(style={"borderColor":"#30363d"}),
                dbc.Row([
                    dbc.Col([dbc.Label("Investigation Case *",className="fw-bold"),
                        dcc.Dropdown(id="uc",options=copts,placeholder="Select case...",className="mb-3",
                            style={"backgroundColor":"#161b22","color":"#c9d1d9"})],md=6),
                    dbc.Col([dbc.Label("Priority",className="fw-bold"),
                        dbc.Select(id="up2",options=[{"label":"🔴 CRITICAL","value":"CRITICAL"},{"label":"🟠 HIGH","value":"HIGH"},
                            {"label":"🟡 MEDIUM","value":"MEDIUM"},{"label":"🟢 LOW","value":"LOW"}],
                            value="MEDIUM",className="bg-dark text-light border-secondary")],md=6),
                ]),
                dbc.Row([
                    dbc.Col([dbc.Label("Classification",className="fw-bold"),
                        dbc.Select(id="ucl",options=[{"label":"🔴 TOP SECRET","value":"TOP_SECRET"},{"label":"🟠 SECRET","value":"SECRET"},
                            {"label":"🟡 CONFIDENTIAL","value":"CONFIDENTIAL"},{"label":"🟢 RESTRICTED","value":"RESTRICTED"}],
                            value="CONFIDENTIAL",className="bg-dark text-light border-secondary")],md=6),
                    dbc.Col([dbc.Label("Seizure Location",className="fw-bold"),
                        dbc.Input(id="ul",placeholder="e.g. Accused residence, Delhi",className="bg-dark text-light border-secondary")],md=6),
                ],className="mt-3"),
                dbc.Row([dbc.Col([dbc.Label("Description",className="fw-bold"),
                    dbc.Textarea(id="ud",rows=3,placeholder="Context, relevance, how obtained...",className="bg-dark text-light border-secondary")])],className="mt-3"),
            ])],className="bg-dark border-secondary")],md=8),
            dbc.Col([dbc.Card([dbc.CardBody([
                sh("Status","fas fa-info-circle"),
                html.Div(id="us",children=[html.Div([
                    ic("fas fa-shield-check fa-3x text-success mb-3 d-block text-center"),
                    html.P("All systems ready",className="text-center text-muted"),
                    html.Hr(style={"borderColor":"#30363d"}),
                    html.Small([ic("fas fa-check text-success me-2"),"SHA-256 + MD5 hashing"]),html.Br(),
                    html.Small([ic("fas fa-check text-success me-2"),"AI threat analysis"]),html.Br(),
                    html.Small([ic("fas fa-check text-success me-2"),"Blockchain anchoring"]),html.Br(),
                    html.Small([ic("fas fa-check text-success me-2"),"Section 65B compliance"]),html.Br(),
                    html.Small([ic("fas fa-check text-success me-2"),"Audit log entry"]),
                ])]),
            ])],className="bg-dark border-secondary")],md=4),
        ]),
        html.Div(id="ur",className="mt-4"),
    ])

def tab_cases(user):
    cases = db_get_cases(user["clearance_level"])
    can = auth_has_perm(user["role"],"manage_cases")
    cards = []
    for c in cases:
        pc = PC.get(c.get("priority","LOW"),"#6c757d")
        ev_n = len(db_get_evidence(c["id"]))
        cards.append(dbc.Card([dbc.CardBody([dbc.Row([
            dbc.Col([
                html.Div([html.Span(c.get("case_number",""),style={"fontFamily":"monospace","color":"#4facfe","fontSize":".8rem"}),
                          html.Span(" | ",className="text-muted"),
                          dbc.Badge(c.get("status","?"),color="success" if c.get("status")=="Active" else "secondary",pill=True,style={"fontSize":".7rem"})]),
                html.H6(c.get("title",""),className="mb-1 mt-1"),
                html.Small(c.get("description","")[:90]+"..." if len(c.get("description",""))>90 else c.get("description",""),className="text-muted"),
            ],md=7),
            dbc.Col([
                html.Strong(c.get("priority","?"),style={"color":pc,"fontSize":".9rem"}),
                html.Div([bdg(c.get("classification","?"),"dark"),bdg(c.get("case_type","?").replace("_"," ").title())],className="mt-1"),
                html.Small([ic("fas fa-file me-1 text-muted"),f"{ev_n} evidence items"],className="text-muted d-block mt-1"),
                html.Small(c.get("created_at","")[:10],className="text-muted"),
            ],md=3),
            dbc.Col([dbc.ButtonGroup([
                dbc.Button(ic("fas fa-eye"),id={"type":"vc","index":c["id"]},color="primary",outline=True,size="sm"),
                dbc.Button(ic("fas fa-file-pdf"),id={"type":"rc","index":c["id"]},color="danger",outline=True,size="sm"),
            ],vertical=True)],md=2,className="d-flex align-items-center justify-content-end"),
        ])])],className="bg-dark border-secondary mb-3"))

    modal = dbc.Modal([
        dbc.ModalHeader(dbc.ModalTitle("Create New Case")),
        dbc.ModalBody([html.Div(id="cca"),
            dbc.Label("Title *"),dbc.Input(id="nct",className="bg-dark text-light border-secondary mb-3"),
            dbc.Label("Type"),dbc.Select(id="nctype",options=[
                {"label":"Cyber Terrorism / APT","value":"cyber_terrorism"},{"label":"Financial Cybercrime","value":"financial_cybercrime"},
                {"label":"Digital Murder Evidence","value":"digital_murder"},{"label":"General","value":"general"}],
                value="general",className="bg-dark text-light border-secondary mb-3"),
            dbc.Row([
                dbc.Col([dbc.Label("Priority"),dbc.Select(id="ncp",options=[{"label":x,"value":x} for x in ["CRITICAL","HIGH","MEDIUM","LOW"]],value="MEDIUM",className="bg-dark text-light border-secondary")],md=6),
                dbc.Col([dbc.Label("Classification"),dbc.Select(id="ncc",options=[{"label":x,"value":x} for x in ["TOP_SECRET","SECRET","CONFIDENTIAL","RESTRICTED"]],value="CONFIDENTIAL",className="bg-dark text-light border-secondary")],md=6),
            ],className="mb-3"),
            dbc.Label("Description"),dbc.Textarea(id="ncd",rows=3,className="bg-dark text-light border-secondary"),
        ]),
        dbc.ModalFooter([dbc.Button("Cancel",id="ccb",color="secondary",outline=True),
                         dbc.Button([ic("fas fa-plus me-1"),"Create"],id="cfcb",color="primary")]),
    ],id="ccm",is_open=False)

    return html.Div([
        dbc.Row([dbc.Col([html.H3([ic("fas fa-folder-open me-2 text-warning"),"Case Management"])],md=8),
                 dbc.Col([dbc.Button([ic("fas fa-plus me-1"),"New Case"],id="ocb",color="primary",disabled=not can,className="float-end")],md=4)],className="mb-4"),
        modal,html.Div(id="car"),
        html.Div(cards if cards else [dbc.Alert("No cases found. Create your first case.",color="info")]),
    ])

def tab_ai(user):
    evidence = db_get_evidence(limit=200)
    hr = [e for e in evidence if e.get("risk_level") in ("HIGH","CRITICAL")]
    tc = {}
    for e in evidence: tc[e.get("risk_level","UNKNOWN")] = tc.get(e.get("risk_level","UNKNOWN"),0)+1
    cards = []
    for e in evidence[:12]:
        rl = e.get("risk_level","UNKNOWN")
        cards.append(dbc.Card([dbc.CardBody([dbc.Row([
            dbc.Col([html.Div([rbdg(rl),bdg(e.get("file_type","?"),"info")]),
                html.Strong(e.get("original_filename","?")[:40],className="d-block mt-1"),
                html.Small(e.get("ai_summary","No analysis")[:120]+"..." if len(e.get("ai_summary",""))>120 else e.get("ai_summary","No analysis"),className="text-muted"),
            ],md=8),
            dbc.Col([html.Small([ic("fas fa-hashtag me-1 text-muted"),html.Code(e.get("sha256_hash","")[:20]+"...",style={"fontSize":".7rem","color":"#8b949e"})],className="d-block"),
                html.Small(f"Block #{e.get('blockchain_block','—')}",className="text-muted d-block"),
                html.Small(f"Score: {e.get('risk_score',0):.2f}",className="text-muted d-block"),
            ],md=4),
        ])])],className="bg-dark border-secondary ec"))

    chain_blocks = []
    for r in db_get_blockchain(8):
        chain_blocks.append(html.Div([
            html.Small(f"Block #{r['block_index']}",className="text-warning fw-bold"),html.Br(),
            html.Small(html.Code(r["block_hash"][:24]+"...",style={"fontSize":".65rem","color":"#8b949e"})),html.Br(),
            html.Small(r.get("evidence_id","?")[:14],className="text-muted"),html.Br(),
            html.Small(r["timestamp"][:16],className="text-muted"),
        ],className="cb"))

    return html.Div([
        html.H3([ic("fas fa-robot me-2 text-success"),"AI Analysis Center"],className="mb-4"),
        dbc.Alert([ic("fas fa-robot me-2"),html.Strong("Groq AI Active — "),f"Model: {GROQ_MODEL} | Cached in SQLite"] if GROQ_KEY else
                  [ic("fas fa-exclamation-triangle me-2"),html.Strong("No Groq Key — "),
                   html.Span(["Local forensic analysis running. Add ",html.Code("GROQ_API_KEY"),
                              " to .env for AI-powered analysis."])],
                  color="success" if GROQ_KEY else "warning",className="mb-4"),
        dbc.Row([scard(len(evidence),"Analyzed","fas fa-database","#4facfe",3),
                 scard(len(hr),"High/Critical","fas fa-exclamation-triangle","#dc3545",3),
                 scard(tc.get("CRITICAL",0),"Critical Items","fas fa-skull","#dc3545",3),
                 scard(tc.get("MINIMAL",0)+tc.get("LOW",0),"Clean/Low Risk","fas fa-check-circle","#198754",3)],className="mb-4"),
        dbc.Row([
            dbc.Col([dbc.Card([dbc.CardBody([sh("Evidence Analysis Log","fas fa-list-check"),
                html.Div(cards if cards else [html.P("Upload evidence to see results.",className="text-muted")])])],className="bg-dark border-secondary")],md=8),
            dbc.Col([dbc.Card([dbc.CardBody([sh("Blockchain Chain","fas fa-cubes"),
                html.Div(chain_blocks if chain_blocks else [html.P("No blocks yet.",className="text-muted")])])],className="bg-dark border-secondary")],md=4),
        ]),
    ])

def tab_reports(user):
    cases = db_get_cases(user["clearance_level"])
    copts = [{"label":f"{c['case_number']} — {c['title'][:35]}","value":c["id"]} for c in cases]
    return html.Div([
        html.H3([ic("fas fa-file-pdf me-2 text-danger"),"Report Generation"],className="mb-4"),
        dbc.Row([
            dbc.Col([dbc.Card([dbc.CardBody([
                sh("Generate Court-Ready Report","fas fa-file-contract"),
                dbc.Label("Select Case *",className="fw-bold"),
                dcc.Dropdown(id="rcs",options=copts,placeholder="Select case...",className="mb-3",style={"backgroundColor":"#161b22"}),
                dbc.Label("Include"),
                dbc.Checklist(id="roi",options=[
                    {"label":" Groq AI narrative" if GROQ_KEY else " Local narrative","value":"ai"},
                    {"label":" Detailed evidence analysis","value":"detail"},
                    {"label":" Blockchain verification proof","value":"bc"},
                ],value=["ai","detail","bc"],className="mb-4"),
                dbc.Button([ic("fas fa-file-pdf me-2"),"Generate PDF Report"],id="grb",color="danger",size="lg",className="w-100"),
                html.Div(id="rs",className="mt-3"),
            ])],className="bg-dark border-secondary")],md=6),
            dbc.Col([dbc.Card([dbc.CardBody([
                sh("Report Features","fas fa-info-circle"),
                dbc.ListGroup([
                    dbc.ListGroupItem([ic("fas fa-check text-success me-2"),"Court-admissible PDF format"],className="bg-dark border-secondary"),
                    dbc.ListGroupItem([ic("fas fa-check text-success me-2"),"Section 65B certificate included"],className="bg-dark border-secondary"),
                    dbc.ListGroupItem([ic("fas fa-check text-success me-2"),"SHA-256 hash verification table"],className="bg-dark border-secondary"),
                    dbc.ListGroupItem([ic("fas fa-check text-success me-2"),"Blockchain anchoring proof"],className="bg-dark border-secondary"),
                    dbc.ListGroupItem([ic("fas fa-robot text-success me-2" if GROQ_KEY else "fas fa-robot text-warning me-2"),
                                       "Groq AI case narrative" if GROQ_KEY else "Local case narrative"],className="bg-dark border-secondary"),
                    dbc.ListGroupItem([ic("fas fa-check text-success me-2"),"Government letterhead & seal"],className="bg-dark border-secondary"),
                ],flush=True),
            ])],className="bg-dark border-secondary")],md=6),
        ]),
    ])

def tab_admin(user):
    if user["role"] != "admin":
        return dbc.Alert([ic("fas fa-lock me-2"),"Admin access required"],color="danger")
    users = db_get_users(); logs = db_get_logs(25); cv = bc_verify_chain()
    urows = [html.Tr([html.Td(u["username"],style={"fontFamily":"monospace"}),html.Td(u["full_name"][:25]),
        html.Td(dbc.Badge(u["role"],color=auth_role_color(u["role"]),pill=True)),html.Td(u["department"][:20],className="small text-muted"),
        html.Td(str(u.get("last_login",""))[:16] or "Never",className="small text-muted"),
        html.Td(dbc.Badge("Active" if u.get("active") else "Off",color="success" if u.get("active") else "secondary",pill=True))]) for u in users]
    lrows = [html.Tr([html.Td(l.get("timestamp","")[:16],className="small text-muted"),
        html.Td(l.get("username","?"),style={"fontFamily":"monospace","fontSize":".8rem"}),
        html.Td(l.get("action","?"),className="small"),html.Td(l.get("details","")[:50],className="small text-muted")]) for l in logs]
    return html.Div([
        html.H3([ic("fas fa-cog me-2 text-danger"),"System Administration"],className="mb-4"),
        dbc.Row([
            dbc.Col([dbc.Card([dbc.CardBody([html.H6([ic("fas fa-link me-2 text-primary"),"Blockchain Integrity"],className="mb-3"),
                dbc.Alert([ic("fas fa-check-circle me-2") if cv["valid"] else ic("fas fa-times-circle me-2"),
                    html.Strong("Chain Valid ✓" if cv["valid"] else "Chain Error!"),
                    f" | {cv.get('blocks',0)} blocks | {cv.get('message','')}"],color="success" if cv["valid"] else "danger"),
            ])],className="bg-dark border-secondary")],md=6),
            dbc.Col([dbc.Card([dbc.CardBody([html.H6([ic("fas fa-robot me-2 text-success"),"Groq AI"],className="mb-3"),
                dbc.Alert([ic("fas fa-check-circle me-2") if GROQ_KEY else ic("fas fa-exclamation-triangle me-2"),
                    f"Model: {GROQ_MODEL} | Key: {'Set ✓' if GROQ_KEY else 'Not set — local mode'}"],color="success" if GROQ_KEY else "warning"),
            ])],className="bg-dark border-secondary")],md=6),
        ],className="mb-4"),
        dbc.Card([dbc.CardBody([sh("System Users","fas fa-users"),dbc.Table([
            html.Thead(html.Tr([html.Th("Username"),html.Th("Name"),html.Th("Role"),html.Th("Department"),html.Th("Last Login"),html.Th("Status")])),
            html.Tbody(urows)],dark=True,hover=True,size="sm",responsive=True)])],className="bg-dark border-secondary mb-4"),
        dbc.Card([dbc.CardBody([sh("Audit Log","fas fa-history"),dbc.Table([
            html.Thead(html.Tr([html.Th("Time"),html.Th("User"),html.Th("Action"),html.Th("Details")])),
            html.Tbody(lrows or [html.Tr([html.Td("No logs",colSpan=4,className="text-muted text-center")])])],
            dark=True,hover=True,size="sm",responsive=True)])],className="bg-dark border-secondary"),
    ])

# ── App layout ─────────────────────────────────────────────────────────────────
app.layout = html.Div([
    dcc.Store(id="ss",storage_type="session"),
    dcc.Location(id="url"),
    html.Div(id="pc"),
    dcc.Download(id="rd"),
])
app.index_string = app.index_string.replace("{%css%}", "{%css%}\n<style>" + CSS + "</style>")

# ── Callbacks ──────────────────────────────────────────────────────────────────
@app.callback(Output("pc","children"), Input("ss","data"))
def route(s):
    if s and s.get("tok") and auth_verify_token(s["tok"]): return main_page()
    return login_page()

@app.callback(Output("ni","children"), Input("ss","data"))
def navbar(s):
    if not s or not s.get("tok"): raise PreventUpdate
    u = auth_verify_token(s["tok"])
    if not u: raise PreventUpdate
    return [html.Span([ic("fas fa-user-circle me-1"),u["full_name"]],style={"fontSize":".85rem"}),
            dbc.Badge(u["role"],color=auth_role_color(u["role"]),pill=True),
            dbc.Badge(auth_clearance_label(u["clearance_level"]),color="dark",pill=True),
            dbc.Button(ic("fas fa-sign-out-alt"),id="lob",color="danger",outline=True,size="sm")]

@app.callback(Output("ss","data"), Output("la","children"),
    Input("lb","n_clicks"), Input({"type":"pb","index":ALL},"n_clicks"),
    State("lu","value"), State("lp","value"), prevent_initial_call=True)
def do_login(mc, pc, uname, pwd):
    ctx = callback_context
    if not ctx.triggered: raise PreventUpdate
    tid = ctx.triggered[0]["prop_id"]
    if '"type":"pb"' in tid:
        idx = json.loads(tid.split(".")[0])["index"]
        uname, pwd = idx, {"admin":"admin123","analyst":"analyst123","investigator":"invest123","officer":"officer123","legal":"legal123"}.get(idx,"")
    user, err = auth_login(uname or "", pwd or "")
    if not user: return {}, dbc.Alert([ic("fas fa-times-circle me-2"),err],color="danger",dismissable=True)
    return {"tok": auth_make_token(user)}, dbc.Alert([ic("fas fa-check-circle me-2"),f"Welcome, {user['full_name']}!"],color="success",duration=2000)

@app.callback(Output("ss","data",allow_duplicate=True), Input("lob","n_clicks"), prevent_initial_call=True)
def logout(n):
    if n: return {}
    raise PreventUpdate

@app.callback(Output("tc","children"), Input("tabs","active_tab"), Input("ri","n_intervals"), State("ss","data"))
def render_tab(tab, _, s):
    if not s or not s.get("tok"): raise PreventUpdate
    u = auth_verify_token(s["tok"])
    if not u: return dbc.Alert("Session expired. Please log in again.",color="warning")
    return {"dash":tab_dashboard,"up":tab_upload,"cases":tab_cases,"ai":tab_ai,"rpt":tab_reports,"adm":tab_admin}.get(tab, lambda u: html.Div())(u)

@app.callback(Output("us","children"), Output("ur","children"),
    Input("eu","contents"), State("eu","filename"), State("uc","value"),
    State("up2","value"), State("ucl","value"), State("ul","value"), State("ud","value"), State("ss","data"),
    prevent_initial_call=True)
def handle_upload(contents, filenames, case_id, priority, classification, location, description, s):
    if not contents: raise PreventUpdate
    u = auth_verify_token((s or {}).get("tok",""))
    if not u: return dbc.Alert("Unauthorized",color="danger"), html.Div()
    if not case_id: return dbc.Alert([ic("fas fa-exclamation me-2"),"Select a case first"],color="warning"), html.Div()
    if isinstance(contents, str): contents, filenames = [contents], [filenames]
    cards = []
    for content, filename in zip(contents, filenames):
        try:
            file_data = base64.b64decode(content.split(",",1)[1])
        except Exception as e:
            cards.append(dbc.Alert(f"Read error {filename}: {e}",color="danger")); continue
        analysis = ai_analyze(file_data, filename)
        eid = f"EVID-{datetime.now().strftime('%Y%m%d%H%M%S')}-{secrets.token_hex(3).upper()}"
        bc = bc_anchor(eid, analysis["hashes"]["sha256"], u["username"], case_id)
        evn = f"EV-{datetime.now().strftime('%Y%m')}-{secrets.token_hex(3).upper()}"
        saved = db_save_evidence({"id":eid,"evidence_number":evn,"filename":secure_filename(filename),"original_filename":filename,
            "file_size":len(file_data),"file_type":analysis["file_type"],"sha256_hash":analysis["hashes"]["sha256"],
            "md5_hash":analysis["hashes"]["md5"],"case_id":case_id,"uploaded_by":u["username"],
            "priority":priority or "MEDIUM","classification":classification or "CONFIDENTIAL","location":location or "",
            "description":description or "","risk_level":analysis["risk_level"],"risk_score":analysis["local_risk_score"],
            "ai_summary":analysis["ai_summary"],"ai_threats":json.dumps(analysis["threats"]),
            "ai_recommendations":json.dumps(analysis["recommendations"]),"processing_time_ms":analysis["processing_time_ms"],
            "blockchain_hash":bc.get("block_hash",""),"blockchain_block":bc.get("block_index",0),"tx_hash":bc.get("tx_hash","")})
        db_log(u["username"],"UPLOAD_EVIDENCE","evidence",eid,f"Uploaded {filename} | Risk: {analysis['risk_level']}")
        findings = analysis.get("key_findings",[]); threats = analysis.get("threats",[]); recs = analysis.get("recommendations",[])
        cards.append(dbc.Card([dbc.CardBody([
            dbc.Row([
                dbc.Col([html.Div([rbdg(analysis["risk_level"]),bdg(analysis["file_type"],"info"),
                    bdg("Groq AI","success") if analysis["groq_powered"] else bdg("Local","warning"),
                    bdg("Cached ⚡","info") if analysis.get("from_cache") else html.Span()]),
                    html.H6(filename,className="mt-2 mb-1"),
                    html.Small([ic("fas fa-hashtag me-1 text-muted"),html.Code(analysis["hashes"]["sha256"][:40]+"...",style={"fontSize":".7rem","color":"#8b949e"})]),
                ],md=8),
                dbc.Col([html.Small(f"Size: {len(file_data):,} bytes",className="text-muted d-block"),
                    html.Small(f"Entropy: {analysis['entropy']:.2f}/8.0",className="text-muted d-block"),
                    html.Small(f"Risk Score: {analysis['local_risk_score']:.2f}",className="text-muted d-block"),
                    html.Small(f"Block: #{bc.get('block_index','—')}",className="text-muted d-block"),
                    html.Small(f"Time: {analysis['processing_time_ms']}ms",className="text-muted d-block"),
                ],md=4),
            ]),
            html.Hr(style={"borderColor":"#30363d","margin":".5rem 0"}),
            html.P(analysis["ai_summary"],className="small mb-2") if analysis["ai_summary"] else html.Span(),
            dbc.Row([
                dbc.Col([html.Strong("Key Findings:",className="small"),html.Ul([html.Li(f,className="small text-muted") for f in findings[:3]],className="mb-0 ps-3")],md=4) if findings else html.Span(),
                dbc.Col([html.Strong("Threats:",className="small text-danger"),html.Ul([html.Li(t,className="small text-muted") for t in threats[:3]],className="mb-0 ps-3")],md=4) if threats else html.Span(),
                dbc.Col([html.Strong("Actions:",className="small text-success"),html.Ul([html.Li(r,className="small text-muted") for r in recs[:3]],className="mb-0 ps-3")],md=4) if recs else html.Span(),
            ]) if (findings or threats or recs) else html.Span(),
            html.Hr(style={"borderColor":"#30363d","margin":".5rem 0"}),
            html.Small([bdg("✓ Blockchain Anchored","primary"),bdg(f"Block #{bc.get('block_index','?')}","dark"),
                        bdg("✓ Saved" if saved else "✗ Failed","success" if saved else "danger"),bdg(evn,"secondary")]),
        ])],color=RC.get(analysis["risk_level"],"secondary"),outline=True,className="mb-3"))
    status = [ic("fas fa-check-circle fa-2x text-success mb-2 d-block"),
              html.Strong(f"Processed {len(cards)} file(s)",className="d-block"),
              html.Small("All evidence anchored on blockchain",className="text-muted")]
    return status, html.Div([html.H5([ic("fas fa-clipboard-check me-2"),"Processing Results"],className="mb-3"),html.Div(cards)])

@app.callback(Output("ccm","is_open"),
    Input("ocb","n_clicks"),Input("ccb","n_clicks"),Input("cfcb","n_clicks"),
    State("ccm","is_open"), prevent_initial_call=True)
def toggle_modal(o,ca,co,is_open):
    t = callback_context.triggered[0]["prop_id"].split(".")[0]
    return True if t=="ocb" else False if t in ("ccb","cfcb") else is_open

@app.callback(Output("car","children"),
    Input("cfcb","n_clicks"), State("nct","value"), State("nctype","value"),
    State("ncp","value"), State("ncc","value"), State("ncd","value"), State("ss","data"),
    prevent_initial_call=True)
def create_case(n, title, ctype, priority, classification, description, s):
    if not n: raise PreventUpdate
    if not title: return dbc.Alert("Title required",color="warning")
    u = auth_verify_token((s or {}).get("tok",""))
    if not u: return dbc.Alert("Unauthorized",color="danger")
    cid = db_create_case(title, description or "", ctype or "general", priority or "MEDIUM", classification or "CONFIDENTIAL", u["sub"])
    db_log(u["username"],"CREATE_CASE","case",cid,f"Created: {title}")
    return dbc.Alert([ic("fas fa-check-circle me-2"),f"Case created! Refresh to see it."],color="success",dismissable=True)

@app.callback(Output("rs","children"), Output("rd","data"),
    Input("grb","n_clicks"), State("rcs","value"), State("roi","value"), State("ss","data"),
    prevent_initial_call=True)
def gen_report(n, case_id, options, s):
    if not n or not case_id: return dbc.Alert("Select a case.",color="warning"), dash.no_update
    u = auth_verify_token((s or {}).get("tok",""))
    if not u: return dbc.Alert("Unauthorized",color="danger"), dash.no_update
    if not REPORTLAB: return dbc.Alert("reportlab not installed. Run: pip install reportlab",color="danger"), dash.no_update
    case = db_get_case(case_id)
    if not case: return dbc.Alert("Case not found",color="danger"), dash.no_update
    ev = db_get_evidence(case_id)
    narrative = ai_groq_narrative(case, ev) if options and "ai" in options else ""
    fpath, err = rpt_generate(case, ev, narrative, u["full_name"])
    if err: return dbc.Alert(f"Error: {err}",color="danger"), dash.no_update
    db_log(u["username"],"GENERATE_REPORT","case",case_id,f"Report for {case['case_number']}")
    return (dbc.Alert([ic("fas fa-check-circle me-2"),f"Report ready: {Path(fpath).name}"],color="success"),
            dcc.send_file(fpath))

# ── File download route ───────────────────────────────────────────────────────
@server.route("/download/<path:fn>")
def dl(fn):
    try: return send_file(f"reports/{fn}", as_attachment=True)
    except: return "Not found", 404

# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    init_db()
    HOST  = os.getenv("HOST","127.0.0.1")
    PORT  = int(os.getenv("PORT",8080))
    DEBUG = os.getenv("DEBUG","true").lower() == "true"
    print(f"""
╔══════════════════════════════════════════════════════════╗
║        🇮🇳 COC EVIDENCE MANAGEMENT SYSTEM               ║
╠══════════════════════════════════════════════════════════╣
║  DB         : SQLite  (data/coc.db)                     ║
║  AI         : {'Groq llama-3.3-70b-versatile ✅' if GROQ_KEY else 'Local forensic analysis ⚠️  (set GROQ_API_KEY)'}{'':12}║
║  Blockchain : SHA-256 hash chain                        ║
║  Reports    : PDF + Section 65B certificate             ║
╠══════════════════════════════════════════════════════════╣
║  admin/admin123        analyst/analyst123               ║
║  investigator/invest123  officer/officer123             ║
╠══════════════════════════════════════════════════════════╣
║  URL → http://{HOST}:{PORT}                              ║
╚══════════════════════════════════════════════════════════╝
""")
    app.run(debug=DEBUG, host=HOST, port=PORT, use_reloader=False)