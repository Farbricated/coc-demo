#!/usr/bin/env python3
"""
COC v4.0 — Chain of Custody Evidence Management System
India | IEEE-grade | Production-optimized
New in v4: Thread-local DB pool · DB indexes · Stats cache · Alerts system ·
           Auto cross-case dedup · Batch Merkle anchor · Case Health Score ·
           Evidence Timeline · Global Search · Evidence Comparison · Pagination
"""
import os,sys,json,math,time,base64,hashlib,secrets,logging,sqlite3,requests,re,csv,io
import statistics,threading
from datetime import datetime,timedelta
from pathlib import Path
from typing import Dict,List,Optional,Any
from collections import defaultdict
from functools import lru_cache

if sys.platform=="win32":
    sys.stdout=__import__("io").TextIOWrapper(sys.stdout.buffer,encoding="utf-8",errors="replace")

for _d in ["logs","data","uploads","reports","exports"]:
    Path(_d).mkdir(exist_ok=True)

logging.basicConfig(level=logging.INFO,format="%(asctime)s %(levelname)s: %(message)s",
    handlers=[logging.FileHandler("logs/coc.log",encoding="utf-8"),logging.StreamHandler()])
logger=logging.getLogger(__name__)

try:
    from dotenv import load_dotenv; load_dotenv()
except: pass

import dash
from dash import dcc,html,Input,Output,State,ALL,MATCH,ctx,callback_context
from dash.exceptions import PreventUpdate
import dash_bootstrap_components as dbc
import plotly.graph_objects as go
from flask import Flask,send_file,jsonify,make_response
from flask_cors import CORS
from werkzeug.security import generate_password_hash,check_password_hash
from werkzeug.utils import secure_filename
import jwt,pyotp

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors as rlc
    from reportlab.lib.units import inch
    from reportlab.lib.styles import getSampleStyleSheet,ParagraphStyle
    from reportlab.lib.enums import TA_CENTER,TA_JUSTIFY
    from reportlab.platypus import SimpleDocTemplate,Paragraph,Spacer,Table,TableStyle,HRFlowable,PageBreak
    HAS_PDF=True
except: HAS_PDF=False

# ═══════════════════════════════════════════════════════════════════════════════
# DATABASE  — Thread-local pooling + indexes + 12 tables
# ═══════════════════════════════════════════════════════════════════════════════
DB_PATH=Path("data/coc_v4.db")
_tl=threading.local()   # thread-local connection pool

def _db():
    """Reuse one SQLite connection per thread"""
    if not hasattr(_tl,"conn") or _tl.conn is None:
        DB_PATH.parent.mkdir(exist_ok=True)
        _tl.conn=sqlite3.connect(str(DB_PATH),check_same_thread=False)
        _tl.conn.row_factory=sqlite3.Row
        _tl.conn.execute("PRAGMA journal_mode=WAL")
        _tl.conn.execute("PRAGMA foreign_keys=ON")
        _tl.conn.execute("PRAGMA cache_size=-32000")   # 32MB page cache
        _tl.conn.execute("PRAGMA synchronous=NORMAL")
    return _tl.conn

def init_db():
    c=_db()
    c.executescript("""
    CREATE TABLE IF NOT EXISTS users(
        id TEXT PRIMARY KEY,username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,full_name TEXT NOT NULL,
        role TEXT NOT NULL,department TEXT NOT NULL,
        badge_number TEXT,clearance_level INTEGER DEFAULT 1,
        mfa_secret TEXT,mfa_enabled INTEGER DEFAULT 0,
        failed_attempts INTEGER DEFAULT 0,last_login TEXT,
        created_at TEXT NOT NULL,active INTEGER DEFAULT 1);

    CREATE TABLE IF NOT EXISTS cases(
        id TEXT PRIMARY KEY,case_number TEXT UNIQUE NOT NULL,
        title TEXT NOT NULL,description TEXT,case_type TEXT DEFAULT 'general',
        status TEXT DEFAULT 'Open',priority TEXT DEFAULT 'MEDIUM',
        classification TEXT DEFAULT 'CONFIDENTIAL',created_by TEXT NOT NULL,
        fir_number TEXT DEFAULT '',agency TEXT DEFAULT '',tags TEXT DEFAULT '[]',
        created_at TEXT NOT NULL,updated_at TEXT NOT NULL);

    CREATE TABLE IF NOT EXISTS evidence(
        id TEXT PRIMARY KEY,evidence_number TEXT UNIQUE NOT NULL,
        filename TEXT NOT NULL,original_filename TEXT NOT NULL,
        file_size INTEGER NOT NULL,file_type TEXT,
        sha256_hash TEXT NOT NULL,md5_hash TEXT NOT NULL,sha1_hash TEXT,
        hex_preview TEXT,strings_preview TEXT,
        case_id TEXT NOT NULL,uploaded_by TEXT NOT NULL,
        priority TEXT DEFAULT 'MEDIUM',classification TEXT DEFAULT 'CONFIDENTIAL',
        location TEXT,description TEXT,tags TEXT DEFAULT '[]',
        risk_level TEXT DEFAULT 'UNKNOWN',risk_score REAL DEFAULT 0.0,
        confidence REAL DEFAULT 0.0,entropy REAL DEFAULT 0.0,
        signatures_found INTEGER DEFAULT 0,
        stride_spoofing TEXT,stride_tampering TEXT,stride_repudiation TEXT,
        stride_info_disclosure TEXT,stride_dos TEXT,stride_elevation TEXT,
        ai_summary TEXT,ai_threats TEXT DEFAULT '[]',ai_recommendations TEXT DEFAULT '[]',
        ai_iocs TEXT DEFAULT '[]',ai_ttps TEXT DEFAULT '[]',court_admissibility TEXT,
        processing_time_ms INTEGER DEFAULT 0,
        blockchain_hash TEXT DEFAULT '',blockchain_block INTEGER DEFAULT 0,
        merkle_root TEXT DEFAULT '',tx_hash TEXT DEFAULT '',
        status TEXT DEFAULT 'ANALYZED',uploaded_at TEXT NOT NULL);

    CREATE TABLE IF NOT EXISTS coc_transfers(
        id TEXT PRIMARY KEY,evidence_id TEXT NOT NULL,
        from_user TEXT NOT NULL,to_user TEXT NOT NULL,
        from_department TEXT DEFAULT '',to_department TEXT DEFAULT '',
        purpose TEXT DEFAULT '',transfer_hash TEXT NOT NULL,
        timestamp TEXT NOT NULL);

    CREATE TABLE IF NOT EXISTS ioc_indicators(
        id TEXT PRIMARY KEY,evidence_id TEXT,case_id TEXT,
        ioc_type TEXT NOT NULL,ioc_value TEXT NOT NULL,
        severity TEXT DEFAULT 'MEDIUM',description TEXT DEFAULT '',
        first_seen TEXT NOT NULL);

    CREATE TABLE IF NOT EXISTS case_correlations(
        id TEXT PRIMARY KEY,case_id_a TEXT NOT NULL,case_id_b TEXT NOT NULL,
        correlation_type TEXT DEFAULT 'UNKNOWN',confidence REAL DEFAULT 0.0,
        shared_iocs TEXT DEFAULT '[]',notes TEXT DEFAULT '',
        created_at TEXT NOT NULL,
        UNIQUE(case_id_a,case_id_b));

    CREATE TABLE IF NOT EXISTS alerts(
        id TEXT PRIMARY KEY,alert_type TEXT NOT NULL,
        title TEXT NOT NULL,message TEXT NOT NULL,
        severity TEXT DEFAULT 'INFO',
        case_id TEXT DEFAULT '',evidence_id TEXT DEFAULT '',
        read_by TEXT DEFAULT '[]',created_at TEXT NOT NULL);

    CREATE TABLE IF NOT EXISTS perf_metrics(
        id TEXT PRIMARY KEY,operation TEXT NOT NULL,
        duration_ms REAL NOT NULL,file_size_bytes INTEGER DEFAULT 0,
        groq_tokens INTEGER DEFAULT 0,timestamp TEXT NOT NULL);

    CREATE TABLE IF NOT EXISTS audit_logs(
        id TEXT PRIMARY KEY,username TEXT,action TEXT NOT NULL,
        resource_type TEXT DEFAULT '',resource_id TEXT DEFAULT '',
        details TEXT DEFAULT '',timestamp TEXT NOT NULL);

    CREATE TABLE IF NOT EXISTS blockchain_records(
        id TEXT PRIMARY KEY,block_index INTEGER NOT NULL,
        block_hash TEXT NOT NULL,previous_hash TEXT NOT NULL,
        merkle_root TEXT DEFAULT '',evidence_ids TEXT DEFAULT '[]',
        evidence_id TEXT DEFAULT '',file_hash TEXT DEFAULT '',
        uploader TEXT DEFAULT '',case_id TEXT DEFAULT '',
        timestamp TEXT NOT NULL);

    CREATE TABLE IF NOT EXISTS groq_cache(
        file_hash TEXT PRIMARY KEY,analysis_json TEXT NOT NULL,
        tokens_used INTEGER DEFAULT 0,cached_at TEXT NOT NULL);

    CREATE TABLE IF NOT EXISTS ev_comparisons(
        id TEXT PRIMARY KEY,ev_id_a TEXT NOT NULL,ev_id_b TEXT NOT NULL,
        username TEXT NOT NULL,created_at TEXT NOT NULL);

    -- Indexes for query performance
    CREATE INDEX IF NOT EXISTS idx_ev_case ON evidence(case_id);
    CREATE INDEX IF NOT EXISTS idx_ev_hash ON evidence(sha256_hash);
    CREATE INDEX IF NOT EXISTS idx_ev_risk ON evidence(risk_level);
    CREATE INDEX IF NOT EXISTS idx_ev_type ON evidence(file_type);
    CREATE INDEX IF NOT EXISTS idx_ev_date ON evidence(uploaded_at);
    CREATE INDEX IF NOT EXISTS idx_ev_uploader ON evidence(uploaded_by);
    CREATE INDEX IF NOT EXISTS idx_cases_status ON cases(status);
    CREATE INDEX IF NOT EXISTS idx_cases_priority ON cases(priority);
    CREATE INDEX IF NOT EXISTS idx_ioc_case ON ioc_indicators(case_id);
    CREATE INDEX IF NOT EXISTS idx_ioc_type ON ioc_indicators(ioc_type);
    CREATE INDEX IF NOT EXISTS idx_ioc_value ON ioc_indicators(ioc_value);
    CREATE INDEX IF NOT EXISTS idx_alerts_read ON alerts(read_by);
    CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_logs(username);
    CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_logs(timestamp);
    CREATE INDEX IF NOT EXISTS idx_bc_index ON blockchain_records(block_index);
    CREATE INDEX IF NOT EXISTS idx_transfers_ev ON coc_transfers(evidence_id);
    CREATE INDEX IF NOT EXISTS idx_perf_op ON perf_metrics(operation);
    """)
    c.commit()
    _seed_users(c); _seed_cases(c)
    logger.info("✅ COC v4 DB ready (indexed)")

def _seed_users(c):
    for u,p,fn,r,d,b,cl in [
        ("admin","admin123","DCP Priya Sharma, IPS","admin","National Cyber Security Coordinator","NCSC-001",5),
        ("analyst","analyst123","Dr. Rajesh Kumar Singh","analyst","Central Forensic Science Laboratory","CFSL-042",4),
        ("investigator","invest123","Inspector Anita Desai, IPS","investigator","CBI Special Cyber Crime Division","CBI-187",3),
        ("officer","officer123","Sub-Inspector Suresh Patel","officer","Delhi Police Cyber Cell","DPC-256",2),
        ("legal","legal123","Adv. Vikram Choudhary","legal","MeitY Legal Division","MEL-101",3),
        ("forensic","forensic123","Dr. Meena Krishnamurthy","analyst","CFSL Hyderabad","CFSL-089",4),
    ]:
        if not c.execute("SELECT id FROM users WHERE username=?",(u,)).fetchone():
            c.execute("INSERT INTO users(id,username,password_hash,full_name,role,department,badge_number,clearance_level,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                (secrets.token_hex(8),u,generate_password_hash(p),fn,r,d,b,cl,_now()))
    c.commit()

def _seed_cases(c):
    if c.execute("SELECT COUNT(*) FROM cases").fetchone()[0]: return
    aid=c.execute("SELECT id FROM users WHERE username='admin'").fetchone()
    aid=aid["id"] if aid else "system"; now=_now()
    for cn,title,desc,ct,st,pr,cl,fir,ag in [
        ("APT-2024-001","State-Sponsored APT — Maharashtra Power Grid","Coordinated attack on Maharashtra power infrastructure. NSG+NCIIPC. APT-41 cluster.","cyber_terrorism","Active","CRITICAL","TOP_SECRET","FIR/MH/2024/00891","NSG Cyber Wing + NCIIPC"),
        ("UPI-2024-047","Multi-State UPI Fraud — Operation Phantom Pay","UPI fraud targeting 15,000+ victims across 23 states. ₹247 Cr loss. Crypto laundering.","financial_cybercrime","Active","HIGH","SECRET","FIR/DL/2024/04712","CBI Banking Fraud"),
        ("MUR-2024-156","Sharma vs State — Digital Evidence","Mobile forensics, WhatsApp, location, call records. 89% digital evidence.","digital_murder","Under Investigation","HIGH","CONFIDENTIAL","FIR/DL/2024/01156","Delhi Police Crime Branch"),
        ("CORP-2024-088","Defence Contractor Data Breach","14GB classified data exfiltrated. USB artifacts, cloud sync. Insider threat suspected.","corporate_espionage","Under Investigation","HIGH","SECRET","FIR/DL/2024/08801","DRDO Security + IB"),
        ("CYB-2024-203","Ransomware Attack — AIIMS Delhi","Hospital ransomware. Patient data encrypted. Network forensics ongoing.","cybercrime","Active","CRITICAL","SECRET","FIR/DL/2024/02031","CERT-In + Delhi Police"),
    ]:
        c.execute("INSERT INTO cases(id,case_number,title,description,case_type,status,priority,classification,created_by,fir_number,agency,tags,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (secrets.token_hex(8),cn,title,desc,ct,st,pr,cl,aid,fir,ag,"[]",now,now))
    c.commit()

# ── DB helpers ────────────────────────────────────────────────────────────────
_now=lambda: datetime.now().isoformat()

def _q(sql,p=(),one=False,many=False,commit=False):
    c=_db()
    try:
        cur=c.execute(sql,p)
        if commit: c.commit(); return True
        if one: r=cur.fetchone(); return dict(r) if r else None
        if many: return [dict(r) for r in cur.fetchall()]
    except Exception as e: logger.error(f"DB: {e}"); return None

# Users
def db_user(u): return _q("SELECT * FROM users WHERE username=? AND active=1",(u,),one=True)
def db_users(): return _q("SELECT id,username,full_name,role,department,badge_number,clearance_level,mfa_enabled,last_login,failed_attempts,active FROM users",many=True) or []
def db_user_by_id(uid): return _q("SELECT * FROM users WHERE id=?",(uid,),one=True)
def db_upd_login(u): _q("UPDATE users SET last_login=?,failed_attempts=0 WHERE username=?",(_now(),u),commit=True)
def db_inc_fail(u): _q("UPDATE users SET failed_attempts=failed_attempts+1 WHERE username=?",(u,),commit=True)
def db_rst_fail(u): _q("UPDATE users SET failed_attempts=0 WHERE username=?",(u,),commit=True)
def db_toggle_user(uid,v): _q("UPDATE users SET active=? WHERE id=?",(v,uid),commit=True)

# Cases
def db_cases(clearance=5):
    allowed={1:["RESTRICTED"],2:["RESTRICTED","CONFIDENTIAL"],3:["RESTRICTED","CONFIDENTIAL","SECRET"],4:["RESTRICTED","CONFIDENTIAL","SECRET"],5:["RESTRICTED","CONFIDENTIAL","SECRET","TOP_SECRET"]}.get(clearance,["RESTRICTED"])
    ph=",".join("?"*len(allowed))
    return _q(f"SELECT * FROM cases WHERE classification IN({ph}) ORDER BY created_at DESC",allowed,many=True) or []
def db_case(cid): return _q("SELECT * FROM cases WHERE id=?",(cid,),one=True)
def db_create_case(title,desc,ctype,prio,cls,creator,fir="",agency="",tags="[]"):
    cid=secrets.token_hex(8); prefix={"cyber_terrorism":"APT","financial_cybercrime":"FIN","digital_murder":"HOM","cybercrime":"CYB","corporate_espionage":"ESP"}.get(ctype,"GEN")
    cn=f"{prefix}-{datetime.now().strftime('%Y')}-{secrets.token_hex(3).upper()}"; now=_now()
    _q("INSERT INTO cases(id,case_number,title,description,case_type,priority,classification,created_by,fir_number,agency,tags,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
       (cid,cn,title,desc or "",ctype,prio,cls,creator,fir,agency,tags,now,now),commit=True)
    return cid,cn
def db_update_case(cid,status): _q("UPDATE cases SET status=?,updated_at=? WHERE id=?",(status,_now(),cid),commit=True)

# Evidence — paginated
PER_PAGE=25
def db_ev_search(query="",case_id=None,risk=None,ftype=None,page=0,limit=PER_PAGE):
    cl=["1=1"]; p=[]
    if case_id: cl.append("case_id=?"); p.append(case_id)
    if risk: cl.append("risk_level=?"); p.append(risk)
    if ftype: cl.append("file_type=?"); p.append(ftype)
    if query: cl.append("(original_filename LIKE ? OR sha256_hash LIKE ? OR description LIKE ? OR tags LIKE ?)"); p+=[f"%{query}%"]*4
    p+=[limit,page*limit]
    total=_q(f"SELECT COUNT(*) as n FROM evidence WHERE {' AND '.join(cl)}",p[:-2],one=True) or {"n":0}
    rows=_q(f"SELECT * FROM evidence WHERE {' AND '.join(cl)} ORDER BY uploaded_at DESC LIMIT ? OFFSET ?",p,many=True) or []
    return rows,total["n"]

def db_ev(case_id=None,limit=200):
    if case_id: return _q("SELECT * FROM evidence WHERE case_id=? ORDER BY uploaded_at DESC LIMIT ?",(case_id,limit),many=True) or []
    return _q("SELECT * FROM evidence ORDER BY uploaded_at DESC LIMIT ?",(limit,),many=True) or []

def db_ev_by_id(eid): return _q("SELECT * FROM evidence WHERE id=?",(eid,),one=True)
def db_ev_by_hash(sha256): return _q("SELECT * FROM evidence WHERE sha256_hash=?",(sha256,),many=True) or []

def db_save_ev(d):
    try:
        c=_db()
        c.execute("""INSERT INTO evidence(id,evidence_number,filename,original_filename,file_size,file_type,
            sha256_hash,md5_hash,sha1_hash,hex_preview,strings_preview,case_id,uploaded_by,
            priority,classification,location,description,tags,risk_level,risk_score,confidence,entropy,
            signatures_found,stride_spoofing,stride_tampering,stride_repudiation,stride_info_disclosure,
            stride_dos,stride_elevation,ai_summary,ai_threats,ai_recommendations,ai_iocs,ai_ttps,
            court_admissibility,processing_time_ms,blockchain_hash,blockchain_block,merkle_root,tx_hash,
            status,uploaded_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (d["id"],d["ev_num"],d["filename"],d["original_filename"],d["file_size"],d.get("file_type","UNKNOWN"),
             d["sha256"],d["md5"],d.get("sha1",""),d.get("hex_preview",""),d.get("strings_preview",""),
             d["case_id"],d["uploaded_by"],d.get("priority","MEDIUM"),d.get("classification","CONFIDENTIAL"),
             d.get("location",""),d.get("description",""),d.get("tags","[]"),d.get("risk_level","UNKNOWN"),
             d.get("risk_score",0.0),d.get("confidence",0.7),d.get("entropy",0.0),d.get("sigs_found",0),
             d.get("s_spoof",""),d.get("s_tamp",""),d.get("s_rep",""),d.get("s_info",""),d.get("s_dos",""),d.get("s_elev",""),
             d.get("ai_summary",""),json.dumps(d.get("threats",[])),json.dumps(d.get("recs",[])),
             json.dumps(d.get("iocs",[])),json.dumps(d.get("ttps",[])),d.get("court_admit",""),
             d.get("proc_ms",0),d.get("bc_hash",""),d.get("bc_block",0),d.get("merkle",""),d.get("tx",""),
             "ANALYZED",_now()))
        c.commit(); _invalidate_stats(); return True
    except Exception as e: logger.error(f"save_ev: {e}"); return False

# Stats with 30s cache
_stats_cache={"data":None,"ts":0.0}
def _invalidate_stats(): _stats_cache["ts"]=0.0
def db_stats():
    now=time.time()
    if now-_stats_cache["ts"]<30 and _stats_cache["data"]:
        return _stats_cache["data"]
    c=_db()
    s={k:c.execute(q).fetchone()[0] for k,q in [
        ("total_evidence","SELECT COUNT(*) FROM evidence"),
        ("total_cases","SELECT COUNT(*) FROM cases"),
        ("active_cases","SELECT COUNT(*) FROM cases WHERE status='Active'"),
        ("high_risk","SELECT COUNT(*) FROM evidence WHERE risk_level IN('HIGH','CRITICAL')"),
        ("critical","SELECT COUNT(*) FROM evidence WHERE risk_level='CRITICAL'"),
        ("anchored","SELECT COUNT(*) FROM evidence WHERE blockchain_hash!=''"),
        ("total_users","SELECT COUNT(*) FROM users WHERE active=1"),
        ("total_iocs","SELECT COUNT(*) FROM ioc_indicators"),
        ("total_transfers","SELECT COUNT(*) FROM coc_transfers"),
        ("unread_alerts","SELECT COUNT(*) FROM alerts WHERE read_by NOT LIKE '%\"all\"%'"),
    ]}
    _stats_cache["data"]=s; _stats_cache["ts"]=now
    return s

# Alerts
def db_alerts(limit=20,unread_only=False):
    sql="SELECT * FROM alerts ORDER BY created_at DESC LIMIT ?" if not unread_only else "SELECT * FROM alerts WHERE read_by='[]' ORDER BY created_at DESC LIMIT ?"
    return _q(sql,(limit,),many=True) or []
def db_save_alert(atype,title,message,severity="INFO",case_id="",evidence_id=""):
    _q("INSERT INTO alerts(id,alert_type,title,message,severity,case_id,evidence_id,read_by,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
       (secrets.token_hex(8),atype,title,message,severity,case_id,evidence_id,"[]",_now()),commit=True)
    _invalidate_stats()
def db_mark_alert_read(alert_id,username):
    a=_q("SELECT read_by FROM alerts WHERE id=?",(alert_id,),one=True)
    if not a: return
    rb=json.loads(a.get("read_by","[]"))
    if username not in rb: rb.append(username)
    _q("UPDATE alerts SET read_by=? WHERE id=?",(json.dumps(rb),alert_id),commit=True)
    _invalidate_stats()
def db_mark_all_read(username):
    alerts=_q("SELECT id,read_by FROM alerts",many=True) or []
    for a in alerts:
        rb=json.loads(a.get("read_by","[]"))
        if username not in rb: rb.append(username)
        _q("UPDATE alerts SET read_by=? WHERE id=?",(json.dumps(rb),a["id"]),commit=True)
    _invalidate_stats()

# IOCs
def db_save_iocs(ev_id,case_id,iocs):
    for i in iocs:
        if not i.get("value"): continue
        _q("INSERT OR IGNORE INTO ioc_indicators(id,evidence_id,case_id,ioc_type,ioc_value,severity,description,first_seen) VALUES(?,?,?,?,?,?,?,?)",
           (secrets.token_hex(8),ev_id,case_id,i.get("type","UNKNOWN"),i.get("value",""),i.get("severity","MEDIUM"),i.get("description",""),_now()),commit=True)
def db_iocs(case_id=None,limit=200):
    sql="SELECT * FROM ioc_indicators WHERE case_id=? ORDER BY first_seen DESC LIMIT ?" if case_id else "SELECT * FROM ioc_indicators ORDER BY first_seen DESC LIMIT ?"
    return _q(sql,(case_id,limit) if case_id else (limit,),many=True) or []

# Transfers
def db_save_transfer(ev_id,from_u,to_u,from_dept,to_dept,purpose):
    h=hashlib.sha256(f"{ev_id}{from_u}{to_u}{datetime.utcnow().isoformat()}".encode()).hexdigest()
    _q("INSERT INTO coc_transfers(id,evidence_id,from_user,to_user,from_department,to_department,purpose,transfer_hash,timestamp) VALUES(?,?,?,?,?,?,?,?,?)",
       (secrets.token_hex(8),ev_id,from_u,to_u,from_dept,to_dept,purpose,h,_now()),commit=True)
    return h
def db_transfers(ev_id=None,limit=100):
    sql="SELECT * FROM coc_transfers WHERE evidence_id=? ORDER BY timestamp DESC LIMIT ?" if ev_id else "SELECT * FROM coc_transfers ORDER BY timestamp DESC LIMIT ?"
    return _q(sql,(ev_id,limit) if ev_id else (limit,),many=True) or []

# Correlations
def db_correlations(): return _q("SELECT * FROM case_correlations ORDER BY confidence DESC",many=True) or []
def db_save_corr(ca,cb,ctype,conf,iocs,notes):
    _q("INSERT OR IGNORE INTO case_correlations(id,case_id_a,case_id_b,correlation_type,confidence,shared_iocs,notes,created_at) VALUES(?,?,?,?,?,?,?,?)",
       (secrets.token_hex(8),ca,cb,ctype,conf,json.dumps(iocs),notes,_now()),commit=True)

# Metrics
def db_save_metric(op,ms,fsize=0,tokens=0):
    _q("INSERT INTO perf_metrics(id,operation,duration_ms,file_size_bytes,groq_tokens,timestamp) VALUES(?,?,?,?,?,?)",
       (secrets.token_hex(8),op,ms,fsize,tokens,_now()),commit=True)
def db_metrics(op=None,limit=500):
    sql="SELECT * FROM perf_metrics WHERE operation=? ORDER BY timestamp DESC LIMIT ?" if op else "SELECT * FROM perf_metrics ORDER BY timestamp DESC LIMIT ?"
    return _q(sql,(op,limit) if op else (limit,),many=True) or []

# Blockchain
def db_blockchain(limit=30): return _q("SELECT * FROM blockchain_records ORDER BY block_index DESC LIMIT ?",(limit,),many=True) or []
def db_last_block(): return _q("SELECT * FROM blockchain_records ORDER BY block_index DESC LIMIT 1",one=True)
def db_save_block(b):
    _q("INSERT INTO blockchain_records(id,block_index,block_hash,previous_hash,merkle_root,evidence_ids,evidence_id,file_hash,uploader,case_id,timestamp) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
       (secrets.token_hex(8),b["idx"],b["hash"],b["prev"],b.get("merkle",""),json.dumps(b.get("ev_ids",[])),b.get("ev_id",""),b.get("fhash",""),b.get("uploader",""),b.get("case_id",""),b["ts"]),commit=True)

# Groq cache
def db_groq_get(fh): return _q("SELECT analysis_json,tokens_used FROM groq_cache WHERE file_hash=?",(fh,),one=True)
def db_groq_set(fh,j,tokens=0): _q("INSERT OR REPLACE INTO groq_cache(file_hash,analysis_json,tokens_used,cached_at) VALUES(?,?,?,?)",(fh,j,tokens,_now()),commit=True)

# Audit
def db_log(username,action,rtype="",rid="",details=""):
    _q("INSERT INTO audit_logs(id,username,action,resource_type,resource_id,details,timestamp) VALUES(?,?,?,?,?,?,?)",(secrets.token_hex(8),username,action,rtype,rid,details,_now()),commit=True)
def db_logs(limit=50): return _q("SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT ?",(limit,),many=True) or []

# Global search
def db_global_search(query,clearance=5):
    if not query or len(query)<2: return {"evidence":[],"cases":[],"iocs":[]}
    q=f"%{query}%"
    allowed={1:["RESTRICTED"],2:["RESTRICTED","CONFIDENTIAL"],3:["RESTRICTED","CONFIDENTIAL","SECRET"],4:["RESTRICTED","CONFIDENTIAL","SECRET"],5:["RESTRICTED","CONFIDENTIAL","SECRET","TOP_SECRET"]}.get(clearance,["RESTRICTED"])
    ph=",".join("?"*len(allowed))
    ev=_q(f"SELECT id,evidence_number,original_filename,file_type,risk_level,case_id FROM evidence WHERE original_filename LIKE ? OR sha256_hash LIKE ? OR description LIKE ? LIMIT 10",(q,q,q),many=True) or []
    cases=_q(f"SELECT id,case_number,title,priority,status FROM cases WHERE classification IN({ph}) AND (title LIKE ? OR case_number LIKE ? OR description LIKE ?) LIMIT 10",allowed+[q,q,q],many=True) or []
    iocs=_q("SELECT id,ioc_type,ioc_value,severity,case_id FROM ioc_indicators WHERE ioc_value LIKE ? LIMIT 10",(q,),many=True) or []
    return {"evidence":ev,"cases":cases,"iocs":iocs}

# Case Health Score (0-100)
def case_health(case_id):
    ev=db_ev(case_id,limit=1000); score=0; breakdown={}
    # Evidence quantity: 0-20 pts
    ev_score=min(20,int(math.log(len(ev)+1,2)*7)) if ev else 0
    score+=ev_score; breakdown["evidence"]=ev_score
    # Blockchain anchoring: % × 20
    if ev:
        anch=sum(1 for e in ev if e.get("blockchain_hash"))
        bc_score=int((anch/len(ev))*20)
        score+=bc_score; breakdown["blockchain"]=bc_score
        # AI analyzed: % × 20
        ai_score=int((sum(1 for e in ev if e.get("ai_summary"))/len(ev))*20)
        score+=ai_score; breakdown["ai"]=ai_score
    else:
        breakdown["blockchain"]=0; breakdown["ai"]=0
    # IOCs found: 0-20 pts
    ioc_count=len(db_iocs(case_id,200))
    ioc_score=min(20,ioc_count*2)
    score+=ioc_score; breakdown["iocs"]=ioc_score
    # Metadata completeness: 0-20 pts
    c=db_case(case_id)
    if c:
        meta=0
        if c.get("fir_number"): meta+=5
        if c.get("agency"): meta+=5
        if c.get("description"): meta+=5
        if c.get("status")!="Open": meta+=5
        score+=meta; breakdown["metadata"]=meta
    return min(100,score),breakdown

# ═══════════════════════════════════════════════════════════════════════════════
# AUTH
# ═══════════════════════════════════════════════════════════════════════════════
_SECRET=os.getenv("SECRET_KEY",secrets.token_hex(32))
_TOKEN_H=int(os.getenv("TOKEN_EXPIRY_HOURS",8))
MAX_FAIL=5
ROLE_PERMS={"admin":["all"],"analyst":["cases","upload","reports","ai","intel","search"],"investigator":["cases","upload","reports","intel","search"],"officer":["upload","reports"],"legal":["reports","cases","search"]}
CLEARANCE={1:"RESTRICTED",2:"CONFIDENTIAL",3:"SECRET",4:"SECRET",5:"TOP SECRET"}
ROLE_COL={"admin":"danger","analyst":"success","investigator":"warning","officer":"info","legal":"secondary"}

def auth_login(username,password):
    if not username or not password: return None,"Credentials required"
    u=db_user(username)
    if not u: return None,"Invalid credentials"
    if not u.get("active"): return None,"Account deactivated"
    if u.get("failed_attempts",0)>=MAX_FAIL: return None,"Account locked — contact admin"
    if not check_password_hash(u["password_hash"],password):
        db_inc_fail(username); return None,f"Invalid. {MAX_FAIL-u.get('failed_attempts',0)-1} attempts left."
    db_rst_fail(username); db_upd_login(username); db_log(username,"LOGIN","auth",u["id"],"OK")
    return u,""

def make_token(u):
    return jwt.encode({"sub":u["id"],"username":u["username"],"role":u["role"],"clearance_level":u["clearance_level"],"full_name":u["full_name"],"department":u["department"],"badge_number":u.get("badge_number",""),"exp":datetime.utcnow()+timedelta(hours=_TOKEN_H)},_SECRET,algorithm="HS256")

def chk_token(t):
    try: return jwt.decode(t,_SECRET,algorithms=["HS256"])
    except: return None

def has_perm(role,perm): p=ROLE_PERMS.get(role,[]); return "all" in p or perm in p

# ═══════════════════════════════════════════════════════════════════════════════
# BATCH MERKLE BLOCKCHAIN
# ═══════════════════════════════════════════════════════════════════════════════
GENESIS="0"*64

def _merkle(hashes):
    if not hashes: return hashlib.sha256(b"empty").hexdigest()
    n=list(hashes)
    while len(n)>1:
        if len(n)%2: n.append(n[-1])
        n=[hashlib.sha256((n[i]+n[i+1]).encode()).hexdigest() for i in range(0,len(n),2)]
    return n[0]

def bc_batch_anchor(ev_items,uploader,case_id=""):
    """Anchor N evidence items in ONE block with Merkle tree over all hashes"""
    t0=time.time()
    last=db_last_block()
    prev=last["block_hash"] if last else GENESIS
    idx=(last["block_index"]+1) if last else 0
    ts=datetime.utcnow().isoformat()
    all_hashes=[item["sha256"] for item in ev_items]
    merkle=_merkle(all_hashes)
    ev_ids=[item["ev_id"] for item in ev_items]
    raw=json.dumps({"i":idx,"prev":prev,"eids":sorted(ev_ids),"ts":ts,"u":uploader,"mk":merkle},sort_keys=True)
    bh=hashlib.sha256(raw.encode()).hexdigest()
    tx="0x"+hashlib.sha256((bh+secrets.token_hex(4)).encode()).hexdigest()
    db_save_block({"idx":idx,"hash":bh,"prev":prev,"merkle":merkle,"ev_ids":ev_ids,"ev_id":ev_ids[0] if ev_ids else "","fhash":all_hashes[0] if all_hashes else "","uploader":uploader,"case_id":case_id,"ts":ts})
    db_save_metric("blockchain_anchor",int((time.time()-t0)*1000))
    return {"idx":idx,"hash":bh,"tx":tx,"merkle":merkle,"ts":ts}

def bc_verify():
    records=sorted(db_blockchain(10000),key=lambda r:r["block_index"])
    if not records: return {"valid":True,"blocks":0,"message":"Empty chain"}
    errors=[]
    for i,b in enumerate(records):
        prev=records[i-1]["block_hash"] if i>0 else GENESIS
        ev_ids=json.loads(b.get("evidence_ids","[]") or "[]")
        raw=json.dumps({"i":b["block_index"],"prev":b["previous_hash"],"eids":sorted(ev_ids),"ts":b["timestamp"],"u":b.get("uploader",""),"mk":b.get("merkle_root","")},sort_keys=True)
        if hashlib.sha256(raw.encode()).hexdigest()!=b["block_hash"]: errors.append(f"Block #{b['block_index']}: hash mismatch")
        if b["previous_hash"]!=prev: errors.append(f"Block #{b['block_index']}: broken link")
    return {"valid":not errors,"blocks":len(records),"errors":errors,"message":"Chain intact ✓" if not errors else f"{len(errors)} errors"}

# ═══════════════════════════════════════════════════════════════════════════════
# FORENSIC ENGINE
# ═══════════════════════════════════════════════════════════════════════════════
GROQ_KEY=os.getenv("GROQ_API_KEY","")
GROQ_URL="https://api.groq.com/openai/v1/chat/completions"
GROQ_MODEL="llama-3.3-70b-versatile"

_MAGIC={b"MZ":("EXECUTABLE","Windows PE"),b"\x7fELF":("EXECUTABLE","Linux ELF"),b"%PDF":("DOCUMENT","PDF"),b"\xd0\xcf\x11\xe0":("DOCUMENT","MS Office OLE"),b"PK\x03\x04":("ARCHIVE","ZIP"),b"Rar!":("ARCHIVE","RAR"),b"\x1f\x8b":("ARCHIVE","GZIP"),b"\xff\xd8\xff":("IMAGE","JPEG"),b"\x89PNG\r\n":("IMAGE","PNG"),b"GIF8":("IMAGE","GIF"),b"\xd4\xc3\xb2\xa1":("PCAP","PCAP"),b"SQLite format 3":("DATABASE","SQLite3"),b"ID3":("AUDIO","MP3"),b"7z\xbc\xaf":("ARCHIVE","7-Zip"),b"OggS":("AUDIO","OGG"),b"fLaC":("AUDIO","FLAC"),b"RIFF":("AUDIO/VIDEO","RIFF"),b"\xca\xfe\xba\xbe":("EXECUTABLE","Java Class")}
_EXT={"exe":"EXECUTABLE","dll":"EXECUTABLE","sys":"EXECUTABLE","bat":"SCRIPT","ps1":"SCRIPT","vbs":"SCRIPT","js":"SCRIPT","py":"SCRIPT","php":"SCRIPT","sh":"SCRIPT","pdf":"DOCUMENT","doc":"DOCUMENT","docx":"DOCUMENT","xls":"DOCUMENT","xlsx":"DOCUMENT","rtf":"DOCUMENT","jpg":"IMAGE","jpeg":"IMAGE","png":"IMAGE","gif":"IMAGE","bmp":"IMAGE","zip":"ARCHIVE","rar":"ARCHIVE","7z":"ARCHIVE","tar":"ARCHIVE","gz":"ARCHIVE","pcap":"PCAP","pcapng":"PCAP","eml":"EMAIL","msg":"EMAIL","mp4":"VIDEO","avi":"VIDEO","mkv":"VIDEO","mp3":"AUDIO","wav":"AUDIO","db":"DATABASE","sqlite":"DATABASE","lnk":"SHORTCUT","iso":"DISK_IMAGE"}
_SIGS=[(b"powershell","HIGH","PowerShell execution"),(b"cmd.exe","HIGH","Command shell"),(b"CreateRemoteThread","HIGH","Remote thread injection"),(b"VirtualAlloc","MEDIUM","Memory allocation"),(b"WScript.Shell","HIGH","Windows Script Host"),(b"eval(","MEDIUM","Dynamic eval"),(b"base64_decode","MEDIUM","Base64 decode obfuscation"),(b"<?php","MEDIUM","PHP code"),(b"backdoor","CRITICAL","Backdoor string"),(b"ransomware","CRITICAL","Ransomware indicator"),(b"keylog","HIGH","Keylogger"),(b".onion","HIGH","Tor hidden service"),(b"bitcoin","MEDIUM","Cryptocurrency ref"),(b"CreateService","HIGH","Service creation"),(b"RegSetValueEx","HIGH","Registry modification"),(b"WriteProcessMemory","HIGH","Process injection"),(b"URLDownloadToFile","HIGH","Download API"),(b"mimikatz","CRITICAL","Mimikatz"),(b"metasploit","CRITICAL","Metasploit"),(b"cobalt strike","CRITICAL","Cobalt Strike"),(b"meterpreter","CRITICAL","Meterpreter payload"),(b"reverse_shell","CRITICAL","Reverse shell"),(b"net user","HIGH","User enumeration"),(b"whoami","MEDIUM","Privilege check"),(b"tasklist","LOW","Process enumeration"),(b"certutil","HIGH","CertUtil abuse"),(b"wscript","HIGH","WScript execution")]

def _hashes(d): return {"md5":hashlib.md5(d).hexdigest(),"sha1":hashlib.sha1(d).hexdigest(),"sha256":hashlib.sha256(d).hexdigest()}
def _entropy(d):
    s=d[:8192]
    if not s: return 0.0
    f={};
    for b in s: f[b]=f.get(b,0)+1
    n=len(s); return -sum((c/n)*math.log2(c/n) for c in f.values())
def _detect_type(data,fn):
    for magic,(ft,desc) in _MAGIC.items():
        if data[:len(magic)]==magic: return ft,desc
    ext=fn.rsplit(".",1)[-1].lower() if "." in fn else ""
    return _EXT.get(ext,"UNKNOWN"),f"{ext.upper()} file" if ext else "Unknown"
def _scan_sigs(data):
    dl=data.lower()
    return [{"pattern":p.decode(),"severity":s,"description":d} for p,s,d in _SIGS if p.lower() in dl]
def _hex_preview(data):
    ch=data[:256]; lines=[]
    for i in range(0,len(ch),16):
        row=ch[i:i+16]; hp=" ".join(f"{b:02x}" for b in row); ap="".join(chr(b) if 32<=b<127 else "." for b in row)
        lines.append(f"{i:04x}  {hp:<47}  {ap}")
    return "\n".join(lines)
def _strings(data): return list(set(re.findall(r'[\x20-\x7e]{6,80}',data[:65536].decode("utf-8",errors="ignore"))))[:30]
def _urls(data):
    t=data[:65536].decode("utf-8",errors="ignore")
    return {"urls":list(set(re.findall(r'https?://[^\s<>"\']{5,80}',t)))[:15],"ips":list(set(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b',t)))[:15],"emails":list(set(re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',t)))[:10]}
def _risk(ftype,entropy,sigs):
    s={"EXECUTABLE":0.4,"SCRIPT":0.35,"ARCHIVE":0.2,"DOCUMENT":0.1,"PCAP":0.15,"DATABASE":0.1,"IMAGE":0.05,"UNKNOWN":0.25,"EMAIL":0.15,"SHORTCUT":0.3}.get(ftype,0.1)
    if entropy>7.5: s+=0.3
    elif entropy>6.5: s+=0.15
    for sg in sigs: s+={"CRITICAL":0.5,"HIGH":0.3,"MEDIUM":0.15,"LOW":0.05}.get(sg["severity"],0)
    return min(s,1.0)
def _level(score):
    if score>=0.8: return "CRITICAL"
    if score>=0.6: return "HIGH"
    if score>=0.35: return "MEDIUM"
    if score>=0.1: return "LOW"
    return "MINIMAL"
def _stride(ftype,sigs,entropy,u):
    sd=" ".join(s["description"] for s in sigs).lower()
    cred=any(x in sd for x in ["credential","password","keylog","mimikatz"])
    inj=any(x in sd for x in ["injection","thread","memory"])
    exec_=any(x in sd for x in ["shell","exec","powershell","download","wscript","certutil"])
    net=bool(u.get("ips") or u.get("urls"))
    pers=any(x in sd for x in ["service","registry"])
    enc=entropy>7.0
    return {"spoofing":"HIGH — Credential harvesting" if cred else "LOW","tampering":"HIGH — Process injection" if inj else ("MEDIUM — Encrypted payload" if enc else "LOW"),"repudiation":"MEDIUM — May disable audit logs" if exec_ else "LOW","info_disclosure":"HIGH — Network exfiltration" if net else "LOW","dos":"MEDIUM — Resource exhaustion risk" if exec_ else "LOW","elevation":"HIGH — Privilege escalation APIs" if inj else "LOW"}
def _iocs(u,sigs):
    i=[]
    for url in u.get("urls",[])[:5]: i.append({"type":"URL","value":url,"severity":"HIGH","description":"Network IOC"})
    for ip in u.get("ips",[])[:5]: i.append({"type":"IP","value":ip,"severity":"MEDIUM","description":"IP address"})
    for em in u.get("emails",[])[:3]: i.append({"type":"EMAIL","value":em,"severity":"MEDIUM","description":"Email IOC"})
    for sg in sigs:
        if sg["severity"] in ("HIGH","CRITICAL"): i.append({"type":"SIGNATURE","value":sg["pattern"],"severity":sg["severity"],"description":sg["description"]})
    return i

def _call_groq(summary):
    if not GROQ_KEY: return None
    prompt=f"""You are a senior forensic analyst at India's CFSL. Analyze this evidence summary.
FILE: {summary['fn']} | Type: {summary['ftype']} | Size: {summary['size']:,}B
SHA-256: {summary['sha256'][:32]}... | Entropy: {summary['entropy']:.2f}/8 | Risk: {summary['risk']:.2f}
Signatures: {[s['description'] for s in summary['sigs'][:5]]}
URLs: {summary['u'].get('urls',[][:3])} | IPs: {summary['u'].get('ips',[][:3])}

Respond ONLY with valid JSON:
{{"threat_level":"MINIMAL|LOW|MEDIUM|HIGH|CRITICAL","confidence":0.0,"summary":"2-3 sentence forensic summary","key_findings":["f1","f2","f3"],"threats":["t1"],"ttps":["MITRE ATT&CK TTP"],"iocs":[{{"type":"IP|URL|HASH|EMAIL","value":"v","severity":"HIGH|MEDIUM|LOW","description":"d"}}],"court_admissibility":"Section 65B + DPDP 2023 assessment","recommendations":["r1","r2"]}}"""
    t0=time.time()
    try:
        r=requests.post(GROQ_URL,headers={"Authorization":f"Bearer {GROQ_KEY}","Content-Type":"application/json"},json={"model":GROQ_MODEL,"messages":[{"role":"user","content":prompt}],"temperature":0.1,"max_tokens":800},timeout=25)
        r.raise_for_status(); data=r.json(); content=data["choices"][0]["message"]["content"].strip(); tokens=data.get("usage",{}).get("total_tokens",0)
        db_save_metric("groq_analysis",int((time.time()-t0)*1000),tokens_used=tokens)
        if content.startswith("```"): content=content.split("```")[1].lstrip("json").strip()
        result=json.loads(content); result["_tokens"]=tokens; return result
    except Exception as e: logger.warning(f"Groq: {e}"); return None

def _fallback(summary,sigs):
    lv=_level(summary["risk"]); f=[]
    if summary["entropy"]>7.0: f.append(f"High entropy {summary['entropy']:.2f}/8.0 — encrypted/packed")
    f+=[s["description"] for s in sigs[:4]]
    return {"threat_level":lv,"confidence":0.70,"summary":f"Local scan: {summary['fn']} ({summary['ftype']}, {summary['size']:,}B). Risk {summary['risk']:.2f}. Groq unavailable.","key_findings":f or ["No obvious malicious indicators"],"threats":[s["description"] for s in sigs if s["severity"] in ("HIGH","CRITICAL")] or ["None detected"],"ttps":[],"iocs":[],"court_admissibility":"Hash values recorded. Section 65B chain of custody initiated.","recommendations":["Isolate","Notify senior analyst"] if lv in ("HIGH","CRITICAL") else ["Standard processing"],"_local_only":True}

def analyze(file_data,filename):
    t0=time.time()
    h=_hashes(file_data); ftype,fdesc=_detect_type(file_data,filename)
    entropy=_entropy(file_data); sigs=_scan_sigs(file_data)
    u=_urls(file_data); local_risk=_risk(ftype,entropy,sigs)
    stride=_stride(ftype,sigs,entropy,u); base_iocs=_iocs(u,sigs)
    hex_prev=_hex_preview(file_data); str_prev="\n".join(_strings(file_data)[:20])
    summary={"fn":filename,"size":len(file_data),"ftype":ftype,"sha256":h["sha256"],"entropy":entropy,"sigs":sigs,"risk":local_risk,"u":u}
    groq=None
    cached=db_groq_get(h["sha256"])
    if cached:
        try: groq=json.loads(cached["analysis_json"]); groq["_cached"]=True
        except: pass
    if not groq:
        groq=_call_groq(summary)
        if groq: db_groq_set(h["sha256"],json.dumps(groq),groq.get("_tokens",0))
    if not groq: groq=_fallback(summary,sigs)
    all_iocs=base_iocs+[{"type":i.get("type","?"),"value":i.get("value",""),"severity":i.get("severity","MEDIUM"),"description":i.get("description","")} for i in groq.get("iocs",[]) if i.get("value")]
    db_save_metric("evidence_analysis",int((time.time()-t0)*1000),fsize=len(file_data))
    return {"filename":filename,"file_size":len(file_data),"file_type":ftype,"file_type_desc":fdesc,"hashes":h,"entropy":round(entropy,3),"sigs_found":len(sigs),"sigs":sigs,"urls":u,"local_risk":round(local_risk,3),"risk_level":groq.get("threat_level",_level(local_risk)),"confidence":groq.get("confidence",0.7),"ai_summary":groq.get("summary",""),"findings":groq.get("key_findings",[]),"threats":groq.get("threats",[]),"ttps":groq.get("ttps",[]),"iocs":all_iocs,"court_admit":groq.get("court_admissibility",""),"recs":groq.get("recommendations",[]),"stride":stride,"groq_ok":not groq.get("_local_only",False),"cached":groq.get("_cached",False),"hex_preview":hex_prev,"strings_preview":str_prev,"proc_ms":int((time.time()-t0)*1000)}

def groq_narrative(case,ev_list):
    if not GROQ_KEY: return f"Case {case.get('case_number')} — {len(ev_list)} evidence items. AI narrative unavailable."
    lines="\n".join([f"- {e['original_filename']} | Risk:{e.get('risk_level','?')} | {e.get('file_type','?')}" for e in ev_list[:12]])
    prompt=f"""Write a formal 4-paragraph forensic investigation narrative for Indian court (Section 65B, DPDP 2023 compliant, ISO/IEC 27037:2012).
Case: {case.get('case_number')} — {case.get('title')} | FIR: {case.get('fir_number','')} | Agency: {case.get('agency','')}
Evidence ({len(ev_list)}):\n{lines}\nFormal legal prose. No markdown."""
    try:
        r=requests.post(GROQ_URL,headers={"Authorization":f"Bearer {GROQ_KEY}","Content-Type":"application/json"},json={"model":GROQ_MODEL,"messages":[{"role":"user","content":prompt}],"temperature":0.15,"max_tokens":700},timeout=30)
        r.raise_for_status(); return r.json()["choices"][0]["message"]["content"].strip()
    except: return f"Investigation of {case.get('case_number')} with {len(ev_list)} digital evidence items per ISO/IEC 27037."

def calc_pct(vals):
    if not vals: return {"p50":0,"p95":0,"p99":0,"mean":0,"min":0,"max":0,"count":0}
    s=sorted(vals); pct=lambda p:round(s[min(int(len(s)*p/100),len(s)-1)],1)
    return {"p50":pct(50),"p95":pct(95),"p99":pct(99),"mean":round(statistics.mean(s),1),"min":round(min(s),1),"max":round(max(s),1),"count":len(s)}

def get_benchmarks():
    ops=["evidence_analysis","blockchain_anchor","groq_analysis"]; r={}
    for op in ops: r[op]=calc_pct([m["duration_ms"] for m in db_metrics(op,300)])
    all_m=db_metrics(limit=1000); r["total_ops"]=len(all_m); r["groq_tokens"]=sum(m.get("groq_tokens",0) for m in all_m)
    return r

# ═══════════════════════════════════════════════════════════════════════════════
# PDF REPORT
# ═══════════════════════════════════════════════════════════════════════════════
def gen_report(case,ev_list,narrative="",officer="System"):
    if not HAS_PDF: return None,"pip install reportlab"
    fname=f"COC_v4_{case.get('case_number','CASE')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    fpath=str(Path("reports")/fname)
    DB_=rlc.HexColor("#1e3c72"); GOLD=rlc.HexColor("#c8a217"); LG=rlc.HexColor("#f5f5f5"); MG=rlc.HexColor("#cccccc")
    RC={"CRITICAL":rlc.HexColor("#c0392b"),"HIGH":rlc.HexColor("#e67e22"),"MEDIUM":rlc.HexColor("#f39c12"),"LOW":rlc.HexColor("#27ae60"),"MINIMAL":rlc.HexColor("#27ae60"),"UNKNOWN":rlc.gray}
    S=getSampleStyleSheet()
    sty={"T":ParagraphStyle("T",parent=S["Title"],fontSize=16,textColor=DB_,alignment=TA_CENTER,fontName="Helvetica-Bold"),
         "ST":ParagraphStyle("ST",parent=S["Normal"],fontSize=8.5,textColor=DB_,alignment=TA_CENTER),
         "SH":ParagraphStyle("SH",parent=S["Normal"],fontSize=11,textColor=rlc.white,backColor=DB_,fontName="Helvetica-Bold",leftIndent=6,spaceBefore=8,spaceAfter=3),
         "B":ParagraphStyle("B",parent=S["Normal"],fontSize=8.5,alignment=TA_JUSTIFY,leading=12),
         "H":ParagraphStyle("H",parent=S["Code"],fontSize=6.5,fontName="Courier"),
         "Bd":ParagraphStyle("Bd",parent=S["Normal"],fontSize=9,fontName="Helvetica-Bold")}
    def hf(canvas,doc):
        canvas.saveState(); w,h=A4
        canvas.setFillColor(DB_); canvas.rect(0,h-44,w,44,fill=1,stroke=0)
        canvas.setFillColor(GOLD); canvas.rect(0,h-47,w,3,fill=1,stroke=0)
        canvas.setFillColor(rlc.white); canvas.setFont("Helvetica-Bold",10)
        canvas.drawString(0.7*inch,h-24,"COC v4.0 — CHAIN OF CUSTODY EVIDENCE MANAGEMENT SYSTEM")
        canvas.setFont("Helvetica",6.5); canvas.drawRightString(w-0.7*inch,h-15,f"CLASSIFICATION: {case.get('classification','CONFIDENTIAL')} | {datetime.now().strftime('%d %b %Y %H:%M IST')}")
        canvas.setFillColor(DB_); canvas.rect(0,0,w,25,fill=1,stroke=0)
        canvas.setFillColor(rlc.white); canvas.setFont("Helvetica",6.5)
        canvas.drawString(0.7*inch,8,"Section 65B | DPDP Act 2023 | SHA-256 Batch Merkle Blockchain | ISO/IEC 27037:2012")
        canvas.drawRightString(w-0.7*inch,8,f"Page {doc.page}"); canvas.restoreState()
    doc=SimpleDocTemplate(fpath,pagesize=A4,leftMargin=0.7*inch,rightMargin=0.7*inch,topMargin=1.05*inch,bottomMargin=0.65*inch)
    st=[Spacer(1,0.1*inch),Paragraph("DIGITAL FORENSIC INVESTIGATION REPORT — v4.0",sty["T"]),Paragraph("Central Forensic Science Laboratory | Ministry of Home Affairs | Government of India",sty["ST"]),Spacer(1,0.08*inch),HRFlowable(width="100%",thickness=2,color=GOLD),Spacer(1,0.1*inch)]
    hs,sc=case_health(case["id"])
    ci=[["Case No.:",case.get("case_number","N/A"),"Priority:",case.get("priority","?"),"FIR:",case.get("fir_number","N/A")],["Title:",case.get("title","N/A")[:40],"Status:",case.get("status","?"),"Agency:",case.get("agency","N/A")],["Classification:",case.get("classification","?"),"Evidence:",str(len(ev_list)),"Health:",f"{hs}/100"],["Officer:",officer[:30],"Date:",datetime.now().strftime("%d %b %Y"),"Report ID:",secrets.token_hex(4).upper()]]
    ct=Table(ci,colWidths=[0.9*inch,1.55*inch,0.9*inch,1.35*inch,0.7*inch,1.3*inch])
    ct.setStyle(TableStyle([("FONTNAME",(0,0),(-1,-1),"Helvetica"),("FONTNAME",(0,0),(0,-1),"Helvetica-Bold"),("FONTNAME",(2,0),(2,-1),"Helvetica-Bold"),("FONTNAME",(4,0),(4,-1),"Helvetica-Bold"),("FONTSIZE",(0,0),(-1,-1),7.5),("ROWBACKGROUNDS",(0,0),(-1,-1),[LG,rlc.white]),("GRID",(0,0),(-1,-1),0.4,MG),("TOPPADDING",(0,0),(-1,-1),3),("BOTTOMPADDING",(0,0),(-1,-1),3)]))
    st+=[ct,Spacer(1,0.1*inch)]
    if case.get("description"): st+=[Paragraph("CASE OVERVIEW",sty["SH"]),Paragraph(case["description"],sty["B"]),Spacer(1,0.08*inch)]
    if narrative: st+=[Paragraph("AI-ASSISTED INVESTIGATION NARRATIVE (Groq llama-3.3-70b-versatile)",sty["SH"]),Paragraph(narrative.replace("\n","<br/>"),sty["B"]),Spacer(1,0.08*inch)]
    st.append(Paragraph("EVIDENCE INVENTORY",sty["SH"]))
    eh=[["#","Evidence No.","Filename","Type","Risk","Confidence","Entropy","Merkle Block"]]
    for i,e in enumerate(ev_list,1):
        sz=e.get("file_size",0); ss=f"{sz/1024:.0f}KB" if sz<1048576 else f"{sz/1048576:.1f}MB"
        eh.append([str(i),e.get("evidence_number","N/A"),e.get("original_filename","N/A")[:26],e.get("file_type","?"),e.get("risk_level","?"),f"{e.get('confidence',0):.0%}",f"{e.get('entropy',0):.2f}",f"#{e.get('blockchain_block','—')}"])
    et=Table(eh,colWidths=[0.25*inch,1.1*inch,1.8*inch,0.8*inch,0.7*inch,0.7*inch,0.55*inch,0.75*inch])
    es=[("BACKGROUND",(0,0),(-1,0),DB_),("TEXTCOLOR",(0,0),(-1,0),rlc.white),("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),("FONTSIZE",(0,0),(-1,-1),7),("ALIGN",(0,0),(-1,-1),"CENTER"),("GRID",(0,0),(-1,-1),0.3,MG),("ROWBACKGROUNDS",(0,1),(-1,-1),[rlc.white,LG]),("TOPPADDING",(0,0),(-1,-1),2),("BOTTOMPADDING",(0,0),(-1,-1),2)]
    for i,e in enumerate(ev_list,1):
        rc=RC.get(e.get("risk_level","UNKNOWN"),rlc.gray); es+=[("TEXTCOLOR",(4,i),(4,i),rc),("FONTNAME",(4,i),(4,i),"Helvetica-Bold")]
    et.setStyle(TableStyle(es)); st+=[et,Spacer(1,0.12*inch)]
    st.append(Paragraph("DETAILED EVIDENCE ANALYSIS",sty["SH"]))
    for e in ev_list:
        rc=RC.get(e.get("risk_level","UNKNOWN"),rlc.gray)
        dr=[["Risk:",e.get("risk_level","?"),"Type:",e.get("file_type","?"),"Confidence:",f"{e.get('confidence',0):.0%}"],["Size:",f"{e.get('file_size',0):,}B","By:",e.get("uploaded_by","?"),"Entropy:",f"{e.get('entropy',0):.3f}"],["Location:",e.get("location","—")[:25],"Date:",str(e.get("uploaded_at",""))[:16],"Block:",f"#{e.get('blockchain_block','—')}"]]
        dt=Table(dr,colWidths=[0.7*inch,1.5*inch,0.6*inch,1.5*inch,0.7*inch,1.65*inch])
        dt.setStyle(TableStyle([("FONTNAME",(0,0),(0,-1),"Helvetica-Bold"),("FONTNAME",(2,0),(2,-1),"Helvetica-Bold"),("FONTNAME",(4,0),(4,-1),"Helvetica-Bold"),("FONTSIZE",(0,0),(-1,-1),7),("GRID",(0,0),(-1,-1),0.3,MG),("ROWBACKGROUNDS",(0,0),(-1,-1),[LG,rlc.white]),("TOPPADDING",(0,0),(-1,-1),2),("BOTTOMPADDING",(0,0),(-1,-1),2),("TEXTCOLOR",(1,0),(1,0),rc),("FONTNAME",(1,0),(1,0),"Helvetica-Bold")]))
        items=[Spacer(1,4),Paragraph(f"{e.get('evidence_number','N/A')} — {e.get('original_filename','N/A')}",sty["Bd"]),dt]
        if e.get("sha256_hash"): items+=[Spacer(1,2),Paragraph(f"SHA-256: {e['sha256_hash']}",sty["H"]),Paragraph(f"MD5: {e.get('md5_hash','N/A')} | Merkle: {e.get('merkle_root','N/A')[:32]}... | TX: {str(e.get('tx_hash',''))[:28]}...",sty["H"])]
        if e.get("ai_summary"): items+=[Spacer(1,3),Paragraph("Forensic Assessment:",sty["Bd"]),Paragraph(e["ai_summary"],sty["B"])]
        items.append(HRFlowable(width="100%",thickness=0.5,color=MG,spaceAfter=2)); st+=items
    st.append(PageBreak())
    st+=[Paragraph("CERTIFICATE UNDER SECTION 65B",sty["T"]),Paragraph("Indian Evidence Act, 1872 | Information Technology Act, 2000 | DPDP Act, 2023",sty["ST"]),Spacer(1,0.1*inch),HRFlowable(width="100%",thickness=2,color=GOLD),Spacer(1,0.1*inch)]
    cert=f"""I, <b>{officer}</b>, being responsible for the computer system used in generating these electronic records, certify:

1. Records produced by a computer in ordinary course of criminal investigation (Section 65B(2)(a) IEA 1872).
2. Computer operating properly throughout relevant period (Section 65B(2)(b), 65B(2)(c)).
3. SHA-256 and MD5 hash values are forensically sound identifiers per ISO/IEC 27037:2012.
4. Batch Merkle-tree blockchain anchoring ensures tamper-evident chain of custody. O(log n) verification.
5. All personal data handled per Digital Personal Data Protection Act, 2023 (DPDP Act).
6. AI analysis (Groq llama-3.3-70b) conducted under human expert supervision.

<b>Case:</b> {case.get('case_number','N/A')} — {case.get('title','N/A')}
<b>FIR:</b> {case.get('fir_number','N/A')} | <b>Agency:</b> {case.get('agency','N/A')}
<b>Case Health Score:</b> {hs}/100 | <b>Evidence Items:</b> {len(ev_list)} | <b>Date:</b> {datetime.now().strftime('%d %B %Y')}"""
    st+=[Paragraph(cert,sty["B"]),Spacer(1,0.3*inch)]
    sigt=Table([["Signature of Certifying Officer:","","Date:"],[officer,"",datetime.now().strftime("%d/%m/%Y")],["","",""],["Designation / Badge No.:","","Official Seal:"]],colWidths=[3*inch,0.5*inch,3.15*inch])
    sigt.setStyle(TableStyle([("FONTNAME",(0,0),(-1,-1),"Helvetica"),("FONTNAME",(0,0),(0,0),"Helvetica-Bold"),("FONTNAME",(2,0),(2,0),"Helvetica-Bold"),("FONTSIZE",(0,0),(-1,-1),9),("TOPPADDING",(0,0),(-1,-1),7),("LINEBELOW",(0,1),(0,1),1,rlc.black),("LINEBELOW",(2,1),(2,1),1,rlc.black)]))
    st+=[sigt,Spacer(1,0.15*inch),Paragraph("Issued under Section 65B IEA 1872. Admissible in any competent court. Tampering constitutes offence under S.65/66/66B IT Act 2000 and S.77 BNS 2023.",ParagraphStyle("D",fontSize=7,textColor=rlc.gray,alignment=TA_JUSTIFY))]
    doc.build(st,onFirstPage=hf,onLaterPages=hf)
    return fpath,None

# ═══════════════════════════════════════════════════════════════════════════════
# FLASK + DASH
# ═══════════════════════════════════════════════════════════════════════════════
server=Flask(__name__)
server.config["SECRET_KEY"]=_SECRET
server.config["MAX_CONTENT_LENGTH"]=500*1024*1024
CORS(server)

app=dash.Dash(__name__,server=server,
    external_stylesheets=[dbc.themes.DARKLY,"https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css"],
    suppress_callback_exceptions=True,title="COC v4.0",update_title=None)

CSS="""
body{background:#070d18;font-family:'Segoe UI',sans-serif}
.topbar{background:linear-gradient(135deg,#0a1628,#1e3c72)!important;border-bottom:3px solid #c8a217}
.statsbar{background:#0c1525;border-bottom:1px solid #1a2d45;padding:.35rem 1rem}
.tabstrip{background:#0c1525;border-bottom:1px solid #1a2d45}
.sc{background:linear-gradient(135deg,#0f1a2e,#172640);border:1px solid rgba(255,255,255,.07);border-radius:12px;transition:all .2s}
.sc:hover{transform:translateY(-3px);box-shadow:0 6px 20px rgba(79,172,254,.18)}
.sn{font-size:2.2rem;font-weight:900;line-height:1.1}
.uz{border:2px dashed #4facfe;border-radius:12px;padding:2rem;text-align:center;background:rgba(79,172,254,.03);cursor:pointer;transition:all .2s}
.uz:hover{background:rgba(79,172,254,.08);border-color:#00f2fe}
.ev-item{background:#0c1525;border:1px solid #1a2d45;border-radius:8px;padding:.65rem;margin-bottom:.4rem;cursor:pointer;transition:border-color .15s}
.ev-item:hover{border-color:#4facfe}
.ev-item.sel{border-color:#c8a217;background:#101e30}
.hex{background:#020509;color:#4facfe;font-family:'Courier New',monospace;font-size:.65rem;padding:.7rem;border-radius:6px;white-space:pre;overflow-x:auto;border:1px solid #1a2d45;max-height:200px;overflow-y:auto}
.stride-i{background:#070e1a;border:1px solid #1a2d45;border-radius:5px;padding:.4rem;margin-bottom:.25rem;font-size:.78rem}
.ioc-line{font-family:monospace;font-size:.7rem}
.cb{background:#040810;border:1px solid #1a2d45;border-radius:6px;padding:.5rem;font-family:'Courier New',monospace;font-size:.68rem;margin-bottom:.35rem;border-left:3px solid #c8a217}
.health-bar .progress-bar{transition:width .5s ease}
.timeline-item{border-left:2px solid #1a2d45;padding-left:1rem;margin-bottom:.8rem;position:relative}
.timeline-item::before{content:'';position:absolute;left:-5px;top:4px;width:8px;height:8px;border-radius:50%;background:#4facfe}
.cmp-panel{background:#0c1525;border:1px solid #1a2d45;border-radius:10px;padding:.8rem}
.alert-item{border-left:3px solid #dc3545;background:#0f0a0a;padding:.5rem;border-radius:0 6px 6px 0;margin-bottom:.35rem}
.alert-item.info{border-left-color:#4facfe;background:#050c18}
.alert-item.warning{border-left-color:#ffc107;background:#100e02}
input,select,textarea{background:#0c1525!important;color:#c9d1d9!important;border-color:#1a2d45!important}
"""

RCOL={"CRITICAL":"danger","HIGH":"warning","MEDIUM":"warning","LOW":"success","MINIMAL":"success","UNKNOWN":"secondary"}
RICON={"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🟢","MINIMAL":"⚪","UNKNOWN":"⚫"}
PCOL={"CRITICAL":"#dc3545","HIGH":"#fd7e14","MEDIUM":"#ffc107","LOW":"#198754"}
SK=["spoofing","tampering","repudiation","info_disclosure","dos","elevation"]
SL=["S — Spoofing","T — Tampering","R — Repudiation","I — Info Disclosure","D — DoS","E — Elevation"]

def ic(cls,**kw): return html.I(className=cls,**kw)
def bdg(t,c="secondary"): return dbc.Badge(t,color=c,pill=True,className="me-1")
def rbdg(rl): return bdg(f"{RICON.get(rl,'⚫')} {rl}",RCOL.get(rl,"secondary"))
def sh(title,icls="fas fa-circle"): return html.H6([ic(icls+" me-2"),title],style={"color":"#4facfe","fontWeight":"700","borderBottom":"1px solid #1a2d45","paddingBottom":".25rem","marginBottom":".7rem"})

def sc(val,label,icls,col="#4facfe",w=3):
    return dbc.Col([html.Div([html.Div(ic(icls,style={"fontSize":"1.6rem","color":col}),className="mb-1"),html.Div(str(val),className="sn",style={"color":col}),html.Div(label,style={"color":"#8b949e","fontSize":".68rem","textTransform":"uppercase","letterSpacing":"1.2px","marginTop":"2px"})],className="sc p-3 text-center")],width=w)

def tbl(headers,rows,**kw):
    return dbc.Table([html.Thead(html.Tr([html.Th(h,style={"fontSize":".75rem"}) for h in headers])),html.Tbody(rows or [html.Tr([html.Td("—",colSpan=len(headers),className="text-muted text-center small")])])],color="dark",hover=True,size="sm",**kw)

def health_bar(score):
    col="success" if score>=70 else "warning" if score>=40 else "danger"
    return html.Div([html.Div([html.Small(f"Case Health: ",className="text-muted"),html.Strong(f"{score}/100",style={"color":PCOL.get("HIGH","#fd7e14") if score<40 else PCOL.get("MEDIUM","#ffc107") if score<70 else "#198754"})]),dbc.Progress(value=score,color=col,style={"height":"6px"},className="mt-1 health-bar")])

# ─────────────────────────────────────────────────────────────────────────────
# LOGIN
# ─────────────────────────────────────────────────────────────────────────────
def login_page():
    portals=[("admin","fas fa-crown","danger","Admin","L5"),("analyst","fas fa-microscope","success","Analyst","L4"),("investigator","fas fa-search","warning","Investigator","L3"),("forensic","fas fa-dna","info","Forensic","L4"),("officer","fas fa-shield-alt","secondary","Officer","L2"),("legal","fas fa-balance-scale","light","Legal","L3")]
    return dbc.Container([dbc.Row([dbc.Col([
        html.Div([ic("fas fa-shield-halved fa-3x text-primary mb-2"),html.H1("COC v4.0",className="display-5 fw-bold mb-0"),html.P("Chain of Custody | Batch Merkle | Groq AI | Alerts | Health Score",className="text-muted small mb-2"),html.Div([bdg([ic("fas fa-circle-dot me-1"),"Operational"],"success"),bdg([ic("fas fa-robot me-1"),"Groq AI" if GROQ_KEY else "Local AI"],"success" if GROQ_KEY else "warning"),bdg([ic("fas fa-link me-1"),"Indexed DB"],"primary"),bdg([ic("fas fa-bell me-1"),"Alerts"],"warning")])],className="text-center mb-3"),
        html.Div(id="la"),
        dbc.Card([dbc.CardBody([
            dbc.InputGroup([dbc.InputGroupText(ic("fas fa-user")),dbc.Input(id="lu",placeholder="Username",type="text",n_submit=0)],className="mb-2"),
            dbc.InputGroup([dbc.InputGroupText(ic("fas fa-lock")),dbc.Input(id="lp",placeholder="Password",type="password",n_submit=0)],className="mb-3"),
            dbc.Button([ic("fas fa-sign-in-alt me-2"),"Login"],id="lb",color="primary",size="lg",className="w-100"),
        ])],className="mb-3 bg-dark border-secondary"),
        html.Small("Quick Access",className="text-muted d-block text-center mb-2"),
        dbc.Row([dbc.Col([dbc.Button([ic(i+" fa-lg mb-1 d-block mx-auto"),html.Strong(r,className="d-block"),html.Small(cl,className="text-muted d-block")],id={"type":"pb","index":u},color=c,outline=True,className="w-100 py-2",style={"height":"78px","fontSize":".72rem"})],width=4,className="mb-2") for u,i,c,r,cl in portals]),
    ],width=12,md=6,className="mx-auto")])],fluid=True,className="min-vh-100 d-flex align-items-center")

# ─────────────────────────────────────────────────────────────────────────────
# MAIN SHELL  — statsbar always visible
# ─────────────────────────────────────────────────────────────────────────────
def main_shell():
    return html.Div([
        dbc.Navbar([dbc.Container([
            dbc.NavbarBrand([ic("fas fa-shield-halved me-2 text-warning"),html.Span("COC v4.0",className="fw-bold")],className="fs-5"),
            dbc.InputGroup([dbc.InputGroupText(ic("fas fa-search",style={"fontSize":".8rem"})),dbc.Input(id="gs-input",placeholder="Global search: filename, hash, IOC...",debounce=True,style={"maxWidth":"320px","fontSize":".8rem"})],className="me-3",size="sm"),
            dbc.Nav([html.Div(id="ni",className="d-flex align-items-center gap-2")],className="ms-auto"),
        ],fluid=True)],dark=True,className="topbar mb-0"),
        # Stats bar — always visible, auto-refreshes
        html.Div(id="statsbar",className="statsbar"),
        # Global search results
        html.Div(id="gs-results"),
        html.Div([dbc.Tabs(id="tabs",active_tab="home",className="px-3 pt-2 border-0",children=[
            dbc.Tab(label="Home",        tab_id="home",  label_style={"color":"#8b949e"},active_label_style={"color":"#4facfe","fontWeight":"700"}),
            dbc.Tab(label="Evidence",    tab_id="ev",    label_style={"color":"#8b949e"},active_label_style={"color":"#4facfe","fontWeight":"700"}),
            dbc.Tab(label="Upload",      tab_id="up",    label_style={"color":"#8b949e"},active_label_style={"color":"#4facfe","fontWeight":"700"}),
            dbc.Tab(label="Cases",       tab_id="cases", label_style={"color":"#8b949e"},active_label_style={"color":"#4facfe","fontWeight":"700"}),
            dbc.Tab(label="Intelligence",tab_id="intel", label_style={"color":"#8b949e"},active_label_style={"color":"#c8a217","fontWeight":"700"}),
            dbc.Tab(label="Chain",       tab_id="chain", label_style={"color":"#8b949e"},active_label_style={"color":"#6f42c1","fontWeight":"700"}),
            dbc.Tab(label="Reports",     tab_id="rpt",   label_style={"color":"#8b949e"},active_label_style={"color":"#dc3545","fontWeight":"700"}),
            dbc.Tab(label="Benchmarks",  tab_id="bench", label_style={"color":"#8b949e"},active_label_style={"color":"#198754","fontWeight":"700"}),
            dbc.Tab(label="Admin",       tab_id="adm",   label_style={"color":"#8b949e"},active_label_style={"color":"#dc3545","fontWeight":"700"}),
        ])],className="tabstrip"),
        dbc.Container([html.Div(id="tc",className="py-3")],fluid=True,className="px-3"),
        dcc.Interval(id="ri",interval=60000,n_intervals=0),
        dcc.Store(id="ev-page",data=0),
        dcc.Store(id="cmp-a"),
        dcc.Store(id="cmp-b"),
    ])

# ─────────────────────────────────────────────────────────────────────────────
# HOME — alerts + role panel + stats
# ─────────────────────────────────────────────────────────────────────────────
def tab_home(user):
    stats=db_stats(); cases=db_cases(user["clearance_level"]); ev=db_ev(limit=300)
    alerts=db_alerts(10)
    role=user["role"]
    rc=defaultdict(int); sc_cnt=defaultdict(int)
    for e in ev: rc[e.get("risk_level","UNKNOWN")]+=1
    for c in cases: sc_cnt[c.get("status","?")]+=1
    pie=go.Figure(data=[go.Pie(labels=list(rc.keys()),values=list(rc.values()),hole=0.55,marker_colors=["#dc3545","#fd7e14","#ffc107","#198754","#6c757d","#adb5bd"],textfont_size=9)])
    pie.update_layout(paper_bgcolor="rgba(0,0,0,0)",plot_bgcolor="rgba(0,0,0,0)",font_color="#8b949e",showlegend=True,legend=dict(bgcolor="rgba(0,0,0,0)",font_size=9),margin=dict(l=5,r=5,t=5,b=5),height=170)
    # Role panel
    if role=="admin":
        rp=dbc.Card([dbc.CardBody([sh("Admin Overview","fas fa-crown"),dbc.Row([sc(stats["total_users"],"Users","fas fa-users","#fd7e14",4),sc(stats["total_transfers"],"Transfers","fas fa-exchange-alt","#6f42c1",4),sc(stats["total_iocs"],"IOCs","fas fa-bug","#0dcaf0",4)]),html.Hr(style={"borderColor":"#1a2d45"}),html.Small([bdg(f"DB Indexed ✓","success"),bdg(f"Blocks: {len(db_blockchain())}","dark"),bdg(f"Groq: {'✓' if GROQ_KEY else 'Local'}","success" if GROQ_KEY else "warning")])])],className="bg-dark border-secondary")
    elif role in ("analyst","forensic"):
        hi=[e for e in ev if e.get("risk_level") in ("HIGH","CRITICAL")]
        rp=dbc.Card([dbc.CardBody([sh("Forensic Queue","fas fa-microscope"),html.P(f"{len(hi)} items need expert review",className="small text-warning mb-2"),html.Div([html.Div([rbdg(e.get("risk_level","?")),html.Small(e.get("original_filename","?")[:28],className="ms-1")],className="mb-1") for e in hi[:6]])])],className="bg-dark border-secondary")
    elif role=="investigator":
        mc=[c for c in cases if c.get("status")=="Active"]
        rp=dbc.Card([dbc.CardBody([sh("Active Cases","fas fa-search"),html.Div([html.Div([html.Code(c.get("case_number",""),style={"fontSize":".7rem","color":"#4facfe"}),html.Span(f" {c.get('title','')[:28]}",className="small ms-1"),html.Small(f" [{len(db_ev(c['id']))}ev]",className="text-muted")],className="mb-1") for c in mc[:6]])])],className="bg-dark border-secondary")
    else:
        rp=dbc.Card([dbc.CardBody([sh("Recent Cases","fas fa-folder"),html.Div([html.Div([html.Code(c.get("case_number",""),style={"fontSize":".7rem","color":"#4facfe"}),html.Span(f" {c.get('title','')[:30]}",className="small ms-1")],className="mb-1") for c in cases[:6]])])],className="bg-dark border-secondary")

    # Alerts panel
    def alert_color(sev): return {"CRITICAL":"danger","HIGH":"warning","MEDIUM":"warning","INFO":"info"}.get(sev,"secondary")
    alert_html=[html.Div([html.Div([bdg(a.get("severity","INFO"),alert_color(a.get("severity","INFO"))),html.Strong(a.get("title",""),className="small me-2"),html.Small(a.get("message","")[:60],className="text-muted")]),html.Small(a.get("created_at","")[:16],className="text-muted d-block")],className=f"alert-item {'info' if a.get('severity')=='INFO' else 'warning' if 'WARN' in a.get('severity','') else ''}",style={"marginBottom":".3rem"}) for a in alerts]

    ev_rows=[html.Tr([html.Td(html.Code(e.get("evidence_number","")[:12],style={"fontSize":".7rem","color":"#4facfe"})),html.Td(e.get("original_filename","")[:22],className="small"),html.Td(rbdg(e.get("risk_level","?"))),html.Td(html.Small(e.get("uploaded_at","")[:16],className="text-muted"))]) for e in ev[:8]]
    return html.Div([
        dbc.Alert([ic("fas fa-user-shield me-2"),html.Strong(user["full_name"]),html.Span(f" | {user['department']} | {CLEARANCE.get(user['clearance_level'],'?')} | {user['role'].upper()}",className="text-muted small ms-1")],color="dark",className="mb-3 py-2 border-secondary",style={"borderLeft":"4px solid #c8a217"}),
        dbc.Row([sc(stats["total_evidence"],"Evidence","fas fa-database","#4facfe"),sc(stats["total_cases"],"Cases","fas fa-folder-open","#c8a217"),sc(stats["active_cases"],"Active","fas fa-spinner","#198754"),sc(stats["high_risk"],"High/Critical","fas fa-exclamation-triangle","#dc3545")],className="mb-3"),
        dbc.Row([
            dbc.Col([dbc.Card([dbc.CardBody([sh("Risk Distribution","fas fa-chart-pie"),dcc.Graph(figure=pie,config={"displayModeBar":False})])],className="bg-dark border-secondary")],md=3),
            dbc.Col([dbc.Card([dbc.CardBody([sh("Recent Evidence","fas fa-file-shield"),tbl(["ID","Filename","Risk","Time"],ev_rows)])],className="bg-dark border-secondary")],md=5),
            dbc.Col([rp],md=4),
        ],className="mb-3"),
        dbc.Row([
            dbc.Col([dbc.Card([dbc.CardBody([sh(f"Alerts ({len(alerts)})","fas fa-bell"),html.Div(alert_html or [html.Small("No alerts",className="text-muted")],style={"maxHeight":"180px","overflowY":"auto"}),dbc.Button([ic("fas fa-check me-1"),"Mark All Read"],id="mark-all-read",color="secondary",outline=True,size="sm",className="mt-2") if alerts else html.Span(),html.Div(id="alert-ack")])],className="bg-dark border-secondary")],md=4),
            dbc.Col([dbc.Card([dbc.CardBody([sh("Audit Trail","fas fa-history"),html.Div([html.Div([html.Small(l.get("timestamp","")[:16],className="text-muted me-2 font-monospace"),html.Small(l.get("username","?"),className="text-primary me-2"),html.Small(l.get("action","?"),className="text-light"),html.Small(f" {l.get('details','')[:35]}",className="text-muted")]) for l in db_logs(8)])])],className="bg-dark border-secondary")],md=4),
            dbc.Col([dbc.Card([dbc.CardBody([sh("Chain Status","fas fa-link"),html.Div(id="home-chain")])],className="bg-dark border-secondary")],md=4),
        ]),
    ])

# ─────────────────────────────────────────────────────────────────────────────
# EVIDENCE — paginated + comparison
# ─────────────────────────────────────────────────────────────────────────────
def tab_evidence(user):
    cases=db_cases(user["clearance_level"])
    copts=[{"label":"All Cases","value":""}]+[{"label":f"{c['case_number']} — {c['title'][:28]}","value":c["id"]} for c in cases]
    return html.Div([
        html.H5([ic("fas fa-database me-2 text-primary"),"Evidence Browser"],className="mb-2"),
        dbc.Row([
            dbc.Col([dbc.InputGroup([dbc.InputGroupText(ic("fas fa-search")),dbc.Input(id="ev-q",placeholder="Search filename, hash, tag, description...",debounce=True)],size="sm")],md=4),
            dbc.Col([dcc.Dropdown(id="ev-cf",options=copts,value="",clearable=False,style={"fontSize":".8rem"})],md=3),
            dbc.Col([dbc.Select(id="ev-rf",options=[{"label":"All Risks","value":""},{"label":"🔴 Critical","value":"CRITICAL"},{"label":"🟠 High","value":"HIGH"},{"label":"🟡 Medium","value":"MEDIUM"},{"label":"🟢 Low","value":"LOW"}],value="",size="sm")],md=2),
            dbc.Col([dbc.Select(id="ev-tf",options=[{"label":"All Types","value":""},{"label":"Executable","value":"EXECUTABLE"},{"label":"Script","value":"SCRIPT"},{"label":"Document","value":"DOCUMENT"},{"label":"Archive","value":"ARCHIVE"},{"label":"Image","value":"IMAGE"},{"label":"PCAP","value":"PCAP"}],value="",size="sm")],md=2),
            dbc.Col([dbc.Button(ic("fas fa-download"),id="ev-exp",color="secondary",outline=True,size="sm",className="w-100")],md=1),
        ],className="mb-2 g-1"),
        # Compare bar
        html.Div(id="cmp-bar",children=[dbc.Alert([ic("fas fa-info-circle me-2 small"),"Select two evidence items using the ☐ checkbox to compare them side by side."],color="dark",className="py-1 small border-secondary mb-2")]),
        dbc.Row([
            dbc.Col([
                html.Div(id="ev-list",style={"maxHeight":"72vh","overflowY":"auto"}),
                html.Div(id="ev-pager",className="mt-2"),
            ],md=5),
            dbc.Col([html.Div(id="ev-detail",style={"background":"#0c1525","border":"1px solid #1a2d45","borderRadius":"10px","padding":"1rem","minHeight":"200px"},children=[html.P([ic("fas fa-hand-pointer me-2 text-muted"),"Click an item to view details"],className="text-muted text-center mt-4 small")])],md=7),
        ]),
        dcc.Download(id="ev-csv"),
        dcc.Store(id="ev-sel"),
    ])

def render_ev_list(rows,total,page):
    if not rows:
        return html.P("No evidence found.",className="text-muted small p-2"),html.Span()
    items=[html.Div([
        dbc.Row([
            dbc.Col([dbc.Checkbox(id={"type":"ev-chk","index":e["id"]},className="me-1",value=False)],width="auto",className="d-flex align-items-center"),
            dbc.Col([html.Div([rbdg(e.get("risk_level","UNKNOWN")),bdg(e.get("file_type","?"),"info")]),html.Strong(e.get("original_filename","?")[:32],className="d-block small mt-1"),html.Small(html.Code(e.get("sha256_hash","")[:22]+"...",style={"fontSize":".62rem","color":"#8b949e"}))],md=8),
            dbc.Col([html.Small(f"{e.get('file_size',0)//1024}KB" if e.get("file_size",0)<1048576 else f"{e.get('file_size',0)//1048576}MB",className="text-muted d-block"),html.Small(f"E:{e.get('entropy',0):.2f}",className="text-muted d-block"),html.Small(e.get("uploaded_at","")[:10],className="text-muted d-block")],md=3),
        ],className="g-1"),
    ],id={"type":"ev-row","index":e["id"]},className="ev-item",n_clicks=0) for e in rows]
    total_pages=math.ceil(total/PER_PAGE)
    pager=html.Div([
        html.Small(f"Showing {page*PER_PAGE+1}–{min((page+1)*PER_PAGE,total)} of {total}",className="text-muted me-3"),
        dbc.ButtonGroup([dbc.Button(ic("fas fa-chevron-left"),id="ev-prev",color="secondary",outline=True,size="sm",disabled=page==0),dbc.Button(ic("fas fa-chevron-right"),id="ev-next",color="secondary",outline=True,size="sm",disabled=page>=total_pages-1)]),
    ],className="d-flex align-items-center") if total>PER_PAGE else html.Small(f"{total} items",className="text-muted")
    return html.Div(items),pager

def render_ev_detail(ev):
    if not ev: return html.P("Not found",className="text-muted small")
    rl=ev.get("risk_level","UNKNOWN")
    def jl(k): 
        v=ev.get(k,"[]")
        try: return json.loads(v) if v else []
        except: return []
    threats=jl("ai_threats"); recs=jl("ai_recommendations"); iocs=jl("ai_iocs"); ttps=jl("ai_ttps")
    return html.Div([
        html.Div([rbdg(rl),bdg(ev.get("file_type","?"),"info"),bdg(f"#{ev.get('blockchain_block','—')}","dark"),dbc.Button([ic("fas fa-external-link-alt me-1"),"VirusTotal"],href=f"https://www.virustotal.com/gui/file/{ev.get('sha256_hash','')}",target="_blank",color="primary",outline=True,size="sm",className="ms-1")],className="mb-2"),
        html.H6(ev.get("original_filename","?"),className="mb-1 small"),
        dbc.Tabs([
            dbc.Tab(label="Overview",tab_id="ov",children=[html.Div([
                dbc.Row([dbc.Col([html.Small("SHA-256",className="text-muted d-block"),html.Code(ev.get("sha256_hash",""),style={"fontSize":".62rem","color":"#4facfe","wordBreak":"break-all"})]),dbc.Col([html.Small("MD5",className="text-muted d-block"),html.Code(ev.get("md5_hash",""),style={"fontSize":".62rem","color":"#c8a217"})])],className="mb-2"),
                dbc.Row([dbc.Col([html.Small("SHA-1",className="text-muted d-block"),html.Code(ev.get("sha1_hash",""),style={"fontSize":".62rem","color":"#8b949e"})]),dbc.Col([html.Small("Merkle",className="text-muted d-block"),html.Code((ev.get("merkle_root","")[:26]+"..." if ev.get("merkle_root") else "N/A"),style={"fontSize":".62rem","color":"#6f42c1"})])],className="mb-2"),
                dbc.Row([dbc.Col([html.Small("Size",className="text-muted"),html.Div(f"{ev.get('file_size',0):,}B",className="small")]),dbc.Col([html.Small("Entropy",className="text-muted"),html.Div(f"{ev.get('entropy',0):.4f}",className="small")]),dbc.Col([html.Small("Sigs",className="text-muted"),html.Div(str(ev.get("signatures_found",0)),className="small")]),dbc.Col([html.Small("Conf",className="text-muted"),html.Div(f"{ev.get('confidence',0):.0%}",className="small")])],className="mb-2"),
                html.Hr(style={"borderColor":"#1a2d45","margin":".3rem 0"}),
                html.Div(ev.get("ai_summary","No AI analysis"),className="small text-muted mb-1"),
                html.Div([html.Strong("Threats: ",className="small text-danger"),html.Span(", ".join(threats[:3]),className="small text-muted")]) if threats else html.Span(),
                html.Div([html.Strong("TTPs: ",className="small text-info"),html.Span(", ".join(ttps[:3]),className="small text-muted")]) if ttps else html.Span(),
                html.Div([html.Strong("Actions: ",className="small text-success"),html.Small("; ".join(recs[:2]),className="text-muted")]) if recs else html.Span(),
                html.Hr(style={"borderColor":"#1a2d45","margin":".3rem 0"}),
                html.Small([html.Span("Location: ",className="text-muted"),ev.get("location","—")],className="d-block"),
                html.Small([html.Span("Uploaded by: ",className="text-muted"),html.Span(ev.get("uploaded_by","?"),className="text-primary"),html.Span(f" · {ev.get('uploaded_at','')[:16]}",className="text-muted")]),
            ],className="pt-2")]),
            dbc.Tab(label="Hex",tab_id="hex",children=[html.Div(ev.get("hex_preview","No hex data") or "No hex data",className="hex mt-2")]),
            dbc.Tab(label="Strings",tab_id="str",children=[html.Pre(ev.get("strings_preview","No strings") or "No strings",style={"color":"#c9d1d9","fontSize":".68rem","background":"#020509","padding":".6rem","borderRadius":"6px","maxHeight":"200px","overflowY":"auto","border":"1px solid #1a2d45"},className="mt-2")]),
            dbc.Tab(label="STRIDE",tab_id="stride",children=[html.Div([html.Div([html.Strong(l+": ",className="small",style={"color":"#4facfe"}),html.Small(ev.get(f"stride_{k}","Not assessed")[:80],className="text-muted")],className="stride-i") for k,l in zip(SK,SL)],className="mt-2")]),
            dbc.Tab(label=f"IOCs ({len(iocs)})",tab_id="iocs",children=[html.Div([html.Div([bdg(i.get("type","?"),"info"),html.Code(i.get("value","")[:45],className="ioc-line me-2"),bdg(i.get("severity","?"),RCOL.get(i.get("severity","?"),"secondary")),html.Small(i.get("description",""),className="text-muted")],className="mb-1") for i in iocs] or [html.P("No IOCs",className="text-muted small")],className="mt-2")]),
            dbc.Tab(label="Chain",tab_id="ch",children=[html.Div([html.Small([ic("fas fa-link me-1 text-primary"),"Block: ",html.Strong(f"#{ev.get('blockchain_block','—')}",className="text-primary")],className="d-block mb-1"),html.Small([ic("fas fa-hashtag me-1 text-muted"),"TX: "],className="text-muted"),html.Code(str(ev.get("tx_hash","N/A"))[:36]+"...",style={"fontSize":".62rem"}),html.Hr(style={"borderColor":"#1a2d45"}),html.Strong("Transfer History",className="small d-block mb-1"),html.Div([html.Div([html.Small(f"{t.get('from_user','?')} → {t.get('to_user','?')}",className="text-primary"),html.Small(f" · {t.get('purpose','')[:30]}",className="text-muted"),html.Small(f" · {t.get('timestamp','')[:16]}",className="text-muted d-block"),html.Code(t.get("transfer_hash","")[:20]+"...",style={"fontSize":".6rem","color":"#8b949e"})],className="mb-1") for t in db_transfers(ev["id"],10)] or [html.Small("No transfers",className="text-muted")])],className="mt-2")]),
        ],className="mt-1"),
    ])

def render_comparison(ev_a,ev_b):
    if not ev_a or not ev_b: return html.Div()
    def row(label,va,vb,highlight=False):
        same=str(va)==str(vb)
        col="secondary" if same else "warning"
        return html.Tr([html.Th(label,className="small text-muted",style={"width":"20%"}),html.Td(str(va)[:35],className="small",style={"color":"#c9d1d9"}),html.Td(str(vb)[:35],className="small",style={"color":"#c9d1d9"}),html.Td(ic("fas fa-equals text-success") if same else ic("fas fa-not-equal text-warning"))])
    rows=[row("Filename",ev_a.get("original_filename","?"),ev_b.get("original_filename","?")),row("File Type",ev_a.get("file_type","?"),ev_b.get("file_type","?")),row("Risk",ev_a.get("risk_level","?"),ev_b.get("risk_level","?")),row("SHA-256",ev_a.get("sha256_hash","?")[:20]+"...",ev_b.get("sha256_hash","?")[:20]+"..."),row("MD5",ev_a.get("md5_hash","?"),ev_b.get("md5_hash","?")),row("Size",f"{ev_a.get('file_size',0):,}B",f"{ev_b.get('file_size',0):,}B"),row("Entropy",f"{ev_a.get('entropy',0):.4f}",f"{ev_b.get('entropy',0):.4f}"),row("Signatures",ev_a.get("signatures_found",0),ev_b.get("signatures_found",0)),row("Confidence",f"{ev_a.get('confidence',0):.0%}",f"{ev_b.get('confidence',0):.0%}"),row("Blockchain",f"#{ev_a.get('blockchain_block','—')}",f"#{ev_b.get('blockchain_block','—')}")]
    same_hash=ev_a.get("sha256_hash")==ev_b.get("sha256_hash")
    return html.Div([
        dbc.Alert([ic("fas fa-exclamation-triangle me-2"),"IDENTICAL FILES — same SHA-256 hash in two cases. Possible duplicate evidence or cross-case link."],color="warning",className="small") if same_hash else html.Span(),
        dbc.Row([dbc.Col([html.H6(ev_a.get("original_filename","?")[:35],className="small text-primary")]),html.Td(""),dbc.Col([html.H6(ev_b.get("original_filename","?")[:35],className="small text-primary text-end")])],className="mb-1"),
        dbc.Table([html.Thead(html.Tr([html.Th("Field",style={"width":"20%"}),html.Th("Evidence A"),html.Th("Evidence B"),html.Th("Match",style={"width":"10%"})])),html.Tbody(rows)],color="dark",size="sm"),
    ])

# ─────────────────────────────────────────────────────────────────────────────
# UPLOAD
# ─────────────────────────────────────────────────────────────────────────────
def tab_upload(user):
    cases=db_cases(user["clearance_level"])
    copts=[{"label":f"{c['case_number']} — {c['title'][:32]}","value":c["id"]} for c in cases]
    return html.Div([
        html.H5([ic("fas fa-upload me-2 text-primary"),"Upload Evidence"],className="mb-3"),
        dbc.Row([
            dbc.Col([dbc.Card([dbc.CardBody([
                dcc.Upload(id="eu",children=html.Div([ic("fas fa-cloud-upload-alt fa-2x text-primary mb-2 d-block"),html.Strong("Drop files or click"),html.Br(),html.Small("Any type · Max 500MB · Batch Merkle anchor · Groq AI analysis",className="text-muted")],className="uz"),multiple=True),
                html.Hr(style={"borderColor":"#1a2d45"}),
                dbc.Row([dbc.Col([dbc.Label("Case *",className="small fw-bold"),dcc.Dropdown(id="uc",options=copts,placeholder="Select case...",style={"fontSize":".8rem"})],md=6),dbc.Col([dbc.Label("Priority",className="small fw-bold"),dbc.Select(id="up2",options=[{"label":"🔴 CRITICAL","value":"CRITICAL"},{"label":"🟠 HIGH","value":"HIGH"},{"label":"🟡 MEDIUM","value":"MEDIUM"},{"label":"🟢 LOW","value":"LOW"}],value="MEDIUM",size="sm")],md=6)],className="mb-2"),
                dbc.Row([dbc.Col([dbc.Label("Classification",className="small fw-bold"),dbc.Select(id="ucl",options=[{"label":"TOP SECRET","value":"TOP_SECRET"},{"label":"SECRET","value":"SECRET"},{"label":"CONFIDENTIAL","value":"CONFIDENTIAL"},{"label":"RESTRICTED","value":"RESTRICTED"}],value="CONFIDENTIAL",size="sm")],md=6),dbc.Col([dbc.Label("Location",className="small fw-bold"),dbc.Input(id="ul",placeholder="Seizure location",size="sm")],md=6)],className="mb-2"),
                dbc.Row([dbc.Col([dbc.Label("Tags",className="small fw-bold"),dbc.Input(id="utags",placeholder="malware, usb, suspect-a",size="sm")]),dbc.Col([dbc.Label("Description",className="small fw-bold"),dbc.Textarea(id="ud",rows=2,placeholder="Context, how obtained...")])]),
            ])],className="bg-dark border-secondary")],md=7),
            dbc.Col([dbc.Card([dbc.CardBody([sh("Analysis Pipeline","fas fa-cogs"),html.Div(id="us",children=[html.Div([ic("fas fa-check text-success me-1 small"),html.Small(t)],className="mb-1") for t in ["SHA-256 + MD5 + SHA-1 hashing","Magic byte + extension detection","Shannon entropy calculation","27-pattern signature scan","String extraction (top 30)","URL/IP/email extraction","Hex dump (first 256 bytes)","STRIDE threat model (6 categories)","Groq AI analysis (LRU cached)","Batch Merkle blockchain anchor","Cross-case dedup detection","IOC extraction + DB storage","Persistent alert if HIGH/CRITICAL","Section 65B compliance","Audit log entry"]])])],className="bg-dark border-secondary mb-3"),
            dbc.Card([dbc.CardBody([sh("Batch Info","fas fa-layer-group"),html.Small("Multiple files uploaded together are anchored in ONE Merkle block. The block hash covers ALL file hashes simultaneously — O(log n) verification.",className="text-muted small")])],className="bg-dark border-secondary"),
            ],md=5),
        ],className="mb-3"),
        html.Div(id="ur"),
    ])

# ─────────────────────────────────────────────────────────────────────────────
# CASES — with health score + timeline
# ─────────────────────────────────────────────────────────────────────────────
def tab_cases(user):
    cases=db_cases(user["clearance_level"]); can=has_perm(user["role"],"cases")
    cards=[]
    for c in cases:
        pc=PCOL.get(c.get("priority","LOW"),"#6c757d")
        ev_list=db_ev(c["id"]); ev_n=len(ev_list); ioc_n=len(db_iocs(c["id"],50))
        hs,_=case_health(c["id"])
        cards.append(dbc.Card([dbc.CardBody([dbc.Row([
            dbc.Col([html.Div([html.Span(c.get("case_number",""),className="small text-primary font-monospace me-2"),dbc.Badge(c.get("status","?"),color="success" if c.get("status")=="Active" else ("warning" if "Invest" in c.get("status","") else "secondary"),pill=True,style={"fontSize":".62rem"})]),html.H6(c.get("title",""),className="mb-1 mt-1 small"),html.Small([ic("fas fa-building me-1 text-muted"),c.get("agency","N/A")," | FIR: ",c.get("fir_number","N/A")],className="text-muted"),html.Br(),html.Small(c.get("description","")[:80]+"..." if len(c.get("description",""))>80 else c.get("description",""),className="text-muted"),html.Div([health_bar(hs)],className="mt-2"),],md=6),
            dbc.Col([html.Strong(c.get("priority","?"),style={"color":pc,"fontSize":".85rem"}),html.Br(),html.Div([bdg(c.get("classification","?"),"dark"),bdg(c.get("case_type","?").replace("_"," ").title(),"secondary")],className="mt-1"),html.Small([ic("fas fa-file me-1 text-muted"),f"{ev_n} evidence · {ioc_n} IOCs"],className="text-muted d-block mt-1"),html.Small(c.get("created_at","")[:10],className="text-muted")],md=3),
            dbc.Col([dbc.Select(id={"type":"cs","index":c["id"]},options=[{"label":x,"value":x} for x in ["Open","Active","Under Investigation","Closed","Archived"]],value=c.get("status","Open"),size="sm",className="mb-1"),dbc.Button(ic("fas fa-file-pdf"),id={"type":"rc","index":c["id"]},color="danger",outline=True,size="sm",className="w-100",title="Generate Report"),],md=3),
        ])])],className="bg-dark border-secondary mb-2"))
    # Timeline section
    all_ev=db_ev(limit=500)
    all_ev.sort(key=lambda e:e.get("uploaded_at",""))
    case_map={c["id"]:c["case_number"] for c in cases}
    timeline=[html.Div([html.Small(e.get("uploaded_at","")[:16],className="text-muted me-2 font-monospace"),rbdg(e.get("risk_level","?")),html.Small(f" {e.get('original_filename','?')[:28]}",className="text-light me-2"),html.Small(f"[{case_map.get(e.get('case_id',''),'?')}]",className="text-primary")],className="timeline-item") for e in all_ev[-20:]]
    modal=dbc.Modal([
        dbc.ModalHeader(dbc.ModalTitle("New Case")),
        dbc.ModalBody([html.Div(id="cca"),
            dbc.Row([dbc.Col([dbc.Label("Title *"),dbc.Input(id="nct")])],className="mb-2"),
            dbc.Row([dbc.Col([dbc.Label("Type"),dbc.Select(id="nctype",options=[{"label":l,"value":v} for l,v in [("Cyber Terrorism","cyber_terrorism"),("Financial Cybercrime","financial_cybercrime"),("Digital Murder","digital_murder"),("General Cybercrime","cybercrime"),("Corporate Espionage","corporate_espionage"),("General","general")]],value="cybercrime")],md=6),dbc.Col([dbc.Label("Priority"),dbc.Select(id="ncp",options=[{"label":x,"value":x} for x in ["CRITICAL","HIGH","MEDIUM","LOW"]],value="HIGH")],md=6)],className="mb-2"),
            dbc.Row([dbc.Col([dbc.Label("Classification"),dbc.Select(id="ncc",options=[{"label":x,"value":x} for x in ["TOP_SECRET","SECRET","CONFIDENTIAL","RESTRICTED"]],value="CONFIDENTIAL")],md=6),dbc.Col([dbc.Label("FIR Number"),dbc.Input(id="ncfir",placeholder="FIR/DL/2024/XXXXX")],md=6)],className="mb-2"),
            dbc.Row([dbc.Col([dbc.Label("Agency"),dbc.Input(id="ncag",placeholder="CBI / Delhi Police / CFSL")])],className="mb-2"),
            dbc.Label("Description"),dbc.Textarea(id="ncd",rows=3),
        ]),
        dbc.ModalFooter([dbc.Button("Cancel",id="ccb",color="secondary",outline=True),dbc.Button([ic("fas fa-plus me-1"),"Create"],id="cfcb",color="primary")]),
    ],id="ccm",is_open=False,size="lg")
    return html.Div([
        dbc.Row([dbc.Col([html.H5([ic("fas fa-folder-open me-2 text-warning"),"Cases"])]),dbc.Col([dbc.Button([ic("fas fa-plus me-1"),"New Case"],id="ocb",color="primary",size="sm",disabled=not can,className="float-end")])],className="mb-3"),
        modal,html.Div(id="car"),html.Div(cards or [dbc.Alert("No cases.",color="info",className="small")]),
        dbc.Card([dbc.CardBody([sh("Evidence Timeline (all cases)","fas fa-stream"),html.Div(timeline or [html.Small("No evidence yet",className="text-muted")],style={"maxHeight":"220px","overflowY":"auto"})])],className="bg-dark border-secondary mt-3"),
    ])

# ─────────────────────────────────────────────────────────────────────────────
# INTELLIGENCE
# ─────────────────────────────────────────────────────────────────────────────
def tab_intel(user):
    if not has_perm(user["role"],"intel"): return dbc.Alert("Access denied.",color="danger")
    iocs=db_iocs(limit=200); corrs=db_correlations(); transfers=db_transfers(limit=30)
    cases=db_cases(user["clearance_level"]); cmap={c["id"]:c["case_number"] for c in cases}
    ev_opts=[{"label":f"{e['evidence_number']} — {e['original_filename'][:22]}","value":e["id"]} for e in db_ev(limit=100)]
    user_opts=[{"label":f"{u['username']} ({u['full_name'][:18]})","value":u["username"]} for u in db_users() if u.get("active")]
    itc=defaultdict(int)
    for i in iocs: itc[i.get("ioc_type","?")]+=1
    ibar=go.Figure(data=[go.Bar(x=list(itc.keys()),y=list(itc.values()),marker_color=["#dc3545","#fd7e14","#4facfe","#198754","#6f42c1"],opacity=.85)])
    ibar.update_layout(paper_bgcolor="rgba(0,0,0,0)",plot_bgcolor="rgba(0,0,0,0)",font_color="#8b949e",xaxis=dict(gridcolor="#1a2d45"),yaxis=dict(gridcolor="#1a2d45"),margin=dict(l=10,r=10,t=5,b=10),height=130)
    ioc_rows=[html.Tr([html.Td(bdg(i.get("ioc_type","?"),"info")),html.Td(html.Code(i.get("ioc_value","")[:42],style={"fontSize":".67rem"})),html.Td(rbdg(i.get("severity","UNKNOWN")) if i.get("severity") in RICON else bdg(i.get("severity","?"),"secondary")),html.Td(html.Small(cmap.get(i.get("case_id",""),"N/A"),className="text-muted")),html.Td(dbc.Button(ic("fas fa-external-link-alt"),href=f"https://www.virustotal.com/gui/search/{i.get('ioc_value','')}",target="_blank",color="primary",outline=True,size="sm") if i.get("ioc_type") in ("URL","IP","HASH","EMAIL","DOMAIN") else html.Span())]) for i in iocs[:40]]
    corr_rows=[html.Tr([html.Td(html.Small(cmap.get(c.get("case_id_a",""),"?"),className="text-primary")),html.Td("↔",className="text-center text-muted small"),html.Td(html.Small(cmap.get(c.get("case_id_b",""),"?"),className="text-primary")),html.Td(bdg(c.get("correlation_type","?"),"warning")),html.Td(dbc.Progress(value=int(c.get("confidence",0)*100),color="success" if c.get("confidence",0)>0.7 else "warning",style={"height":"8px"})),html.Td(html.Small(c.get("notes","")[:30],className="text-muted"))]) for c in corrs[:10]]
    tf_rows=[html.Tr([html.Td(html.Code(t.get("evidence_id","")[:10],style={"fontSize":".65rem","color":"#8b949e"})),html.Td(html.Small(t.get("from_user",""),className="text-warning")),html.Td("→",className="text-center small text-muted"),html.Td(html.Small(t.get("to_user",""),className="text-success")),html.Td(html.Small(t.get("purpose","")[:28],className="text-muted")),html.Td(html.Small(t.get("timestamp","")[:16],className="text-muted"))]) for t in transfers]
    return html.Div([
        html.H5([ic("fas fa-bug me-2 text-warning"),"Threat Intelligence"],className="mb-3"),
        dbc.Row([sc(len(iocs),"IOCs","fas fa-bug","#fd7e14"),sc(len([i for i in iocs if i.get("severity")=="CRITICAL"]),"Critical IOCs","fas fa-skull","#dc3545"),sc(len(corrs),"Correlations","fas fa-project-diagram","#6f42c1"),sc(len(transfers),"Transfers","fas fa-exchange-alt","#0dcaf0")],className="mb-3"),
        dbc.Row([
            dbc.Col([dbc.Card([dbc.CardBody([sh("IOC Types","fas fa-chart-bar"),dcc.Graph(figure=ibar,config={"displayModeBar":False})])],className="bg-dark border-secondary")],md=3),
            dbc.Col([dbc.Card([dbc.CardBody([sh("Record Transfer","fas fa-exchange-alt"),dbc.Row([dbc.Col([dbc.Label("Evidence",className="small"),dcc.Dropdown(id="tf-ev",options=ev_opts,placeholder="Select...",style={"fontSize":".8rem"})]),],className="mb-2"),dbc.Row([dbc.Col([dbc.Label("To",className="small"),dcc.Dropdown(id="tf-to",options=user_opts,placeholder="Recipient...",style={"fontSize":".8rem"})],md=6),dbc.Col([dbc.Label("Purpose",className="small"),dbc.Input(id="tf-purpose",placeholder="Court order / reason",size="sm")],md=6)],className="mb-2"),dbc.Button([ic("fas fa-exchange-alt me-1"),"Record"],id="tf-btn",color="warning",outline=True,size="sm",className="w-100"),html.Div(id="tf-status",className="mt-2")])],className="bg-dark border-secondary")],md=3),
            dbc.Col([dbc.Card([dbc.CardBody([sh("Case Correlations","fas fa-project-diagram"),tbl(["Case A","","Case B","Type","Confidence","Notes"],corr_rows)])],className="bg-dark border-secondary")],md=6),
        ],className="mb-3"),
        dbc.Row([
            dbc.Col([dbc.Card([dbc.CardBody([sh("IOC Indicators (VT links live)","fas fa-crosshairs"),tbl(["Type","Value","Severity","Case","VT"],ioc_rows,responsive=True)])],className="bg-dark border-secondary")],md=8),
            dbc.Col([dbc.Card([dbc.CardBody([sh("CoC Transfer Log","fas fa-link"),tbl(["Evidence","From","","To","Purpose","Time"],tf_rows,responsive=True)])],className="bg-dark border-secondary")],md=4),
        ]),
    ])

# ─────────────────────────────────────────────────────────────────────────────
# CHAIN
# ─────────────────────────────────────────────────────────────────────────────
def tab_chain(user):
    cv=bc_verify(); blocks=db_blockchain(25)
    block_items=[html.Div([html.Div([html.Span(f"#{b['block_index']}",className="text-warning fw-bold small me-2"),html.Span("GENESIS" if b["block_index"]==0 else "",className="text-success small"),html.Span(f"  {len(json.loads(b.get('evidence_ids','[]') or '[]'))} files",className="text-muted small")]),html.Div([html.Small("H: ",className="text-muted"),html.Code(b["block_hash"][:30]+"...",style={"fontSize":".63rem","color":"#4facfe"})]),html.Div([html.Small("P: ",className="text-muted"),html.Code(b["previous_hash"][:30]+"...",style={"fontSize":".63rem","color":"#8b949e"})]),html.Div([html.Small("M: ",className="text-muted"),html.Code((b.get("merkle_root","")[:22]+"..." if b.get("merkle_root") else "N/A"),style={"fontSize":".63rem","color":"#c8a217"})]),html.Small(f"{b['timestamp'][:16]} | {b.get('uploader','?')}",className="text-muted")],className="cb") for b in blocks]
    return html.Div([
        html.H5([ic("fas fa-cubes me-2"),"Batch Merkle Blockchain"],className="mb-3",style={"color":"#6f42c1"}),
        dbc.Alert([ic("fas fa-check-circle me-2" if cv["valid"] else "fas fa-times-circle me-2"),html.Strong("Chain Intact ✓" if cv["valid"] else "Chain Error!"),f" | {cv.get('blocks',0)} blocks | {cv.get('message','')}"],color="success" if cv["valid"] else "danger",className="mb-3"),
        dbc.Row([
            dbc.Col([dbc.Card([dbc.CardBody([sh("Batch Merkle — What Makes v4 Different","fas fa-info-circle"),html.P("v4 anchors ALL files in a single upload as ONE block. Merkle tree is computed over all N file SHA-256 hashes simultaneously.",className="small text-muted mb-2"),html.P("This is O(log n) batch verification — a IEEE-publishable novel contribution over naive per-file chaining (O(n)).",className="small text-muted mb-2"),html.Code("Block hash = SHA256(index‖prev‖sorted(evidence_ids)‖timestamp‖uploader‖MerkleRoot)",style={"fontSize":".65rem","color":"#4facfe","display":"block"}),html.Br(),html.Code("MerkleRoot = reduce(SHA256(left‖right), all_SHA256_hashes)",style={"fontSize":".65rem","color":"#c8a217","display":"block"})])],className="bg-dark border-secondary")],md=5),
            dbc.Col([dbc.Card([dbc.CardBody([sh("Block Explorer","fas fa-search"),html.Div(block_items or [html.P("No blocks. Upload evidence.",className="text-muted small")],style={"maxHeight":"58vh","overflowY":"auto"})])],className="bg-dark border-secondary")],md=7),
        ]),
    ])

# ─────────────────────────────────────────────────────────────────────────────
# REPORTS
# ─────────────────────────────────────────────────────────────────────────────
def tab_reports(user):
    cases=db_cases(user["clearance_level"])
    copts=[{"label":f"{c['case_number']} — {c['title'][:32]}","value":c["id"]} for c in cases]
    prev=[html.Div([ic("fas fa-file-pdf text-danger me-2"),html.Small(p.name,className="text-muted"),html.Span(f" {int(p.stat().st_size/1024)}KB",className="text-muted small ms-2")],className="mb-1") for p in sorted(Path("reports").glob("*.pdf"),key=lambda x:x.stat().st_mtime,reverse=True)[:8]]
    return html.Div([
        html.H5([ic("fas fa-file-pdf me-2 text-danger"),"Report Generation"],className="mb-3"),
        dbc.Row([
            dbc.Col([dbc.Card([dbc.CardBody([sh("Generate Report","fas fa-file-contract"),dbc.Label("Case *",className="small fw-bold"),dcc.Dropdown(id="rcs",options=copts,placeholder="Select case...",className="mb-2",style={"fontSize":".8rem"}),dbc.Checklist(id="roi",options=[{"label":" Groq AI narrative","value":"ai"},{"label":" Section 65B + DPDP 2023 cert","value":"cert"},{"label":" Case health score","value":"health"}],value=["ai","cert","health"],className="mb-3 small"),dbc.Button([ic("fas fa-file-pdf me-2"),"Generate PDF"],id="grb",color="danger",size="lg",className="w-100"),html.Div(id="rs",className="mt-2")])],className="bg-dark border-secondary")],md=4),
            dbc.Col([dbc.Card([dbc.CardBody([sh("What's Included","fas fa-list-check"),*[html.Div([ic("fas fa-check text-success me-2 small"),html.Small(t)],className="mb-1") for t in ["Evidence inventory with SHA-256+MD5+SHA-1","Batch Merkle blockchain proof per file","Per-file AI forensic assessment","STRIDE threat model summary","Section 65B compliance certificate","DPDP Act 2023 compliance statement","Case health score (0-100)","ISO/IEC 27037:2012 methodology note","MITRE ATT&CK TTPs referenced","Government letterhead + classification banner"]]])],className="bg-dark border-secondary")],md=4),
            dbc.Col([dbc.Card([dbc.CardBody([sh("Recent Reports","fas fa-history"),html.Div(prev or [html.Small("No reports yet",className="text-muted")])])],className="bg-dark border-secondary")],md=4),
        ]),
    ])

# ─────────────────────────────────────────────────────────────────────────────
# BENCHMARKS
# ─────────────────────────────────────────────────────────────────────────────
def tab_benchmarks(user):
    bm=get_benchmarks(); all_m=db_metrics(limit=400)
    def bm_tbl(op):
        d=bm.get(op,{})
        if not d.get("count"): return dbc.Alert("No data yet",color="dark",className="small py-1")
        return dbc.Table([html.Thead(html.Tr([html.Th("Metric"),html.Th("Value")])),html.Tbody([html.Tr([html.Td(m,className="small text-muted"),html.Td(html.Strong(f"{v} ms",style={"color":"#4facfe"}))]) for m,v in [("N",d["count"]),("P50",d["p50"]),("P95",d["p95"]),("P99",d["p99"]),("Mean",d["mean"]),("Min",d["min"]),("Max",d["max"])]])],color="dark",size="sm")
    if all_m:
        ops=[m["operation"] for m in all_m]; ts=[m["duration_ms"] for m in all_m]
        fig=go.Figure(data=[go.Scatter(x=list(range(len(ts))),y=ts,mode="markers",marker=dict(color=["#4facfe" if "analysis" in o else "#c8a217" if "blockchain" in o else "#198754" for o in ops],size=4,opacity=0.7))])
        fig.update_layout(paper_bgcolor="rgba(0,0,0,0)",plot_bgcolor="rgba(0,0,0,0)",font_color="#8b949e",xaxis=dict(gridcolor="#1a2d45",title="Op #"),yaxis=dict(gridcolor="#1a2d45",title="ms"),margin=dict(l=30,r=10,t=5,b=30),height=190)
    else: fig=go.Figure()
    n=bm.get("total_ops",0)
    return html.Div([
        html.H5([ic("fas fa-tachometer-alt me-2 text-success"),"Performance Benchmarks (IEEE Methodology)"],className="mb-3"),
        dbc.Alert([ic("fas fa-info-circle me-2 small"),html.Strong("IEEE Table I: "),"P50/P95/P99 latency. N=",html.Strong(str(n))," ops measured. Cache hits excluded from Groq timing."],color="info",className="mb-3 small"),
        dbc.Row([dbc.Col([dbc.Card([dbc.CardBody([sh("Evidence Analysis","fas fa-microscope"),bm_tbl("evidence_analysis")])],className="bg-dark border-secondary h-100")],md=4),dbc.Col([dbc.Card([dbc.CardBody([sh("Batch Blockchain Anchor","fas fa-cubes"),bm_tbl("blockchain_anchor")])],className="bg-dark border-secondary h-100")],md=4),dbc.Col([dbc.Card([dbc.CardBody([sh("Groq AI Analysis","fas fa-robot"),bm_tbl("groq_analysis"),html.Hr(style={"borderColor":"#1a2d45"}),html.Small(f"Tokens total: {bm.get('groq_tokens',0):,}",className="text-muted")])],className="bg-dark border-secondary h-100")],md=4)],className="mb-3"),
        dbc.Card([dbc.CardBody([sh("Latency Scatter","fas fa-chart-scatter"),dcc.Graph(figure=fig,config={"displayModeBar":False}) if all_m else html.P("Upload evidence to generate data.",className="text-muted small")])],className="bg-dark border-secondary mb-3"),
        dbc.Card([dbc.CardBody([sh("IEEE Paper Table I (copy-paste ready)","fas fa-copy"),html.Pre(f"""TABLE I. COC v4.0 SYSTEM PERFORMANCE BENCHMARKS (N={n} operations)
+----------------------------------+----------+----------+----------+----------+
| Operation                        | P50 (ms) | P95 (ms) | P99 (ms) | Mean(ms) |
+----------------------------------+----------+----------+----------+----------+
| Evidence Analysis Pipeline       |{bm.get('evidence_analysis',{}).get('p50',0):10.1f}|{bm.get('evidence_analysis',{}).get('p95',0):10.1f}|{bm.get('evidence_analysis',{}).get('p99',0):10.1f}|{bm.get('evidence_analysis',{}).get('mean',0):10.1f}|
| Batch Merkle Blockchain Anchor   |{bm.get('blockchain_anchor',{}).get('p50',0):10.1f}|{bm.get('blockchain_anchor',{}).get('p95',0):10.1f}|{bm.get('blockchain_anchor',{}).get('p99',0):10.1f}|{bm.get('blockchain_anchor',{}).get('mean',0):10.1f}|
| Groq AI Analysis (API only)      |{bm.get('groq_analysis',{}).get('p50',0):10.1f}|{bm.get('groq_analysis',{}).get('p95',0):10.1f}|{bm.get('groq_analysis',{}).get('p99',0):10.1f}|{bm.get('groq_analysis',{}).get('mean',0):10.1f}|
+----------------------------------+----------+----------+----------+----------+
Platform: COC v4.0 | DB: SQLite WAL (indexed) | AI: {GROQ_MODEL}
Groq LRU Cache Tokens Used: {bm.get('groq_tokens',0):,}""",style={"fontSize":".68rem","color":"#4facfe","background":"#020509","padding":".8rem","borderRadius":"6px"})])],className="bg-dark border-secondary"),
    ])

# ─────────────────────────────────────────────────────────────────────────────
# ADMIN
# ─────────────────────────────────────────────────────────────────────────────
def tab_admin(user):
    if user["role"]!="admin": return dbc.Alert("Admin only.",color="danger")
    users=db_users(); logs=db_logs(40); cv=bc_verify(); bm=get_benchmarks(); stats=db_stats()
    urows=[html.Tr([html.Td(u["username"],className="small font-monospace"),html.Td(u["full_name"][:22],className="small"),html.Td(dbc.Badge(u["role"],color=ROLE_COL.get(u["role"],"secondary"),pill=True,style={"fontSize":".62rem"})),html.Td(u["department"][:20],className="small text-muted"),html.Td(dbc.Badge("MFA" if u.get("mfa_enabled") else "—",color="success" if u.get("mfa_enabled") else "secondary",pill=True,style={"fontSize":".6rem"})),html.Td(html.Small(str(u.get("last_login",""))[:16] or "Never",className="text-muted")),html.Td(html.Small(str(u.get("failed_attempts",0)),className="text-warning")),html.Td(dbc.Button("Disable" if u.get("active") else "Enable",id={"type":"tu","index":u["id"]},color="danger" if u.get("active") else "success",outline=True,size="sm",style={"fontSize":".62rem","padding":"1px 6px"}))]) for u in users]
    lrows=[html.Tr([html.Td(l.get("timestamp","")[:16],className="small text-muted"),html.Td(l.get("username","?"),className="small font-monospace text-primary"),html.Td(l.get("action","?"),className="small"),html.Td(l.get("details","")[:52],className="small text-muted")]) for l in logs]
    return html.Div([
        html.H5([ic("fas fa-cog me-2 text-danger"),"Administration"],className="mb-3"),
        dbc.Row([
            dbc.Col([dbc.Card([dbc.CardBody([html.Small("Blockchain",className="text-muted small d-block"),dbc.Alert([ic("fas fa-check-circle me-1" if cv["valid"] else "fas fa-times-circle me-1"),f"{'Valid' if cv['valid'] else 'ERROR'} | {cv.get('blocks',0)} blocks"],color="success" if cv["valid"] else "danger",className="mb-0 py-1 small")])],className="bg-dark border-secondary")],md=3),
            dbc.Col([dbc.Card([dbc.CardBody([html.Small("Groq AI",className="text-muted small d-block"),dbc.Alert([ic("fas fa-robot me-1"),f"{'Active ✓' if GROQ_KEY else 'Local mode'} | {bm.get('groq_tokens',0):,} tokens | {sum(1 for m in db_metrics(limit=10000) if m.get('groq_tokens',0)>0)} cached"],color="success" if GROQ_KEY else "warning",className="mb-0 py-1 small")])],className="bg-dark border-secondary")],md=4),
            dbc.Col([dbc.Card([dbc.CardBody([html.Small("Database",className="text-muted small d-block"),dbc.Alert([ic("fas fa-database me-1"),f"SQLite WAL+Indexed | {stats['total_evidence']}ev | {stats['total_cases']} cases | {stats['total_iocs']} IOCs | {stats['unread_alerts']} alerts"],color="info",className="mb-0 py-1 small")])],className="bg-dark border-secondary")],md=5),
        ],className="mb-3"),
        html.Div(id="user-msg"),
        dbc.Card([dbc.CardBody([sh("Users","fas fa-users"),tbl(["Username","Name","Role","Dept","MFA","Last Login","Fails","Action"],urows,responsive=True)])],className="bg-dark border-secondary mb-3"),
        dbc.Card([dbc.CardBody([sh("Audit Log","fas fa-history"),tbl(["Time","User","Action","Details"],lrows,responsive=True)])],className="bg-dark border-secondary"),
    ])

# ═══════════════════════════════════════════════════════════════════════════════
# APP LAYOUT + CALLBACKS
# ═══════════════════════════════════════════════════════════════════════════════
app.layout=html.Div([dcc.Store(id="ss",storage_type="session"),dcc.Location(id="url"),html.Div(id="pc"),dcc.Download(id="rd"),dcc.Download(id="ev-csv")])
app.index_string=app.index_string.replace("{%css%}","{%css%}\n<style>"+CSS+"</style>")

@app.callback(Output("pc","children"),Input("ss","data"))
def route(s):
    if s and s.get("tok") and chk_token(s["tok"]): return main_shell()
    return login_page()

@app.callback(Output("ni","children"),Input("ss","data"))
def navbar(s):
    if not s or not s.get("tok"): raise PreventUpdate
    u=chk_token(s["tok"])
    if not u: raise PreventUpdate
    alerts=db_alerts(50,unread_only=True); ac=len(alerts)
    return [html.Span(u["full_name"],className="small text-light"),dbc.Badge(u["role"],color=ROLE_COL.get(u["role"],"secondary"),pill=True),dbc.Badge(CLEARANCE.get(u["clearance_level"],"?"),color="dark",pill=True),dbc.Badge([ic("fas fa-bell me-1"),str(ac)],color="danger" if ac>0 else "dark",pill=True),dbc.Button(ic("fas fa-sign-out-alt"),id="lob",color="danger",outline=True,size="sm")]

@app.callback(Output("statsbar","children"),Input("ss","data"),Input("ri","n_intervals"))
def statsbar(s,_):
    if not s or not s.get("tok"): return html.Span()
    st=db_stats(); cv=bc_verify(); groq_status="✓ Groq Active" if GROQ_KEY else "Local AI"
    return html.Div([html.Small([ic("fas fa-database me-1 text-primary"),f"{st['total_evidence']} evidence"],className="me-3"),html.Small([ic("fas fa-folder me-1 text-warning"),f"{st['total_cases']} cases ({st['active_cases']} active)"],className="me-3"),html.Small([ic("fas fa-exclamation-triangle me-1 text-danger"),f"{st['high_risk']} high risk"],className="me-3"),html.Small([ic("fas fa-link me-1 text-purple"),f"{st['anchored']} anchored"],className="me-3",style={"color":"#6f42c1"}),html.Small([ic("fas fa-cubes me-1"),f"Chain: {'✓' if cv['valid'] else '⚠'}"],className="me-3",style={"color":"#198754" if cv["valid"] else "#dc3545"}),html.Small([ic("fas fa-robot me-1"),groq_status],className="me-3",style={"color":"#198754" if GROQ_KEY else "#ffc107"}),html.Small([ic("fas fa-bell me-1"),f"{st['unread_alerts']} alerts"],style={"color":"#dc3545" if st['unread_alerts']>0 else "#8b949e"})],className="d-flex flex-wrap align-items-center",style={"fontSize":".75rem","color":"#8b949e"})

@app.callback(Output("ss","data"),Output("la","children"),Input("lb","n_clicks"),Input({"type":"pb","index":ALL},"n_clicks"),State("lu","value"),State("lp","value"),prevent_initial_call=True)
def do_login(mc,pc,uname,pwd):
    tid=ctx.triggered_id
    if isinstance(tid,dict) and tid.get("type")=="pb":
        uname=tid["index"]; pwd={"admin":"admin123","analyst":"analyst123","investigator":"invest123","officer":"officer123","legal":"legal123","forensic":"forensic123"}.get(uname,"")
    user,err=auth_login(uname or "",pwd or "")
    if not user: return {},dbc.Alert([ic("fas fa-times-circle me-2"),err],color="danger",dismissable=True)
    return {"tok":make_token(user)},dbc.Alert(f"Welcome, {user['full_name']}!",color="success",duration=2000)

@app.callback(Output("ss","data",allow_duplicate=True),Input("lob","n_clicks"),prevent_initial_call=True)
def logout(n):
    if n: return {}
    raise PreventUpdate

@app.callback(Output("tc","children"),Input("tabs","active_tab"),Input("ri","n_intervals"),State("ss","data"))
def render_tab(tab,_,s):
    if not s or not s.get("tok"): raise PreventUpdate
    u=chk_token(s["tok"])
    if not u: return dbc.Alert("Session expired.",color="warning")
    return {"home":tab_home,"ev":tab_evidence,"up":tab_upload,"cases":tab_cases,"intel":tab_intel,"chain":tab_chain,"rpt":tab_reports,"bench":tab_benchmarks,"adm":tab_admin}.get(tab,lambda u:html.Div())(u)

# Global search
@app.callback(Output("gs-results","children"),Input("gs-input","value"),State("ss","data"))
def global_search(query,s):
    if not query or len(query)<2: return html.Span()
    u=chk_token((s or {}).get("tok",""))
    if not u: return html.Span()
    results=db_global_search(query,u["clearance_level"])
    ev=results["evidence"]; cases=results["cases"]; iocs=results["iocs"]
    if not ev and not cases and not iocs: return dbc.Alert(f"No results for '{query}'",color="dark",className="small mx-3 mt-1 py-1",dismissable=True)
    return dbc.Card([dbc.CardBody([dbc.Row([
        dbc.Col([html.Strong(f"Evidence ({len(ev)})",className="small text-primary"),html.Div([html.Div([rbdg(e.get("risk_level","?")),html.Small(e.get("original_filename","?")[:30],className="ms-1")],className="small") for e in ev[:5]])]),
        dbc.Col([html.Strong(f"Cases ({len(cases)})",className="small text-warning"),html.Div([html.Div([html.Code(c.get("case_number",""),style={"fontSize":".7rem","color":"#4facfe"}),html.Small(f" {c.get('title','')[:30]}",className="ms-1")],className="small") for c in cases[:5]])]),
        dbc.Col([html.Strong(f"IOCs ({len(iocs)})",className="small text-danger"),html.Div([html.Div([bdg(i.get("ioc_type","?"),"info"),html.Code(i.get("ioc_value","")[:30],style={"fontSize":".7rem"})],className="small") for i in iocs[:5]])]),
    ])])],className="bg-dark border-secondary mx-3 mt-1",style={"maxWidth":"700px"})

# Alerts
@app.callback(Output("alert-ack","children"),Input("mark-all-read","n_clicks"),State("ss","data"),prevent_initial_call=True)
def mark_read(n,s):
    if not n: raise PreventUpdate
    u=chk_token((s or {}).get("tok",""))
    if not u: raise PreventUpdate
    db_mark_all_read(u["username"])
    return dbc.Alert("All alerts marked read.",color="success",dismissable=True,className="small mt-1")

@app.callback(Output("home-chain","children"),Input("ri","n_intervals"),Input("ss","data"))
def home_chain(_,s):
    if not s or not s.get("tok"): raise PreventUpdate
    cv=bc_verify(); blocks=db_blockchain(3)
    return html.Div([dbc.Alert([ic("fas fa-check-circle me-1"),f"Valid ✓ | {cv.get('blocks',0)} blocks"],color="success",className="py-1 small mb-2") if cv["valid"] else dbc.Alert("Chain Error",color="danger",className="py-1 small mb-2"),html.Div([html.Div([html.Small(f"#{b['block_index']}",className="text-warning fw-bold me-2"),html.Code(b["block_hash"][:18]+"...",style={"fontSize":".62rem","color":"#4facfe"})]) for b in blocks])])

# Evidence browser
@app.callback(Output("ev-list","children"),Output("ev-pager","children"),Input("ev-q","value"),Input("ev-cf","value"),Input("ev-rf","value"),Input("ev-tf","value"),Input("ev-page","data"),State("ss","data"))
def ev_list(query,case_id,risk,ftype,page,s):
    if not s or not s.get("tok"): raise PreventUpdate
    rows,total=db_ev_search(query or "",case_id or None,risk or None,ftype or None,page or 0)
    items,pager=render_ev_list(rows,total,page or 0)
    return items,pager

@app.callback(Output("ev-page","data",allow_duplicate=True),Input("ev-prev","n_clicks"),State("ev-page","data"),prevent_initial_call=True)
def ev_prev(n,p): return max(0,(p or 0)-1) if n else (p or 0)

@app.callback(Output("ev-page","data",allow_duplicate=True),Input("ev-next","n_clicks"),State("ev-page","data"),prevent_initial_call=True)
def ev_next(n,p): return (p or 0)+1 if n else (p or 0)

@app.callback(Output("ev-detail","children"),Output("ev-sel","data"),Input({"type":"ev-row","index":ALL},"n_clicks"),State("ss","data"),prevent_initial_call=True)
def ev_detail(clicks,s):
    if not any(clicks): raise PreventUpdate
    eid=ctx.triggered_id["index"]; ev=db_ev_by_id(eid)
    return render_ev_detail(ev),eid

# Evidence comparison
@app.callback(Output("cmp-bar","children"),Output("cmp-a","data"),Output("cmp-b","data"),Input({"type":"ev-chk","index":ALL},"value"),State("cmp-a","data"),State("cmp-b","data"),prevent_initial_call=True)
def ev_compare(vals,cmp_a,cmp_b):
    if not any(vals): return dbc.Alert([ic("fas fa-info-circle me-2 small"),"Select two items to compare."],color="dark",className="py-1 small border-secondary mb-2"),None,None
    checked=[ctx.inputs_list[0][i]["id"]["index"] for i,v in enumerate(vals) if v]
    if len(checked)==0: return dbc.Alert([ic("fas fa-info-circle me-2 small"),"Select two items to compare."],color="dark",className="py-1 small border-secondary mb-2"),None,None
    if len(checked)==1: return dbc.Alert([ic("fas fa-hand-pointer me-2 small"),f"1 selected. Select one more to compare."],color="info",className="py-1 small mb-2"),checked[0],None
    a,b=db_ev_by_id(checked[0]),db_ev_by_id(checked[1])
    cmp_view=render_comparison(a,b)
    return html.Div([dbc.Alert([ic("fas fa-equals me-2"),html.Strong("Comparing 2 items"),dbc.Button(ic("fas fa-times"),id="cmp-clear",color="link",size="sm",className="float-end p-0")],color="warning",className="py-1 small mb-2"),cmp_view]),checked[0],checked[1]

@app.callback(Output("ev-csv","data"),Input("ev-exp","n_clicks"),State("ev-q","value"),State("ev-cf","value"),State("ev-rf","value"),State("ev-tf","value"),State("ss","data"),prevent_initial_call=True)
def export_csv(n,q,cf,rf,tf,s):
    if not n: raise PreventUpdate
    u=chk_token((s or {}).get("tok",""))
    if not u: raise PreventUpdate
    rows,_=db_ev_search(q or "",cf or None,rf or None,tf or None,0,10000)
    buf=io.StringIO(); w=csv.writer(buf)
    w.writerow(["Evidence Number","Filename","SHA-256","MD5","SHA-1","File Type","Risk Level","Confidence","Entropy","Size","Case ID","Uploaded By","Date","Block","Merkle Root","Location"])
    for e in rows: w.writerow([e.get("evidence_number",""),e.get("original_filename",""),e.get("sha256_hash",""),e.get("md5_hash",""),e.get("sha1_hash",""),e.get("file_type",""),e.get("risk_level",""),e.get("confidence",""),e.get("entropy",""),e.get("file_size",""),e.get("case_id",""),e.get("uploaded_by",""),e.get("uploaded_at","")[:16],e.get("blockchain_block",""),e.get("merkle_root",""),e.get("location","")])
    db_log(u["username"],"EXPORT_CSV","evidence","",f"{len(rows)} items")
    return dict(content=buf.getvalue(),filename=f"evidence_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",type="text/csv")

# Upload — batch Merkle anchor
@app.callback(Output("us","children"),Output("ur","children"),Input("eu","contents"),State("eu","filename"),State("uc","value"),State("up2","value"),State("ucl","value"),State("ul","value"),State("ud","value"),State("utags","value"),State("ss","data"),prevent_initial_call=True)
def handle_upload(contents,filenames,case_id,priority,classification,location,description,tags_str,s):
    if not contents: raise PreventUpdate
    u=chk_token((s or {}).get("tok",""))
    if not u: return dbc.Alert("Unauthorized",color="danger"),html.Div()
    if not case_id: return dbc.Alert([ic("fas fa-exclamation me-2"),"Select a case first."],color="warning"),html.Div()
    if isinstance(contents,str): contents,filenames=[contents],[filenames]
    # Analyze all files first
    analyses=[]; ev_ids=[]; cards=[]
    tags=json.dumps([t.strip() for t in (tags_str or "").split(",") if t.strip()])
    for content,filename in zip(contents,filenames):
        try: fd=base64.b64decode(content.split(",",1)[1])
        except Exception as e: cards.append(dbc.Alert(f"Read error {filename}: {e}",color="danger")); continue
        an=analyze(fd,filename)
        eid=f"EV-{datetime.now().strftime('%Y%m%d%H%M%S')}-{secrets.token_hex(3).upper()}"
        analyses.append((fd,filename,an,eid))
        ev_ids.append({"ev_id":eid,"sha256":an["hashes"]["sha256"]})

    # Batch Merkle anchor ALL files in one block
    bc_result=None
    if ev_ids:
        bc_result=bc_batch_anchor(ev_ids,u["username"],case_id)

    for fd,filename,an,eid in analyses:
        evn=f"EV-{datetime.now().strftime('%Y%m')}-{secrets.token_hex(3).upper()}"
        saved=db_save_ev({"id":eid,"ev_num":evn,"filename":secure_filename(filename),"original_filename":filename,"file_size":len(fd),"file_type":an["file_type"],"sha256":an["hashes"]["sha256"],"md5":an["hashes"]["md5"],"sha1":an["hashes"].get("sha1",""),"hex_preview":an["hex_preview"],"strings_preview":an["strings_preview"],"case_id":case_id,"uploaded_by":u["username"],"priority":priority or "MEDIUM","classification":classification or "CONFIDENTIAL","location":location or "","description":description or "","tags":tags,"risk_level":an["risk_level"],"risk_score":an["local_risk"],"confidence":an["confidence"],"entropy":an["entropy"],"sigs_found":an["sigs_found"],"s_spoof":an["stride"].get("spoofing",""),"s_tamp":an["stride"].get("tampering",""),"s_rep":an["stride"].get("repudiation",""),"s_info":an["stride"].get("info_disclosure",""),"s_dos":an["stride"].get("dos",""),"s_elev":an["stride"].get("elevation",""),"ai_summary":an["ai_summary"],"threats":an["threats"],"recs":an["recs"],"iocs":an["iocs"],"ttps":an["ttps"],"court_admit":an["court_admit"],"proc_ms":an["proc_ms"],"bc_hash":bc_result.get("hash","") if bc_result else "","bc_block":bc_result.get("idx",0) if bc_result else 0,"merkle":bc_result.get("merkle","") if bc_result else "","tx":bc_result.get("tx","") if bc_result else ""})
        if an.get("iocs"): db_save_iocs(eid,case_id,an["iocs"])
        db_log(u["username"],"UPLOAD","evidence",eid,f"{filename}|{an['risk_level']}|Block#{bc_result.get('idx','?') if bc_result else '?'}")

        # AUTO DEDUP — check if same hash exists in any other case
        existing=db_ev_by_hash(an["hashes"]["sha256"])
        other_cases=[e for e in existing if e["case_id"]!=case_id]
        if other_cases:
            oc=other_cases[0]; other_case=db_case(oc["case_id"])
            db_save_alert("DUPLICATE_FILE",f"Duplicate File Detected: {filename}",f"File '{filename}' (SHA-256: {an['hashes']['sha256'][:20]}...) already exists in case {other_case.get('case_number','?') if other_case else 'UNKNOWN'}. Possible cross-case link.",severity="HIGH",case_id=case_id,evidence_id=eid)
            db_save_corr(case_id,oc["case_id"],"DUPLICATE_FILE",0.95,[{"type":"HASH","value":an["hashes"]["sha256"]}],f"Same file in both cases: {filename}")

        # Alert for high/critical
        if an["risk_level"] in ("CRITICAL","HIGH"):
            db_save_alert("HIGH_RISK",f"{an['risk_level']} Risk Evidence: {filename}",f"Evidence '{filename}' analyzed with {an['risk_level']} risk (score {an['local_risk']:.2f}). {an['sigs_found']} signatures. Immediate review recommended.",severity=an["risk_level"],case_id=case_id,evidence_id=eid)

        f=an.get("findings",[]); t=an.get("threats",[]); r=an.get("recs",[]); iocs=an.get("iocs",[])
        cards.append(dbc.Card([dbc.CardBody([
            dbc.Row([dbc.Col([html.Div([rbdg(an["risk_level"]),bdg(an["file_type"],"info"),bdg("Groq ✓","success") if an["groq_ok"] else bdg("Local","warning"),bdg("⚡ Cache","info") if an["cached"] else html.Span()]),html.Strong(filename,className="d-block small mt-1"),html.Small(html.Code(an["hashes"]["sha256"][:42]+"...",style={"fontSize":".62rem","color":"#8b949e"}))],md=8),dbc.Col([html.Small(f"Size: {len(fd):,}B",className="text-muted d-block"),html.Small(f"Entropy: {an['entropy']:.3f}/8",className="text-muted d-block"),html.Small(f"Risk: {an['local_risk']:.3f}",className="text-muted d-block"),html.Small(f"Conf: {an['confidence']:.0%}",className="text-muted d-block"),html.Small(f"Sigs: {an['sigs_found']}",className="text-muted d-block"),html.Small(f"Batch Block #{bc_result.get('idx','—') if bc_result else '—'}",className="text-muted d-block"),html.Small(f"IOCs: {len(iocs)}",className="text-muted d-block"),html.Small(f"{an['proc_ms']}ms",className="text-muted d-block")],md=4)]),
            html.Hr(style={"borderColor":"#1a2d45","margin":".35rem 0"}),
            html.P(an["ai_summary"],className="small mb-1") if an["ai_summary"] else html.Span(),
            dbc.Row([dbc.Col([html.Strong("Findings:",className="small"),html.Ul([html.Li(x,className="small text-muted") for x in f[:3]],className="mb-0 ps-3")],md=4) if f else html.Span(),dbc.Col([html.Strong("Threats:",className="small text-danger"),html.Ul([html.Li(x,className="small text-muted") for x in t[:3]],className="mb-0 ps-3")],md=4) if t else html.Span(),dbc.Col([html.Strong("Actions:",className="small text-success"),html.Ul([html.Li(x,className="small text-muted") for x in r[:3]],className="mb-0 ps-3")],md=4) if r else html.Span()]) if (f or t or r) else html.Span(),
            html.Hr(style={"borderColor":"#1a2d45","margin":".3rem 0"}),
            html.Small([bdg("✓ Batch Merkle","primary"),bdg(f"#{bc_result.get('idx','?') if bc_result else '?'}","dark"),bdg("✓ STRIDE","warning"),bdg(f"{len(iocs)} IOCs","info"),bdg("✓ Saved" if saved else "✗ Failed","success" if saved else "danger")]),
            dbc.Alert([ic("fas fa-copy me-1 text-warning"),"DUPLICATE FILE DETECTED — same hash exists in another case. Cross-case correlation recorded."],color="warning",className="mt-1 py-1 small") if other_cases else html.Span(),
        ])],color=RCOL.get(an["risk_level"],"secondary"),outline=True,className="mb-2"))

    btext=f"Batch block #{bc_result.get('idx','?') if bc_result else '?'} — {len(analyses)} files in one Merkle block" if bc_result else "Upload complete"
    status=[ic("fas fa-check-circle text-success me-2"),html.Strong(f"{len(analyses)} file(s) analyzed"),html.Small(f" · {btext}",className="text-muted")]
    return status,html.Div([html.H6("Results",className="mb-2"),html.Div(cards)])

# Cases
@app.callback(Output("ccm","is_open"),Input("ocb","n_clicks"),Input("ccb","n_clicks"),Input("cfcb","n_clicks"),State("ccm","is_open"),prevent_initial_call=True)
def toggle_modal(o,ca,co,io): t=ctx.triggered_id; return True if t=="ocb" else False if t in ("ccb","cfcb") else io

@app.callback(Output("car","children"),Input("cfcb","n_clicks"),State("nct","value"),State("nctype","value"),State("ncp","value"),State("ncc","value"),State("ncd","value"),State("ncfir","value"),State("ncag","value"),State("ss","data"),prevent_initial_call=True)
def create_case_cb(n,title,ctype,prio,cls,desc,fir,agency,s):
    if not n: raise PreventUpdate
    if not title: return dbc.Alert("Title required",color="warning",className="small")
    u=chk_token((s or {}).get("tok",""))
    if not u: return dbc.Alert("Unauthorized",color="danger")
    cid,cn=db_create_case(title,desc or "",ctype or "cybercrime",prio or "HIGH",cls or "CONFIDENTIAL",u["sub"],fir or "",agency or "")
    db_log(u["username"],"CREATE_CASE","case",cid,f"{cn}: {title}")
    return dbc.Alert(f"Case {cn} created.",color="success",dismissable=True,className="small")

@app.callback(Output({"type":"cs","index":MATCH},"value",allow_duplicate=True),Input({"type":"cs","index":MATCH},"value"),State("ss","data"),prevent_initial_call=True)
def update_status(status,s):
    u=chk_token((s or {}).get("tok",""))
    if not u: raise PreventUpdate
    cid=ctx.triggered_id["index"]; db_update_case(cid,status); db_log(u["username"],"UPDATE_CASE","case",cid,f"→{status}")
    return status

# Reports
@app.callback(Output("rs","children"),Output("rd","data"),Input("grb","n_clicks"),State("rcs","value"),State("roi","value"),State("ss","data"),prevent_initial_call=True)
def gen_report_cb(n,cid,options,s):
    if not n or not cid: return dbc.Alert("Select a case.",color="warning",className="small"),dash.no_update
    u=chk_token((s or {}).get("tok",""))
    if not u: return dbc.Alert("Unauthorized",color="danger"),dash.no_update
    if not HAS_PDF: return dbc.Alert("pip install reportlab",color="danger"),dash.no_update
    case=db_case(cid); ev=db_ev(cid)
    if not case: return dbc.Alert("Case not found",color="danger"),dash.no_update
    narrative=groq_narrative(case,ev) if options and "ai" in options else ""
    fpath,err=gen_report(case,ev,narrative,u["full_name"])
    if err: return dbc.Alert(f"Error: {err}",color="danger"),dash.no_update
    db_log(u["username"],"REPORT","case",cid,f"{case['case_number']}")
    return dbc.Alert(f"Generated: {Path(fpath).name}",color="success",className="small"),dcc.send_file(fpath)

# Intel — transfer
@app.callback(Output("tf-status","children"),Input("tf-btn","n_clicks"),State("tf-ev","value"),State("tf-to","value"),State("tf-purpose","value"),State("ss","data"),prevent_initial_call=True)
def record_transfer(n,ev_id,to_user,purpose,s):
    if not n: raise PreventUpdate
    u=chk_token((s or {}).get("tok",""))
    if not u: return dbc.Alert("Unauthorized",color="danger")
    if not ev_id or not to_user: return dbc.Alert("Select evidence and recipient.",color="warning",className="small")
    to_u=db_user(to_user); thash=db_save_transfer(ev_id,u["username"],to_user,u.get("department",""),to_u.get("department","") if to_u else "",purpose or "")
    db_log(u["username"],"TRANSFER","evidence",ev_id,f"→{to_user}|{thash[:14]}...")
    return dbc.Alert(f"Transfer recorded. Hash: {thash[:18]}...",color="success",dismissable=True,className="small")

# Admin — toggle user
@app.callback(Output("user-msg","children"),Input({"type":"tu","index":ALL},"n_clicks"),State("ss","data"),prevent_initial_call=True)
def toggle_user_cb(clicks,s):
    if not any(clicks): raise PreventUpdate
    u=chk_token((s or {}).get("tok",""))
    if not u or u["role"]!="admin": raise PreventUpdate
    uid=ctx.triggered_id["index"]; all_u=db_users()
    target=next((x for x in all_u if x["id"]==uid),None)
    if not target: raise PreventUpdate
    new=0 if target.get("active") else 1; db_toggle_user(uid,new)
    db_log(u["username"],"TOGGLE_USER","user",uid,f"{'Enabled' if new else 'Disabled'} {target['username']}")
    return dbc.Alert(f"{'Enabled' if new else 'Disabled'} {target['username']}.",color="success" if new else "warning",dismissable=True,className="small")

# REST API
@server.route("/api/health")
def api_health(): return jsonify({"status":"operational","version":"4.0.0","groq":bool(GROQ_KEY),"db_indexed":True,"blocks":len(db_blockchain()),"timestamp":datetime.utcnow().isoformat()})
@server.route("/api/stats")
def api_stats(): return jsonify(db_stats())
@server.route("/api/benchmarks")
def api_bench(): return jsonify(get_benchmarks())
@server.route("/api/chain/verify")
def api_chain(): return jsonify(bc_verify())
@server.route("/api/search/<query>")
def api_search(query): return jsonify(db_global_search(query,5))
@server.route("/api/evidence/export")
def api_export():
    ev=db_ev(); buf=io.StringIO(); w=csv.writer(buf)
    w.writerow(["Evidence Number","Filename","SHA256","MD5","File Type","Risk Level","Entropy","Case ID","Uploaded By","Date","Block"])
    for e in ev: w.writerow([e.get("evidence_number",""),e.get("original_filename",""),e.get("sha256_hash",""),e.get("md5_hash",""),e.get("file_type",""),e.get("risk_level",""),e.get("entropy",""),e.get("case_id",""),e.get("uploaded_by",""),e.get("uploaded_at","")[:16],e.get("blockchain_block","")])
    r=make_response(buf.getvalue()); r.headers["Content-Type"]="text/csv"; r.headers["Content-Disposition"]="attachment; filename=evidence.csv"
    return r
@server.route("/download/<path:fn>")
def dl(fn):
    try: return send_file(f"reports/{fn}",as_attachment=True)
    except: return "Not found",404

# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════
if __name__=="__main__":
    init_db()
    HOST=os.getenv("HOST","127.0.0.1"); PORT=int(os.getenv("PORT",8080)); DEBUG=os.getenv("DEBUG","true").lower()=="true"
    print(f"""
╔══════════════════════════════════════════════════════════════════╗
║  COC v4.0 — Chain of Custody Evidence Management System         ║
╠══════════════════════════════════════════════════════════════════╣
║  DB     : SQLite WAL + 18 indexes | 12 tables | Thread pool     ║
║  AI     : {'Groq llama-3.3-70b-versatile ✅' if GROQ_KEY else 'Local forensic analysis (set GROQ_API_KEY)'}
║  Chain  : Batch Merkle SHA-256 — N files → 1 block             ║
║  NEW v4 : Stats cache·Alerts·Dedup·Health score·Pagination·Cmp  ║
║  API    : /api/health /api/stats /api/benchmarks /api/chain     ║
║           /api/search/<q> /api/evidence/export                  ║
╠══════════════════════════════════════════════════════════════════╣
║  URL    : http://{HOST}:{PORT}                                   ║
╚══════════════════════════════════════════════════════════════════╝
""")
    app.run(debug=DEBUG,host=HOST,port=PORT,use_reloader=False)