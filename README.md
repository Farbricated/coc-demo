# 🇮🇳 COC v4.0 — Chain of Custody Evidence Management System

> **IEEE-Grade Digital Forensics Platform** for Indian Law Enforcement  
> Single-file · SQLite · Groq AI · Batch Merkle Blockchain · Section 65B · DPDP Act 2023

---

## Quick Start

```bash
# 1. Install dependencies
pip install dash dash-bootstrap-components plotly flask flask-cors \
    PyJWT pyotp qrcode werkzeug requests reportlab Pillow python-dotenv

# 2. Create .env file
echo "GROQ_API_KEY=your_key_here" > .env
echo "SECRET_KEY=your_secret_here" >> .env

# 3. Run
python app.py

# 4. Open browser
http://127.0.0.1:8080
```

---

## Login Credentials

| Username | Password | Role | Clearance |
|---|---|---|---|
| `admin` | `admin123` | National Coordinator | TOP SECRET · L5 |
| `analyst` | `analyst123` | Forensic Scientist | SECRET · L4 |
| `forensic` | `forensic123` | Digital Forensics Director | SECRET · L4 |
| `investigator` | `invest123` | CBI Investigator | SECRET · L3 |
| `legal` | `legal123` | Legal Advisor | SECRET · L3 |
| `officer` | `officer123` | Field Officer | CONFIDENTIAL · L2 |

---

## Architecture

**Single file** (`app.py`) — 1,412 lines, zero microservices, zero Docker required.

```
app.py
├── DATABASE        SQLite WAL · 12 tables · 17 indexes · thread-local pool
├── AUTH            JWT tokens · TOTP MFA · role-based permissions · account lockout
├── BLOCKCHAIN      Batch Merkle SHA-256 hash chain · O(log n) verification
├── FORENSIC ENGINE Local analysis + Groq AI · LRU cache · STRIDE model
├── PDF REPORTS     Section 65B + DPDP Act 2023 · court-admissible
└── DASH UI         9 tabs · role-specific dashboards · live stats bar
```

### Database Tables (12)

| Table | Purpose |
|---|---|
| `users` | Officers, roles, clearance levels, MFA secrets |
| `cases` | Investigation cases with FIR numbers and agency |
| `evidence` | All uploaded files with full forensic metadata |
| `coc_transfers` | Chain of custody handover log with SHA-256 proof |
| `ioc_indicators` | Extracted IOCs — URLs, IPs, emails, signatures |
| `case_correlations` | Auto-detected cross-case links and duplicates |
| `alerts` | Persistent system alerts — HIGH risk, duplicates |
| `perf_metrics` | P50/P95/P99 benchmark data for IEEE paper |
| `audit_logs` | Every user action, timestamped |
| `blockchain_records` | Merkle hash chain blocks |
| `groq_cache` | LRU cache for Groq API responses by file hash |
| `ev_comparisons` | Evidence comparison session history |

### Database Indexes (17)

All foreign keys and common query columns are indexed:
`evidence(case_id, sha256_hash, risk_level, file_type, uploaded_at)` · `ioc_indicators(case_id, ioc_type, ioc_value)` · `alerts(read_by)` · `audit_logs(username, timestamp)` · `blockchain_records(block_index)` · `coc_transfers(evidence_id)` · `perf_metrics(operation)`

---

## User Interface — 9 Tabs

### Home
Role-specific landing page. Admin sees system health. Analyst sees forensic queue (HIGH/CRITICAL items needing review). Investigator sees active cases with evidence counts. Officer gets upload shortcut. Always-visible stats bar across top shows live evidence count, case count, chain status, Groq status.

### Evidence
Full evidence browser with search + filter. Left panel: paginated list (25/page) with search by filename/hash/description, filter by case/risk/type, CSV export. Right panel: detail view with 6 sub-tabs — Overview (all hashes + AI summary), Hex Dump (first 256 bytes), Strings (extracted printable strings), STRIDE (6-category threat model), IOCs (extracted indicators with VirusTotal links), Chain (block info + transfer history). Select two items with checkboxes to compare side by side.

### Upload
Drag and drop any file type up to 500MB. Select case, priority, classification, seizure location, tags, description. On upload: SHA-256 + MD5 + SHA-1, magic byte detection, entropy, 27-pattern signature scan, string extraction, URL/IP/email extraction, hex dump, STRIDE assessment, Groq AI analysis, batch Merkle anchor, cross-case dedup check, IOC storage, alert creation if HIGH/CRITICAL. Multiple files anchor in ONE Merkle block.

### Cases
All cases your clearance permits. Each card shows case number, FIR, agency, status, evidence count, IOC count, and a **Health Score (0–100)** progress bar. Status dropdown updates live. Evidence timeline at bottom shows all evidence across all cases in chronological order.

### Intelligence
IOC management table with VirusTotal links on every row. Record evidence transfers between officers — generates SHA-256 proof hash. Case correlation panel shows auto-detected links. IOC type distribution chart.

### Chain
Batch Merkle blockchain explorer. Shows each block with hash, previous hash, Merkle root, files anchored, uploader, timestamp. Chain integrity verification on load. Mathematical formula displayed. Explains O(log n) batch verification for IEEE methodology section.

### Reports
Generate court-ready PDFs. Includes: evidence inventory with all hashes, batch Merkle proof, AI forensic assessments, STRIDE summary, Section 65B certificate, DPDP Act 2023 compliance statement, case health score, ISO/IEC 27037:2012 methodology note. Downloaded immediately.

### Benchmarks
Live P50/P95/P99 latency for evidence analysis, blockchain anchor, Groq AI. Latency scatter plot. Pre-formatted IEEE Table I ready to copy into paper. Groq token count.

### Admin
User management — enable/disable accounts. System health cards. Full audit log. Database stats.

---

## Analysis Pipeline (per file upload)

```
File received
    ↓ SHA-256 + MD5 + SHA-1
    ↓ Magic byte detection (24 types) + extension fallback
    ↓ Shannon entropy (8KB sample)
    ↓ 27-pattern signature scan (CRITICAL/HIGH/MEDIUM/LOW)
    ↓ String extraction (top 30 printable strings ≥6 chars)
    ↓ URL / IP / email extraction (regex)
    ↓ Hex dump (first 256 bytes, formatted)
    ↓ Local risk score (0.0–1.0)
    ↓ STRIDE assessment (6 categories from local signals)
    ↓ IOC extraction (URLs, IPs, emails, high-severity signatures)
    ↓ Groq cache check (by SHA-256 hash)
    ↓   → Cache hit: skip API call entirely
    ↓   → Cache miss: call Groq llama-3.3-70b-versatile
    ↓   → Groq unavailable: local fallback analysis
    ↓ Merge Groq IOCs with local IOCs
    ↓ Batch Merkle anchor (all files in upload → one block)
    ↓ Cross-case dedup check (same SHA-256 in other cases?)
    ↓   → Duplicate found: create alert + case correlation
    ↓ Persistent alert if HIGH or CRITICAL risk
    ↓ Save to evidence table
    ↓ Save IOCs to ioc_indicators table
    ↓ Audit log entry
    ↓ Invalidate stats cache
```

---

## Blockchain — Batch Merkle Design

All files dropped in a single upload are anchored in **one block** using a Merkle tree over all N file hashes.

```
Block Hash = SHA256(index ‖ prev_hash ‖ sorted(evidence_ids) ‖ timestamp ‖ uploader ‖ MerkleRoot)

MerkleRoot = reduce(SHA256(left ‖ right), [sha256(file_1), sha256(file_2), ..., sha256(file_N)])
```

This is **O(log N) batch verification** — a single block proves N files simultaneously. Single-file chaining would require N blocks and O(N) verification.

---

## STRIDE Threat Model

Every evidence item gets a 6-category STRIDE assessment based on local signals:

| Category | Signal Used |
|---|---|
| **Spoofing** | Credential harvesting signatures (mimikatz, keylog, password) |
| **Tampering** | Process injection APIs (WriteProcessMemory, CreateRemoteThread) |
| **Repudiation** | Script execution that may clear audit logs |
| **Info Disclosure** | Network indicators — extracted IPs and URLs |
| **DoS** | Resource-intensive execution patterns |
| **Elevation** | Privilege escalation APIs |

---

## Case Health Score

Every case gets a score 0–100 based on:

| Component | Max Points |
|---|---|
| Evidence quantity (log scale) | 20 |
| % evidence blockchain anchored | 20 |
| % evidence AI analyzed | 20 |
| IOC count extracted | 20 |
| Metadata completeness (FIR, agency, description, status) | 20 |

Shown as a colored progress bar on each case card and included in generated reports.

---

## REST API

| Endpoint | Returns |
|---|---|
| `GET /api/health` | System status, version, block count |
| `GET /api/stats` | Live counts for all tables |
| `GET /api/benchmarks` | P50/P95/P99 per operation |
| `GET /api/chain/verify` | Full chain integrity check |
| `GET /api/search/<query>` | Search evidence + cases + IOCs |
| `GET /api/evidence/export` | CSV of all evidence |
| `GET /download/<filename>` | Download generated PDF report |

---

## Configuration (.env)

```env
GROQ_API_KEY=gsk_your_key_here          # Get free at console.groq.com
SECRET_KEY=your-random-64-char-string   # JWT signing key
HOST=127.0.0.1                          # Server host
PORT=8080                               # Server port
DEBUG=true                              # Set false for production
TOKEN_EXPIRY_HOURS=8                    # JWT expiry
```

Without `GROQ_API_KEY`, all features still work — analysis falls back to local forensic engine (entropy + signatures + STRIDE). Groq responses are cached in SQLite by file hash so the same file never calls the API twice.

---

## IEEE Publication — Novel Contributions

1. **First framework combining blockchain + AI for Indian legal compliance** — Section 65B + DPDP Act 2023 + ISO/IEC 27037:2012 in one system

2. **Batch Merkle blockchain anchoring** — N evidence files anchored in O(log N) vs O(N) for naive per-file chaining. Provably tamper-evident without external PKI

3. **STRIDE integrated into forensic pipeline** — automated per-file threat modelling at upload time, stored in DB, included in court reports

4. **Role hierarchy mapped to Indian government clearance** — MHA/CVC 5-level classification enforced at DB query level (SQL WHERE clause), not just UI

5. **Live P50/P95/P99 benchmarks** — every operation timed and stored, IEEE Table I auto-generated from real measurements

6. **LLM cross-case IOC correlation** — Groq extracts IOCs per file, stored in normalized table, auto-correlates across cases on duplicate hash detection

---

## Legal Compliance

| Standard | Implementation |
|---|---|
| Section 65B, Indian Evidence Act 1872 | Certificate page in every PDF report |
| Information Technology Act 2000 | Referenced in certificate, tampering offence noted |
| DPDP Act 2023 | Data minimisation statement, purpose limitation |
| ISO/IEC 27037:2012 | Methodology reference in reports and certificate |
| BNS 2023 (Bharatiya Nyaya Sanhita) | Section 77 referenced in certificate |
| CERT-In Guidelines | Chain of custody integrity requirements met |

---

## What's Not Yet Built

- Email/SMS notifications on critical evidence upload
- YARA custom rule upload and scanning
- Disk image mounting (.dd / .E01 / .vmdk)
- VirusTotal API hash submission (links open VT in browser; no auto-submission)
- Digital signature on PDF reports (officer certificate)
- Data retention auto-enforcement (DPDP Act schedule)
- CCTNS export format
- User study questionnaire (required for IEEE Transactions)
- Comparative analysis vs Autopsy / FTK / EnCase (required for IEEE)
- Password reset flow
- Mobile-optimized layout

---

## Project Structure

```
coc-demo/
├── app.py              # Entire system — 1,412 lines, single file
├── .env                # Your keys (never commit this)
├── .env.example        # Template
├── requirements.txt    # Dependencies
├── README.md           # This file
├── data/
│   └── coc_v4.db       # SQLite database (auto-created)
├── reports/            # Generated PDF reports
├── logs/
│   └── coc.log         # Application log
└── exports/            # CSV exports
```

---

## Dependencies

```
dash                    Web framework
dash-bootstrap-components  UI components
plotly                  Charts
flask / flask-cors      HTTP server
PyJWT                   JWT authentication
pyotp / qrcode          TOTP MFA
werkzeug                Password hashing, file utils
requests                Groq API calls
reportlab / Pillow      PDF generation
python-dotenv           .env loading
```

---

*COC v4.0 — Built for Indian Law Enforcement · IEEE-Grade · Section 65B Compliant*