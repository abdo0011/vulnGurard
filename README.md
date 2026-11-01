# Vulnerability Management Dashboard

A professional web-based vulnerability tracking and management system built with Flask, designed for security teams to track, prioritize, and remediate security findings.

![Python](https://img.shields.io/badge/python-3.7+-blue.svg)
![Flask](https://img.shields.io/badge/flask-3.0.0-green.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Status](https://img.shields.io/badge/status-active-success.svg)

## Purpose

Security teams need a centralized way to track vulnerabilities discovered through penetration testing, security scans, and bug bounty programs. This dashboard provides a clean, intuitive interface to manage the entire vulnerability lifecycle from discovery to remediation.

## Features

**Vulnerability management**
- Full CRUD for vulnerabilities, with severity (Critical/High/Medium/Low), status (Open/In Progress/Fixed) and CVSS (0-10)
- Filter by severity, status and **asset**; live search across title, description, asset name and IP
- Each vulnerability is linked to an **asset**; the table shows the asset name and IP
- CSV import with per-row validation and error reporting

**Asset management** (new, `#assets` page)
- Add, edit, delete and view assets: auto-generated ID (AST-0001), name, IP address, type (Server, Website, Workstation, Network Device, Database, Other), operating system, owner, description, created date
- Search by name or IP, filter by type, per-asset vulnerability counts, detail view listing all linked vulnerabilities
- Safe deletion: an asset with vulnerabilities cannot be deleted until they are reassigned to another asset (or explicitly left unassigned)
- Asset CSV import with validation, duplicate detection (name or IP) and row-level error messages

**Dashboard**
- Total assets, total/critical/high/medium/low/open/fixed vulnerability cards
- Charts: by severity, by status, per asset, asset distribution by type, plus a "most vulnerable assets" list
- Everything refreshes automatically after any change

## Installation

**Requirements:**
- Python 3.8+
- Flask (see `requirements.txt`)

**Setup:**
```bash
git clone https://github.com/Smriti-ss/vulnerability_dashboard.git
cd vulnerability_dashboard
pip install -r requirements.txt
```

## Usage

**Start the application:**
```bash
python app.py            # add FLASK_DEBUG=1 for auto-reload during development
```
The server binds to `127.0.0.1:5000` only. Set `VULNGUARD_DB=/path/to/file.db` to use a different database file.

**Open your browser:**
```
http://localhost:5000
```

**Add your first asset, then a vulnerability:**
1. Open the **Assets** tab and click "New asset" (or import `sample_assets.csv`)
2. Click "New vulnerability", fill in the details and choose the asset
3. Click Save
4. Watch the dashboard statistics update in real-time!

## Screenshots
<img width="1889" height="929" alt="Screenshot 2026-01-17 182948" src="https://github.com/user-attachments/assets/6044f894-3806-4273-b720-b8f67f9febe3" />

## Tech Stack

**Backend:**
- Python 3.11
- Flask 3.0.0
- SQLite3

**Frontend:**
- HTML5
- CSS3 (Custom + Bootstrap 5.3)
- Vanilla JavaScript
- Font Awesome Icons

**Architecture:**
- RESTful API design
- AJAX for asynchronous operations
- Responsive design (mobile-friendly)

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/vulnerabilities` | List vulnerabilities (`severity`, `status`, `asset_id` filters; `asset_id=none` = unassigned) |
| POST | `/api/vulnerabilities` | Create (`asset_id` preferred; legacy `asset` name still accepted) |
| PUT | `/api/vulnerabilities/<id>` | Update |
| DELETE | `/api/vulnerabilities/<id>` | Delete |
| POST | `/api/import-csv` | Import vulnerabilities (`title,severity,status` required; `description,asset,cvss_score,discovered_date` optional) |
| GET | `/api/assets` | List assets with vulnerability counts (`search` by name/IP, `type`) |
| GET | `/api/assets/<id>` | Asset detail with linked vulnerabilities |
| POST | `/api/assets` | Create asset |
| PUT | `/api/assets/<id>` | Update asset |
| DELETE | `/api/assets/<id>` | Delete; returns 409 if vulnerabilities are linked unless `?reassign_to=<asset id>` or `?reassign_to=none` |
| POST | `/api/assets/import-csv` | Import assets (`name` required; `ip_address,asset_type,operating_system,owner,description` optional) |
| GET | `/api/stats` | Dashboard statistics (original keys kept, asset stats added) |

**Example:**
```bash
curl "http://localhost:5000/api/vulnerabilities?severity=Critical&asset_id=2"
```

## Database

SQLite (`vulnerabilities.db`). New `assets` table; `vulnerabilities.asset_id` is a foreign key (`ON DELETE RESTRICT`, foreign keys enforced). On first start with an older database, VulnGuard automatically backs it up to `vulnerabilities.db.pre-assets.bak`, adds the column, and converts each distinct legacy `asset` text value into an asset and links it. The legacy `asset` text column is kept (synced with the asset name) for compatibility. All queries are parameterized.

## Severity Levels

| Level | CVSS Range | Color | Priority |
|-------|------------|-------|----------|
| **Critical** | 9.0 - 10.0 | Red | Immediate |
| **High** | 7.0 - 8.9 | Orange | Urgent |
| **Medium** | 4.0 - 6.9 | Blue | Moderate |
| **Low** | 0.1 - 3.9 | Gray | Low |

## Use Cases

**Security Teams:**
- Track findings from penetration tests
- Manage bug bounty submissions
- Prioritize remediation efforts based on CVSS scores
- Report on security posture to management

**Integration Examples:**
- Feed data from automated scanners (like SQLi scanners, Nessus, Burp Suite)
- Export vulnerability reports for compliance
- Integrate with ticketing systems (Jira, ServiceNow)

## What I Learned

- **Full-stack development** - Building a complete web application from scratch
- **RESTful API design** - Creating clean, intuitive API endpoints
- **Database design** - Schema design for vulnerability tracking
- **Frontend development** - Building responsive, interactive UIs with vanilla JavaScript
- **Security workflows** - Understanding vulnerability management lifecycle
- **CVSS scoring** - Industry-standard risk assessment methodology

## Future Enhancements

- [ ] User authentication and role-based access control
- [ ] Export reports to PDF/CSV
- [ ] Email notifications for critical vulnerabilities
- [ ] Integration with Slack/Teams for alerts
- [ ] Vulnerability timeline and history tracking
- [ ] Attachment support for proof-of-concept files
- [ ] Multi-tenant support for multiple projects

## License


