"""
Scan service: glue between the Flask app and the scanner package.

It contains NO scanning logic. Target validation, scope, authorization, crawling and detection all stay in
`scanner/`; this module only (1) stores scan records and findings in SQLite, (2) runs one scan at a time in a
background thread so a request never blocks for the length of a crawl, and (3) turns scanner outcomes and errors
into safe, user-displayable data.

Security notes
- Findings are stored via Finding.to_dict(), the scanner's output guard (sanitized URLs, redacted evidence).
  The raw Finding / affected_urls are never written to the database or returned.
- Scope errors are mapped to fixed messages: a resolved IP address (possibly internal) is never echoed.
- Unexpected exceptions are reported by class name only.
- Only ONE scan may run at a time, which also prevents duplicate submissions from starting duplicate scans.
"""
import json
import threading
from datetime import datetime, timedelta

from scanner.detectors import CATEGORIES, get_detectors
from scanner.models import SEVERITIES
from scanner.sanitize import sanitize_url, scrub_text
from scanner.scope_validator import ScopeError

NOW_FMT = '%Y-%m-%d %H:%M:%S'
MAX_TARGET_CHARS = 2048
HISTORY_LIMIT = 20
STALE_AFTER = timedelta(hours=1)      # a 'running' scan older than this belongs to a process that died

# Fixed, user-safe wording per ScopeError code. ScopeError messages can contain resolved IPs, so they are not used.
SCOPE_MESSAGES = {
    'authorization_required': 'You must confirm that you are authorized to test this target.',
    'invalid_url': 'Enter a valid http:// or https:// URL.',
    'scheme_not_allowed': 'Only http:// and https:// targets are allowed.',
    'credentials_in_url': 'URLs containing credentials are not allowed.',
    'invalid_host': 'The target host name is not valid.',
    'host_not_allowlisted': 'This target is not on the approved scan allowlist (VULNGUARD_SCAN_ALLOWLIST).',
    'dns_failure': 'The target host name could not be resolved.',
    'blocked_address': 'The target resolves to a non-public or reserved address, which is not allowed.',
    'out_of_scope': 'The target is outside the approved scan scope.',
}
GENERIC_SCOPE_MESSAGE = 'The target was rejected by the scan scope checks.'


def scope_message(exc):
    return SCOPE_MESSAGES.get(getattr(exc, 'code', ''), GENERIC_SCOPE_MESSAGE)


def now_str():
    return datetime.now().strftime(NOW_FMT)


def available_categories():
    """Categories that have at least one registered detector, as [{'id', 'label'}] (the catalog may define more)."""
    present = {d.category for d in get_detectors()}
    return [{'id': key, 'label': label} for key, label in CATEGORIES.items() if key in present]


# ---------------------------------------------------------------------------
# Schema (additive only: new tables, nothing existing is altered)
# ---------------------------------------------------------------------------
def init_tables(conn):
    conn.execute('''CREATE TABLE IF NOT EXISTS scans
                    (id INTEGER PRIMARY KEY AUTOINCREMENT,
                     target TEXT NOT NULL,
                     asset_id INTEGER REFERENCES assets(id) ON DELETE SET NULL,
                     status TEXT NOT NULL,
                     stage TEXT,
                     categories TEXT,
                     started_at TEXT,
                     completed_at TEXT,
                     pages_crawled INTEGER NOT NULL DEFAULT 0,
                     requests_used INTEGER NOT NULL DEFAULT 0,
                     checks_done INTEGER NOT NULL DEFAULT 0,
                     checks_total INTEGER NOT NULL DEFAULT 0,
                     findings_total INTEGER NOT NULL DEFAULT 0,
                     errors TEXT,
                     notes TEXT,
                     created_date TEXT NOT NULL)''')
    conn.execute('''CREATE TABLE IF NOT EXISTS scan_findings
                    (id INTEGER PRIMARY KEY AUTOINCREMENT,
                     scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                     rule_id TEXT NOT NULL,
                     title TEXT NOT NULL,
                     category TEXT,
                     severity TEXT NOT NULL,
                     confidence TEXT,
                     description TEXT,
                     affected_url TEXT,
                     affected_urls TEXT,
                     evidence TEXT,
                     impact TEXT,
                     remediation TEXT,
                     reference TEXT,
                     detection_method TEXT,
                     fingerprint TEXT)''')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_scan_findings_scan ON scan_findings(scan_id)')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_scans_asset ON scans(asset_id)')
    # A scan left 'running' by a process that died can never finish: close it out instead of showing it forever.
    # Only scans older than STALE_AFTER are touched, so a second process importing the app cannot kill a live scan.
    cutoff = (datetime.now() - STALE_AFTER).strftime(NOW_FMT)
    conn.execute("UPDATE scans SET status = 'failed', stage = 'done', completed_at = ?, errors = ? "
                 "WHERE status = 'running' AND started_at < ?",
                 (now_str(), json.dumps(['The scan was interrupted because the application stopped.']), cutoff))


# ---------------------------------------------------------------------------
# Persistence helpers (parameterized SQL only)
# ---------------------------------------------------------------------------
def create_scan(conn, target_display, asset_id, categories):
    cur = conn.execute(
        'INSERT INTO scans (target, asset_id, status, stage, categories, started_at, created_date) '
        "VALUES (?, ?, 'running', 'validating', ?, ?, ?)",
        (target_display, asset_id, json.dumps(categories), now_str(), now_str()))
    return cur.lastrowid


def update_progress(conn, scan_id, stage, checks_done, checks_total, findings_total):
    conn.execute('UPDATE scans SET stage = ?, checks_done = ?, checks_total = ?, findings_total = ? WHERE id = ?',
                 (stage, checks_done, checks_total, findings_total, scan_id))


def fail_scan(conn, scan_id, message):
    conn.execute("UPDATE scans SET status = 'failed', stage = 'done', completed_at = ?, errors = ? WHERE id = ?",
                 (now_str(), json.dumps([message]), scan_id))


def save_outcome(conn, scan_id, outcome):
    """Store a ScanOutcome. Findings go through Finding.to_dict() (the output guard), never the raw objects."""
    rows = []
    for f in outcome.findings:
        d = f.to_dict()
        rows.append((scan_id, d['rule_id'], d['title'], d['category'], d['severity'], d['confidence'],
                     d['description'], d['affected_url'], json.dumps(d['affected_urls']), d['evidence'],
                     d['impact'], d['remediation'], d['reference'], d['detection_method'], d['fingerprint']))
    conn.executemany(
        'INSERT INTO scan_findings (scan_id, rule_id, title, category, severity, confidence, description, '
        'affected_url, affected_urls, evidence, impact, remediation, reference, detection_method, fingerprint) '
        'VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)', rows)
    conn.execute(
        'UPDATE scans SET status = ?, stage = ?, completed_at = ?, pages_crawled = ?, requests_used = ?, '
        'checks_done = ?, checks_total = ?, findings_total = ?, errors = ?, notes = ? WHERE id = ?',
        (outcome.status, 'done', outcome.completed_at or now_str(), outcome.pages_crawled, outcome.requests_used,
         outcome.checks_done, outcome.checks_total, len(rows),
         json.dumps([scrub_text(e) for e in outcome.errors]),
         json.dumps([scrub_text(n) for n in outcome.notes]), scan_id))


def _scan_to_dict(row):
    d = dict(row)
    for key in ('errors', 'notes', 'categories'):
        try:
            d[key] = json.loads(d.get(key) or '[]')
        except ValueError:
            d[key] = []
    d['target'] = sanitize_url(d['target'])
    return d


def get_scan(conn, scan_id, with_findings=True):
    row = conn.execute('SELECT s.*, a.name AS asset_name FROM scans s LEFT JOIN assets a ON a.id = s.asset_id '
                       'WHERE s.id = ?', (scan_id,)).fetchone()
    if row is None:
        return None
    scan = _scan_to_dict(row)
    counts = {s: 0 for s in SEVERITIES}
    for r in conn.execute('SELECT severity, COUNT(*) AS n FROM scan_findings WHERE scan_id = ? GROUP BY severity',
                          (scan_id,)):
        counts[r['severity']] = r['n']
    scan['severity_counts'] = counts
    if with_findings:
        order = 'CASE severity ' + ' '.join(f"WHEN '{s}' THEN {i}" for i, s in enumerate(SEVERITIES)) + ' ELSE 99 END'
        findings = []
        for r in conn.execute(f'SELECT * FROM scan_findings WHERE scan_id = ? ORDER BY {order}, id', (scan_id,)):
            f = dict(r)
            try:
                urls = json.loads(f.pop('affected_urls', None) or '[]')
            except ValueError:
                urls = []
            f.pop('affected_url', None)
            f['urls'] = urls or ['-']            # sanitized URLs only (stored from Finding.to_dict())
            f['category_label'] = CATEGORIES.get(f['category'], f['category'])
            findings.append(f)
        scan['findings'] = findings
    return scan


def list_scans(conn, limit=HISTORY_LIMIT):
    rows = conn.execute('SELECT s.*, a.name AS asset_name FROM scans s LEFT JOIN assets a ON a.id = s.asset_id '
                        'ORDER BY s.id DESC LIMIT ?', (limit,)).fetchall()
    return [_scan_to_dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------
class ScanManager:
    """Runs at most one scan at a time in a background thread."""

    def __init__(self):
        self._lock = threading.Lock()
        self._thread = None
        self.active_scan_id = None

    def is_busy(self):
        return self._lock.locked()

    def start(self, connect, engine, url, categories, asset_id):
        """
        Create the scan record and start it. Returns the scan id, or None if a scan is already running.
        `connect` returns a new sqlite connection (one per thread); `engine` is a scanner.engine.ScanEngine.
        """
        if not self._lock.acquire(blocking=False):
            return None
        try:
            conn = connect()
            try:
                scan_id = create_scan(conn, sanitize_url(url), asset_id, categories)
                conn.commit()
            finally:
                conn.close()
            self.active_scan_id = scan_id
            self._thread = threading.Thread(target=self._run, args=(connect, engine, scan_id, url, categories),
                                            name=f'scan-{scan_id}', daemon=True)
            self._thread.start()
            return scan_id
        except BaseException:
            self.active_scan_id = None
            self._lock.release()
            raise

    def _run(self, connect, engine, scan_id, url, categories):
        def with_conn(fn, *args):
            conn = connect()
            try:
                fn(conn, *args)
                conn.commit()
            finally:
                conn.close()

        def progress(stage, done, total, findings):
            try:
                with_conn(update_progress, scan_id, stage, done, total, findings)
            except Exception:       # progress is best effort; it must never abort a scan
                pass

        try:
            outcome = engine.run(url, True, categories=categories, progress=progress)
            with_conn(save_outcome, scan_id, outcome)
        except ScopeError as exc:
            with_conn(fail_scan, scan_id, scope_message(exc))
        except Exception as exc:    # one broken scan must not take the app down; expose the class name only
            try:
                with_conn(fail_scan, scan_id, f'The scan failed unexpectedly ({type(exc).__name__}).')
            except Exception:
                pass
        finally:
            self.active_scan_id = None
            self._lock.release()

    def join(self, timeout=None):
        """Wait for the running scan (used by tests)."""
        thread = self._thread
        if thread is not None:
            thread.join(timeout)
