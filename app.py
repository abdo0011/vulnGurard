from flask import Flask, render_template, request, jsonify
import sqlite3
from datetime import datetime
from contextlib import contextmanager
import csv
import ipaddress
import os
import re
import shutil
from io import StringIO

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5 MB upload limit

# The database lives next to app.py regardless of the working directory.
# Override with the VULNGUARD_DB environment variable if needed.
DB_PATH = os.environ.get(
    'VULNGUARD_DB',
    os.path.join(os.path.dirname(os.path.abspath(__file__)), 'vulnerabilities.db'))

SEVERITIES = ['Critical', 'High', 'Medium', 'Low']
STATUSES = ['Open', 'In Progress', 'Fixed']
ASSET_TYPES = ['Server', 'Website', 'Workstation', 'Network Device', 'Database', 'Other']

NOW_FMT = '%Y-%m-%d %H:%M:%S'


def now_str():
    return datetime.now().strftime(NOW_FMT)


# ---------------------------------------------------------------------------
# Database setup & migration
# ---------------------------------------------------------------------------
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA foreign_keys = ON')
    return conn


@contextmanager
def db():
    """Connection that commits on success, rolls back on error, always closes."""
    conn = get_db()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    """Create tables and migrate older databases without losing data."""
    first_run = not os.path.exists(DB_PATH)
    conn = get_db()
    try:
        conn.execute('''CREATE TABLE IF NOT EXISTS assets
                        (id INTEGER PRIMARY KEY AUTOINCREMENT,
                         name TEXT NOT NULL,
                         ip_address TEXT,
                         asset_type TEXT NOT NULL DEFAULT 'Other',
                         operating_system TEXT,
                         owner TEXT,
                         description TEXT,
                         created_date TEXT NOT NULL)''')

        conn.execute('''CREATE TABLE IF NOT EXISTS vulnerabilities
                        (id INTEGER PRIMARY KEY AUTOINCREMENT,
                         title TEXT NOT NULL,
                         description TEXT,
                         severity TEXT NOT NULL,
                         status TEXT NOT NULL,
                         asset TEXT,
                         cvss_score REAL,
                         discovered_date TEXT,
                         updated_date TEXT,
                         asset_id INTEGER REFERENCES assets(id) ON DELETE RESTRICT)''')

        columns = [r['name'] for r in conn.execute('PRAGMA table_info(vulnerabilities)')]
        if 'asset_id' not in columns:
            # Existing pre-asset database: take a one-time backup, then migrate in place.
            if not first_run:
                backup = DB_PATH + '.pre-assets.bak'
                if not os.path.exists(backup):
                    conn.commit()
                    shutil.copyfile(DB_PATH, backup)
            conn.execute('ALTER TABLE vulnerabilities '
                         'ADD COLUMN asset_id INTEGER REFERENCES assets(id) ON DELETE RESTRICT')

        conn.execute('CREATE UNIQUE INDEX IF NOT EXISTS idx_assets_name_ci ON assets(LOWER(name))')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_vuln_asset ON vulnerabilities(asset_id)')

        # Backfill: turn legacy free-text asset values into real assets and link them.
        legacy = conn.execute(
            "SELECT DISTINCT TRIM(asset) AS name FROM vulnerabilities "
            "WHERE asset_id IS NULL AND asset IS NOT NULL AND TRIM(asset) <> ''").fetchall()
        for row in legacy:
            find_or_create_asset(conn, row['name'], description='Created automatically from existing vulnerability data')
        conn.execute(
            "UPDATE vulnerabilities SET asset_id = "
            "(SELECT a.id FROM assets a WHERE LOWER(a.name) = LOWER(TRIM(vulnerabilities.asset))) "
            "WHERE asset_id IS NULL AND asset IS NOT NULL AND TRIM(asset) <> ''")
        conn.commit()
    finally:
        conn.close()


def find_or_create_asset(conn, name, description=''):
    """Look an asset up by name (case-insensitive); create a minimal one if missing."""
    name = clean_text(name, 120)
    row = conn.execute('SELECT id FROM assets WHERE LOWER(name) = LOWER(?)', (name,)).fetchone()
    if row:
        return row['id']
    ip = ''
    try:
        ip = str(ipaddress.ip_address(name))
        if conn.execute('SELECT 1 FROM assets WHERE ip_address = ?', (ip,)).fetchone():
            ip = ''
    except ValueError:
        pass
    cur = conn.execute(
        'INSERT INTO assets (name, ip_address, asset_type, operating_system, owner, description, created_date) '
        'VALUES (?, ?, ?, ?, ?, ?, ?)',
        (name, ip, 'Other', '', '', description, now_str()))
    return cur.lastrowid


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------
_CONTROL_CHARS = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]')


def clean_text(value, max_len):
    """Coerce to str, strip control characters and surrounding whitespace, cap length."""
    if value is None:
        return ''
    return _CONTROL_CHARS.sub('', str(value)).strip()[:max_len]


def validate_asset(data):
    """Return (clean_values, errors) for asset input."""
    errors = []
    name = clean_text(data.get('name'), 120)
    if not name:
        errors.append('Asset name is required.')

    ip_raw = clean_text(data.get('ip_address'), 64)
    ip = ''
    if ip_raw:
        try:
            ip = str(ipaddress.ip_address(ip_raw))
        except ValueError:
            errors.append(f"'{ip_raw}' is not a valid IPv4/IPv6 address.")

    asset_type = clean_text(data.get('asset_type'), 40) or 'Other'
    match = next((t for t in ASSET_TYPES if t.lower() == asset_type.lower()), None)
    if match is None:
        errors.append(f"Asset type must be one of: {', '.join(ASSET_TYPES)}.")
    else:
        asset_type = match

    values = {
        'name': name,
        'ip_address': ip,
        'asset_type': asset_type,
        'operating_system': clean_text(data.get('operating_system'), 100),
        'owner': clean_text(data.get('owner'), 100),
        'description': clean_text(data.get('description'), 1000),
    }
    return values, errors


def asset_conflict(conn, values, exclude_id=None):
    """Return an error string if name or IP already belongs to another asset."""
    exclude = exclude_id or -1
    if conn.execute('SELECT 1 FROM assets WHERE LOWER(name) = LOWER(?) AND id <> ?',
                    (values['name'], exclude)).fetchone():
        return f"An asset named '{values['name']}' already exists."
    if values['ip_address'] and conn.execute(
            'SELECT 1 FROM assets WHERE ip_address = ? AND id <> ?',
            (values['ip_address'], exclude)).fetchone():
        return f"An asset with IP address {values['ip_address']} already exists."
    return None


def validate_vulnerability(data, partial_ok=False):
    errors = []
    title = clean_text(data.get('title'), 200)
    if not title:
        errors.append('Title is required.')
    severity = clean_text(data.get('severity'), 20)
    if severity not in SEVERITIES:
        errors.append(f"Severity must be one of: {', '.join(SEVERITIES)}.")
    status = clean_text(data.get('status'), 20)
    if status not in STATUSES:
        errors.append(f"Status must be one of: {', '.join(STATUSES)}.")
    cvss = data.get('cvss_score', 0)
    if cvss in (None, ''):
        cvss = 0
    try:
        cvss = float(cvss)
        if not 0 <= cvss <= 10:
            raise ValueError
    except (TypeError, ValueError):
        errors.append('CVSS score must be a number between 0 and 10.')
        cvss = 0
    values = {
        'title': title,
        'description': clean_text(data.get('description'), 2000),
        'severity': severity,
        'status': status,
        'cvss_score': cvss,
    }
    return values, errors


def resolve_asset(conn, data, keep=None):
    """
    Work out which asset a vulnerability belongs to.
    Accepts `asset_id` (preferred) or the legacy free-text `asset` (matched by name,
    created if unknown, so older API clients and CSV files keep working).
    Returns (asset_id, error). `keep` is returned when neither key is supplied.
    """
    if 'asset_id' in data:
        raw = data['asset_id']
        if raw in (None, '', 'none'):
            return None, None
        try:
            asset_id = int(raw)
        except (TypeError, ValueError):
            return None, 'Invalid asset selected.'
        if not conn.execute('SELECT 1 FROM assets WHERE id = ?', (asset_id,)).fetchone():
            return None, 'The selected asset does not exist.'
        return asset_id, None
    if 'asset' in data:
        name = clean_text(data.get('asset'), 120)
        return (find_or_create_asset(conn, name) if name else None), None
    return keep, None


def asset_name(conn, asset_id):
    if asset_id is None:
        return ''
    row = conn.execute('SELECT name FROM assets WHERE id = ?', (asset_id,)).fetchone()
    return row['name'] if row else ''


def get_json_body():
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else None


def error(message, status=400, **extra):
    return jsonify({'error': message, **extra}), status


@app.errorhandler(sqlite3.Error)
def handle_db_error(exc):
    app.logger.exception('Database error: %s', exc)
    return error('A database error occurred. Please try again.', 500)


@app.errorhandler(413)
def too_large(_):
    return error('File is too large (limit is 5 MB).', 413)


init_db()


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------
@app.route('/')
def index():
    return render_template('index.html', asset_types=ASSET_TYPES)


# ---------------------------------------------------------------------------
# Vulnerabilities
# ---------------------------------------------------------------------------
VULN_SELECT = '''SELECT v.*, a.name AS asset_name, a.ip_address AS asset_ip
                 FROM vulnerabilities v
                 LEFT JOIN assets a ON a.id = v.asset_id'''


def vuln_to_dict(row):
    d = dict(row)
    # Keep the legacy `asset` field (now the linked asset's name) for older clients.
    d['asset'] = d.get('asset_name') or d.get('asset') or ''
    return d


@app.route('/api/vulnerabilities', methods=['GET'])
def get_vulnerabilities():
    """Get all vulnerabilities with optional filtering"""
    severity = request.args.get('severity')
    status = request.args.get('status')
    asset_id = request.args.get('asset_id')

    query = VULN_SELECT + ' WHERE 1=1'
    params = []

    if severity and severity != 'all':
        query += ' AND v.severity = ?'
        params.append(severity)

    if status and status != 'all':
        query += ' AND v.status = ?'
        params.append(status)

    if asset_id and asset_id != 'all':
        if asset_id == 'none':
            query += ' AND v.asset_id IS NULL'
        else:
            try:
                params.append(int(asset_id))
            except ValueError:
                return error('Invalid asset filter.')
            query += ' AND v.asset_id = ?'

    query += ' ORDER BY v.id DESC'

    with db() as conn:
        vulnerabilities = [vuln_to_dict(r) for r in conn.execute(query, params).fetchall()]
    return jsonify(vulnerabilities)


@app.route('/api/vulnerabilities', methods=['POST'])
def add_vulnerability():
    """Add a new vulnerability"""
    data = get_json_body()
    if data is None:
        return error('Request body must be a JSON object.')

    values, errors = validate_vulnerability(data)
    with db() as conn:
        asset_id, asset_err = resolve_asset(conn, data)
        if asset_err:
            errors.append(asset_err)
        if errors:
            return error(' '.join(errors), errors=errors)

        now = now_str()
        cursor = conn.execute(
            '''INSERT INTO vulnerabilities
               (title, description, severity, status, asset, asset_id, cvss_score, discovered_date, updated_date)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
            (values['title'], values['description'], values['severity'], values['status'],
             asset_name(conn, asset_id), asset_id, values['cvss_score'], now, now))
        vuln_id = cursor.lastrowid

    return jsonify({'id': vuln_id, 'message': 'Vulnerability added successfully'}), 201


@app.route('/api/vulnerabilities/<int:vuln_id>', methods=['PUT'])
def update_vulnerability(vuln_id):
    """Update a vulnerability"""
    data = get_json_body()
    if data is None:
        return error('Request body must be a JSON object.')

    values, errors = validate_vulnerability(data)
    with db() as conn:
        existing = conn.execute('SELECT asset_id FROM vulnerabilities WHERE id = ?', (vuln_id,)).fetchone()
        if not existing:
            return error('Vulnerability not found.', 404)

        asset_id, asset_err = resolve_asset(conn, data, keep=existing['asset_id'])
        if asset_err:
            errors.append(asset_err)
        if errors:
            return error(' '.join(errors), errors=errors)

        conn.execute(
            '''UPDATE vulnerabilities
               SET title=?, description=?, severity=?, status=?,
                   asset=?, asset_id=?, cvss_score=?, updated_date=?
               WHERE id=?''',
            (values['title'], values['description'], values['severity'], values['status'],
             asset_name(conn, asset_id), asset_id, values['cvss_score'], now_str(), vuln_id))

    return jsonify({'message': 'Vulnerability updated successfully'})


@app.route('/api/vulnerabilities/<int:vuln_id>', methods=['DELETE'])
def delete_vulnerability(vuln_id):
    """Delete a vulnerability"""
    with db() as conn:
        cur = conn.execute('DELETE FROM vulnerabilities WHERE id=?', (vuln_id,))
        if cur.rowcount == 0:
            return error('Vulnerability not found.', 404)
    return jsonify({'message': 'Vulnerability deleted successfully'})


# ---------------------------------------------------------------------------
# Assets
# ---------------------------------------------------------------------------
ASSET_SELECT = '''SELECT a.*,
                         COUNT(v.id) AS vuln_count,
                         COALESCE(SUM(CASE WHEN v.status <> 'Fixed' THEN 1 ELSE 0 END), 0) AS open_vuln_count,
                         COALESCE(SUM(CASE WHEN v.severity = 'Critical' THEN 1 ELSE 0 END), 0) AS critical_count
                  FROM assets a
                  LEFT JOIN vulnerabilities v ON v.asset_id = a.id'''


def like_escape(term):
    return term.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')


@app.route('/api/assets', methods=['GET'])
def get_assets():
    """List assets with optional ?search= (name/IP) and ?type= filters."""
    search = clean_text(request.args.get('search'), 100)
    asset_type = request.args.get('type')

    query = ASSET_SELECT + ' WHERE 1=1'
    params = []
    if search:
        like = f'%{like_escape(search.lower())}%'
        query += " AND (LOWER(a.name) LIKE ? ESCAPE '\\' OR LOWER(a.ip_address) LIKE ? ESCAPE '\\')"
        params += [like, like]
    if asset_type and asset_type != 'all':
        query += ' AND a.asset_type = ?'
        params.append(asset_type)
    query += ' GROUP BY a.id ORDER BY a.id DESC'

    with db() as conn:
        return jsonify([dict(r) for r in conn.execute(query, params).fetchall()])


@app.route('/api/assets/<int:asset_id>', methods=['GET'])
def get_asset(asset_id):
    """Asset details including every vulnerability linked to it."""
    with db() as conn:
        row = conn.execute(ASSET_SELECT + ' WHERE a.id = ? GROUP BY a.id', (asset_id,)).fetchone()
        if not row:
            return error('Asset not found.', 404)
        asset = dict(row)
        vulns = conn.execute(VULN_SELECT + ' WHERE v.asset_id = ? ORDER BY v.id DESC', (asset_id,)).fetchall()
        asset['vulnerabilities'] = [vuln_to_dict(v) for v in vulns]
        asset['severity_counts'] = {s: sum(1 for v in vulns if v['severity'] == s) for s in SEVERITIES}
    return jsonify(asset)


@app.route('/api/assets', methods=['POST'])
def add_asset():
    data = get_json_body()
    if data is None:
        return error('Request body must be a JSON object.')

    values, errors = validate_asset(data)
    if errors:
        return error(' '.join(errors), errors=errors)

    with db() as conn:
        conflict = asset_conflict(conn, values)
        if conflict:
            return error(conflict, 409)
        cur = conn.execute(
            '''INSERT INTO assets (name, ip_address, asset_type, operating_system, owner, description, created_date)
               VALUES (?, ?, ?, ?, ?, ?, ?)''',
            (values['name'], values['ip_address'], values['asset_type'], values['operating_system'],
             values['owner'], values['description'], now_str()))
        asset_id = cur.lastrowid
    return jsonify({'id': asset_id, 'message': 'Asset added successfully'}), 201


@app.route('/api/assets/<int:asset_id>', methods=['PUT'])
def update_asset(asset_id):
    data = get_json_body()
    if data is None:
        return error('Request body must be a JSON object.')

    values, errors = validate_asset(data)
    if errors:
        return error(' '.join(errors), errors=errors)

    with db() as conn:
        if not conn.execute('SELECT 1 FROM assets WHERE id = ?', (asset_id,)).fetchone():
            return error('Asset not found.', 404)
        conflict = asset_conflict(conn, values, exclude_id=asset_id)
        if conflict:
            return error(conflict, 409)
        conn.execute(
            '''UPDATE assets SET name=?, ip_address=?, asset_type=?, operating_system=?, owner=?, description=?
               WHERE id=?''',
            (values['name'], values['ip_address'], values['asset_type'], values['operating_system'],
             values['owner'], values['description'], asset_id))
        # Keep the legacy text column on vulnerabilities in sync with the asset name.
        conn.execute('UPDATE vulnerabilities SET asset = ? WHERE asset_id = ?', (values['name'], asset_id))
    return jsonify({'message': 'Asset updated successfully'})


@app.route('/api/assets/<int:asset_id>', methods=['DELETE'])
def delete_asset(asset_id):
    """
    Delete an asset. If vulnerabilities are linked, the request is refused (409) unless
    ?reassign_to=<other asset id> moves them, or ?reassign_to=none leaves them unassigned.
    """
    reassign_to = request.args.get('reassign_to')
    with db() as conn:
        if not conn.execute('SELECT 1 FROM assets WHERE id = ?', (asset_id,)).fetchone():
            return error('Asset not found.', 404)

        count = conn.execute('SELECT COUNT(*) FROM vulnerabilities WHERE asset_id = ?', (asset_id,)).fetchone()[0]
        if count:
            if reassign_to is None:
                return error(
                    f'This asset has {count} associated vulnerabilit{"y" if count == 1 else "ies"}. '
                    'Reassign them to another asset before deleting.',
                    409, vulnerability_count=count)
            if reassign_to == 'none':
                conn.execute("UPDATE vulnerabilities SET asset_id = NULL, asset = '' WHERE asset_id = ?", (asset_id,))
            else:
                try:
                    target = int(reassign_to)
                except ValueError:
                    return error('Invalid reassignment target.')
                if target == asset_id:
                    return error('Cannot reassign vulnerabilities to the asset being deleted.')
                if not conn.execute('SELECT 1 FROM assets WHERE id = ?', (target,)).fetchone():
                    return error('Reassignment target asset does not exist.', 404)
                conn.execute('UPDATE vulnerabilities SET asset_id = ?, asset = ? WHERE asset_id = ?',
                             (target, asset_name(conn, target), asset_id))

        conn.execute('DELETE FROM assets WHERE id = ?', (asset_id,))
    return jsonify({'message': 'Asset deleted successfully', 'reassigned': count})


# ---------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------
@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get dashboard statistics (original keys preserved, asset data added)"""
    with db() as conn:
        def scalar(sql, *params):
            return conn.execute(sql, params).fetchone()[0]

        stats = {
            'total': scalar('SELECT COUNT(*) FROM vulnerabilities'),
            'critical': scalar('SELECT COUNT(*) FROM vulnerabilities WHERE severity=?', 'Critical'),
            'high': scalar('SELECT COUNT(*) FROM vulnerabilities WHERE severity=?', 'High'),
            'medium': scalar('SELECT COUNT(*) FROM vulnerabilities WHERE severity=?', 'Medium'),
            'low': scalar('SELECT COUNT(*) FROM vulnerabilities WHERE severity=?', 'Low'),
            'open': scalar('SELECT COUNT(*) FROM vulnerabilities WHERE status=?', 'Open'),
            'in_progress': scalar('SELECT COUNT(*) FROM vulnerabilities WHERE status=?', 'In Progress'),
            'fixed': scalar('SELECT COUNT(*) FROM vulnerabilities WHERE status=?', 'Fixed'),
            'total_assets': scalar('SELECT COUNT(*) FROM assets'),
            'unassigned': scalar('SELECT COUNT(*) FROM vulnerabilities WHERE asset_id IS NULL'),
        }

        per_asset = [dict(r) for r in conn.execute(
            '''SELECT a.id, a.name, a.ip_address, a.asset_type, COUNT(v.id) AS count
               FROM assets a JOIN vulnerabilities v ON v.asset_id = a.id
               GROUP BY a.id ORDER BY count DESC, a.name COLLATE NOCASE LIMIT 10''').fetchall()]
        stats['top_assets'] = per_asset[:5]
        stats['vulns_per_asset'] = per_asset
        stats['assets_by_type'] = [dict(r) for r in conn.execute(
            'SELECT asset_type AS type, COUNT(*) AS count FROM assets GROUP BY asset_type ORDER BY count DESC').fetchall()]
    return jsonify(stats)


# ---------------------------------------------------------------------------
# CSV import
# ---------------------------------------------------------------------------
def read_csv_upload():
    """Return (DictReader rows list, normalized fieldnames) or (None, error_message)."""
    file = request.files.get('file')
    if not file or not file.filename:
        return None, 'No file provided'
    try:
        content = file.read().decode('utf-8-sig')
    except UnicodeDecodeError:
        return None, 'File must be UTF-8 encoded CSV.'
    reader = csv.DictReader(StringIO(content))
    if not reader.fieldnames:
        return None, 'CSV file is empty or has no header row.'
    reader.fieldnames = [re.sub(r'\s+', '_', (h or '').strip().lower()) for h in reader.fieldnames]
    return reader, None


ASSET_CSV_ALIASES = {
    'asset_name': 'name', 'ip': 'ip_address', 'ip_addr': 'ip_address', 'type': 'asset_type',
    'os': 'operating_system', 'responsible_person': 'owner',
}


@app.route('/api/import-csv', methods=['POST'])
def import_csv():
    """Import vulnerabilities from CSV file. Assets are matched by name (created if new)."""
    reader, err = read_csv_upload()
    if err:
        return error(err)

    required = {'title', 'severity', 'status'}
    missing = required - set(reader.fieldnames)
    if missing:
        return error(f"Missing required column(s): {', '.join(sorted(missing))}")

    imported, errors = 0, []
    try:
        with db() as conn:
            for line, row in enumerate(reader, start=2):
                row = {k: v for k, v in row.items() if k}
                values, row_errors = validate_vulnerability(row)
                if row_errors:
                    errors.append({'row': line, 'error': ' '.join(row_errors)})
                    continue
                asset_id, asset_err = resolve_asset(conn, {'asset': row.get('asset')})
                if asset_err:
                    errors.append({'row': line, 'error': asset_err})
                    continue
                discovered = clean_text(row.get('discovered_date'), 30) or now_str()
                conn.execute(
                    '''INSERT INTO vulnerabilities
                       (title, description, severity, status, asset, asset_id, cvss_score, discovered_date, updated_date)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                    (values['title'], values['description'], values['severity'], values['status'],
                     asset_name(conn, asset_id), asset_id, values['cvss_score'], discovered, discovered))
                imported += 1
    except csv.Error as exc:
        return error(f'Malformed CSV: {exc}')

    message = f'Successfully imported {imported} vulnerabilities'
    if errors:
        message += f' ({len(errors)} row(s) skipped)'
    return jsonify({'message': message, 'imported': imported, 'errors': errors}), 200


@app.route('/api/assets/import-csv', methods=['POST'])
def import_assets_csv():
    """
    Import assets from CSV. Columns: name (required), ip_address, asset_type,
    operating_system, owner, description. Duplicates (same name or IP) are skipped.
    """
    reader, err = read_csv_upload()
    if err:
        return error(err)

    reader.fieldnames = [ASSET_CSV_ALIASES.get(h, h) for h in reader.fieldnames]
    if 'name' not in reader.fieldnames:
        return error("Missing required column: name")

    imported, duplicates, errors = 0, [], []
    try:
        with db() as conn:
            for line, row in enumerate(reader, start=2):
                row = {k: v for k, v in row.items() if k}
                if not any((v or '').strip() for v in row.values() if isinstance(v, str)):
                    continue  # blank line
                values, row_errors = validate_asset(row)
                if row_errors:
                    errors.append({'row': line, 'error': ' '.join(row_errors)})
                    continue
                conflict = asset_conflict(conn, values)
                if conflict:
                    duplicates.append({'row': line, 'error': conflict})
                    continue
                conn.execute(
                    '''INSERT INTO assets (name, ip_address, asset_type, operating_system, owner, description, created_date)
                       VALUES (?, ?, ?, ?, ?, ?, ?)''',
                    (values['name'], values['ip_address'], values['asset_type'], values['operating_system'],
                     values['owner'], values['description'], now_str()))
                imported += 1
    except csv.Error as exc:
        return error(f'Malformed CSV: {exc}')

    parts = [f'Imported {imported} asset(s)']
    if duplicates:
        parts.append(f'{len(duplicates)} duplicate(s) skipped')
    if errors:
        parts.append(f'{len(errors)} invalid row(s) skipped')
    return jsonify({'message': ', '.join(parts), 'imported': imported,
                    'duplicates': duplicates, 'errors': errors}), 200


if __name__ == '__main__':
    # Set FLASK_DEBUG=1 for auto-reload during development. Bound to localhost only.
    app.run(host='127.0.0.1', debug=os.environ.get('FLASK_DEBUG') == '1', port=5000)
