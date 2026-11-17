/* VulnGuard front-end: scanner page. Relies on helpers from app.js (esc, api, jsonOptions, toast). */

const SCAN_SEVERITIES = ['Critical', 'High', 'Medium', 'Low', 'Informational'];
const SCAN_SEV_CLASS = { Critical: 'danger', High: 'warning', Medium: 'info', Low: 'secondary', Informational: 'secondary' };
let scanPollTimer = null;
let scanViewedId = null;
let scanToken = '';           // kept in memory only, never written to storage

function scanHeaders(json) {
    const headers = json ? { 'Content-Type': 'application/json' } : {};
    if (scanToken) headers['X-API-Token'] = scanToken;
    return headers;
}

function scanGet(url) { return api(url, { headers: scanHeaders(false) }); }

function stopScanPolling() {
    if (scanPollTimer) { clearTimeout(scanPollTimer); scanPollTimer = null; }
}

function scanTokenNeeded() {
    document.getElementById('scan-token-group').classList.remove('d-none');
}

async function initScannerView() {
    scanToken = document.getElementById('scan-token').value || scanToken;
    const { ok, status, data } = await scanGet('/api/scanner/options');
    if (status === 401) { scanTokenNeeded(); showScanError(data.error || 'API token required.'); return; }
    if (!ok) { showScanError(data.error || 'Could not load scanner options.'); return; }
    showScanError('');
    document.getElementById('scan-categories').innerHTML = data.categories.map(c =>
        `<div class="form-check"><input class="form-check-input scan-category" type="checkbox" id="scan-cat-${esc(c.id)}" value="${esc(c.id)}" checked>
         <label class="form-check-label" for="scan-cat-${esc(c.id)}">${esc(c.label)}</label></div>`).join('');
    const select = document.getElementById('scan-asset');
    const chosen = select.value;
    select.innerHTML = '<option value="">No asset</option>' +
        data.assets.map(a => `<option value="${a.id}">${esc(a.name)}</option>`).join('');
    select.value = chosen;
    const l = data.limits;
    document.getElementById('scan-limits').textContent =
        `Passive checks only. Limits: depth ${l.max_depth}, up to ${l.max_pages} pages, ${l.max_requests} requests, ${l.max_requests_per_second} requests/second.` +
        (data.allowlist_configured ? '' : ' No scan allowlist is configured, so every target will be refused until VULNGUARD_SCAN_ALLOWLIST is set.');
    document.getElementById('scan-submit').disabled = data.busy;
    await loadScanHistory();
    if (scanViewedId) await showScan(scanViewedId);
}

function showScanError(message) {
    const el = document.getElementById('scan-form-error');
    el.textContent = message || '';
    el.classList.toggle('d-none', !message);
}

async function loadScanHistory() {
    const { ok, data } = await scanGet('/api/scans');
    const body = document.getElementById('scan-history');
    if (!ok) { body.innerHTML = '<tr><td colspan="5" class="text-muted">Could not load scans.</td></tr>'; return; }
    document.getElementById('scan-submit').disabled = !!data.busy;
    if (!data.scans.length) { body.innerHTML = '<tr><td colspan="5" class="text-muted">No scans yet.</td></tr>'; return; }
    body.innerHTML = data.scans.map(s => `<tr>
        <td class="text-break">${esc(s.target)}${s.asset_name ? `<div class="small text-muted">${esc(s.asset_name)}</div>` : ''}</td>
        <td>${scanStatusBadge(s.status)}</td><td>${s.findings_total}</td><td>${esc(s.started_at)}</td>
        <td><button class="btn btn-sm btn-outline-dark-soft" onclick="showScan(${s.id})">View</button></td></tr>`).join('');
}

function scanStatusBadge(status) {
    const cls = { running: 'info', completed: 'success', completed_with_errors: 'warning', failed: 'danger' }[status] || 'secondary';
    const label = { running: 'Running', completed: 'Completed', completed_with_errors: 'Completed with errors', failed: 'Failed' }[status] || status;
    return `<span class="badge bg-${cls}">${esc(label)}</span>`;
}

async function showScan(id) {
    scanViewedId = id;
    stopScanPolling();
    const { ok, data } = await scanGet('/api/scans/' + id);
    const card = document.getElementById('scan-result-card');
    if (!ok) { toast(data.error || 'Could not load the scan.', 'danger'); return; }
    card.classList.remove('d-none');
    document.getElementById('scan-result').innerHTML = renderScan(data);
    if (data.status === 'running') {
        scanPollTimer = setTimeout(async () => { await loadScanHistory(); await showScan(id); }, 2000);
    } else {
        loadScanHistory();
    }
}

function renderScan(s) {
    const counts = SCAN_SEVERITIES.map(sev =>
        `<span class="badge bg-${SCAN_SEV_CLASS[sev]} me-1">${esc(sev)}: ${s.severity_counts[sev] || 0}</span>`).join('');
    let html = `<div class="d-flex justify-content-between flex-wrap gap-2 mb-2">
        <h5 class="card-title mb-0">Scan #${s.id} ${scanStatusBadge(s.status)}</h5>
        <span class="text-muted small">${s.status === 'running' ? 'Stage: ' + esc(s.stage) + ' (' + s.checks_done + '/' + s.checks_total + ' checks)' : ''}</span></div>
        <dl class="row small mb-3">
          <dt class="col-sm-3">Target</dt><dd class="col-sm-9 text-break">${esc(s.target)}</dd>
          ${s.asset_name ? `<dt class="col-sm-3">Asset</dt><dd class="col-sm-9">${esc(s.asset_name)}</dd>` : ''}
          <dt class="col-sm-3">Started</dt><dd class="col-sm-9">${esc(s.started_at)}</dd>
          <dt class="col-sm-3">Completed</dt><dd class="col-sm-9">${esc(s.completed_at || '-')}</dd>
          <dt class="col-sm-3">Pages / requests</dt><dd class="col-sm-9">${s.pages_crawled} pages, ${s.requests_used} requests</dd>
          <dt class="col-sm-3">Total findings</dt><dd class="col-sm-9">${s.findings_total} &nbsp; ${counts}</dd>
        </dl>`;
    (s.errors || []).forEach(e => { html += `<div class="alert alert-danger py-2">${esc(e)}</div>`; });
    (s.notes || []).forEach(n => { html += `<div class="alert alert-warning py-2">${esc(n)}</div>`; });
    if (s.status === 'running') return html + '<div class="text-muted">Scan in progress. Results appear here when it finishes.</div>';
    if (!s.findings.length) return html + '<div class="text-muted">No findings were reported.</div>';
    for (const sev of SCAN_SEVERITIES) {
        const group = s.findings.filter(f => f.severity === sev);
        if (!group.length) continue;
        html += `<h6 class="mt-3"><span class="badge bg-${SCAN_SEV_CLASS[sev]}">${esc(sev)}</span> <span class="count-pill">${group.length}</span></h6>`;
        html += group.map(renderScanFinding).join('');
    }
    return html;
}

function renderScanFinding(f) {
    const urls = f.urls.map(u => `<div class="text-break">${esc(u)}</div>`).join('');
    return `<details class="border rounded p-2 mb-2"><summary><strong>${esc(f.title)}</strong>
        <span class="text-muted small"> &middot; ${esc(f.category_label)} &middot; ${esc(f.confidence)}</span></summary>
        <div class="small mt-2">
          <p class="mb-1">${esc(f.description)}</p>
          <div class="mb-1"><strong>Affected URL${f.urls.length > 1 ? 's' : ''}:</strong>${urls}</div>
          <div class="mb-1"><strong>Evidence:</strong> <span class="text-break">${esc(f.evidence)}</span></div>
          <div class="mb-1"><strong>Impact:</strong> ${esc(f.impact)}</div>
          <div class="mb-1"><strong>Remediation:</strong> ${esc(f.remediation)}</div>
          <div class="text-muted">${esc(f.reference)} &middot; ${esc(f.detection_method)} &middot; ${esc(f.rule_id)}</div>
        </div></details>`;
}

document.getElementById('scanForm').addEventListener('submit', async (event) => {
    event.preventDefault();
    const button = document.getElementById('scan-submit');
    if (button.disabled) return;                        // a second click/Enter while a request is in flight
    showScanError('');
    scanToken = document.getElementById('scan-token').value || scanToken;
    const categories = [...document.querySelectorAll('.scan-category:checked')].map(c => c.value);
    const assetId = document.getElementById('scan-asset').value;
    button.disabled = true;
    const { ok, status, data } = await api('/api/scans', {
        method: 'POST', headers: scanHeaders(true),
        body: JSON.stringify({
            target: document.getElementById('scan-target').value.trim(),
            categories,
            asset_id: assetId ? Number(assetId) : null,
            authorized: document.getElementById('scan-authorized').checked,
        }),
    });
    if (status === 401) scanTokenNeeded();
    if (!ok) { showScanError(data.error || 'The scan could not be started.'); button.disabled = status === 409; if (status === 409) loadScanHistory(); return; }
    await loadScanHistory();
    await showScan(data.id);
    toast('Scan started.');
});
