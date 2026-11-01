/* VulnGuard front-end: dashboard, vulnerabilities and asset management */

let allVulnerabilities = [];   // result of the current vulnerability query
let allAssets = [];            // every asset (unfiltered) - feeds dropdowns and delete dialog
let assetDetailId = null;
const charts = {};

const SEV_COLORS = { Critical: '#e34e66', High: '#f3ad45', Medium: '#3983c4', Low: '#a9b6ca' };
const STATUS_COLORS = { 'Open': '#e34e66', 'In Progress': '#f3ad45', 'Fixed': '#27bd8a' };
const TYPE_COLORS = ['#4169f5', '#27bd8a', '#f3ad45', '#e34e66', '#8b5cf6', '#a9b6ca'];

/* ---------------------------------------------------------------- helpers */
function esc(value) {
    return String(value ?? '').replace(/[&<>"']/g, c => (
        { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function fmtDate(s) {
    if (!s) return '-';
    const d = new Date(String(s).replace(' ', 'T'));
    return isNaN(d) ? esc(s) : d.toLocaleDateString();
}

function assetCode(id) { return 'AST-' + String(id).padStart(4, '0'); }

function getSeverityColor(severity) {
    return { 'Critical': 'danger', 'High': 'warning', 'Medium': 'info', 'Low': 'secondary' }[severity] || 'secondary';
}

function getStatusColor(status) {
    return { 'Open': 'danger', 'In Progress': 'warning', 'Fixed': 'success' }[status] || 'secondary';
}

async function api(url, options) {
    try {
        const response = await fetch(url, options);
        let data = {};
        try { data = await response.json(); } catch (_) { /* non-JSON body */ }
        return { ok: response.ok, status: response.status, data };
    } catch (err) {
        return { ok: false, status: 0, data: { error: 'Network error - is the VulnGuard server running?' } };
    }
}

function jsonOptions(method, body) {
    return { method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) };
}

function toast(message, type = 'success') {
    const icon = { success: 'fa-circle-check', danger: 'fa-circle-exclamation', warning: 'fa-triangle-exclamation' }[type];
    const el = document.createElement('div');
    el.className = `toast vg-toast vg-toast-${type} align-items-center border-0`;
    el.setAttribute('role', type === 'danger' ? 'alert' : 'status');
    el.innerHTML = `<div class="d-flex"><div class="toast-body"><i class="fas ${icon} me-2"></i>${esc(message)}</div>
        <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast" aria-label="Close"></button></div>`;
    document.getElementById('toast-container').appendChild(el);
    const t = new bootstrap.Toast(el, { delay: type === 'danger' ? 7000 : 4000 });
    el.addEventListener('hidden.bs.toast', () => el.remove());
    t.show();
}

function modal(id) { return bootstrap.Modal.getOrCreateInstance(document.getElementById(id)); }

/** Hide one modal, then run fn once it has fully closed (avoids stacked backdrops). */
function afterHidden(id, fn) {
    const el = document.getElementById(id);
    if (!el.classList.contains('show')) { fn(); return; }
    el.addEventListener('hidden.bs.modal', fn, { once: true });
    modal(id).hide();
}

function showFormError(id, message) {
    const el = document.getElementById(id);
    el.textContent = message || '';
    el.classList.toggle('d-none', !message);
}

function debounce(fn, ms) {
    let timer;
    return (...args) => { clearTimeout(timer); timer = setTimeout(() => fn(...args), ms); };
}

/* ---------------------------------------------------------------- routing */
function route() {
    const view = location.hash === '#assets' ? 'assets' : 'dashboard';
    document.getElementById('view-dashboard').classList.toggle('d-none', view !== 'dashboard');
    document.getElementById('view-assets').classList.toggle('d-none', view !== 'assets');
    document.getElementById('nav-dashboard').classList.toggle('active', view === 'dashboard');
    document.getElementById('nav-assets').classList.toggle('active', view === 'assets');
    refreshAll();
}

async function refreshAll() {
    await loadAssetOptions();
    await Promise.all([loadVulnerabilities(), loadAssets()]);
}

/* ---------------------------------------------------------------- stats & charts */
async function loadStats() {
    const { ok, data: stats } = await api('/api/stats');
    if (!ok) return;

    const set = (id, v) => { document.getElementById(id).textContent = v; };
    set('stat-assets', stats.total_assets);
    set('stat-total', stats.total);
    set('stat-critical', stats.critical);
    set('stat-high', stats.high);
    set('stat-medium', stats.medium);
    set('stat-low', stats.low);
    set('stat-open', stats.open);
    set('stat-fixed', stats.fixed);

    renderTopAssets(stats.top_assets);

    upsertChart('severity', 'chart-severity', 'doughnut',
        ['Critical', 'High', 'Medium', 'Low'],
        [stats.critical, stats.high, stats.medium, stats.low],
        ['Critical', 'High', 'Medium', 'Low'].map(k => SEV_COLORS[k]));

    upsertChart('status', 'chart-status', 'doughnut',
        ['Open', 'In Progress', 'Fixed'],
        [stats.open, stats.in_progress, stats.fixed],
        ['Open', 'In Progress', 'Fixed'].map(k => STATUS_COLORS[k]));

    upsertChart('types', 'chart-types', 'doughnut',
        stats.assets_by_type.map(t => t.type),
        stats.assets_by_type.map(t => t.count),
        stats.assets_by_type.map((_, i) => TYPE_COLORS[i % TYPE_COLORS.length]));

    upsertChart('assets', 'chart-assets', 'bar',
        stats.vulns_per_asset.map(a => a.name),
        stats.vulns_per_asset.map(a => a.count),
        '#4169f5');
}

function upsertChart(key, canvasId, type, labels, values, colors) {
    const canvas = document.getElementById(canvasId);
    const empty = canvas.parentElement.querySelector('.chart-empty');
    const hasData = values.some(v => v > 0);
    canvas.classList.toggle('d-none', !hasData);
    empty.classList.toggle('d-none', hasData);
    if (typeof Chart === 'undefined') return;

    if (!hasData) {
        if (charts[key]) { charts[key].destroy(); delete charts[key]; }
        return;
    }
    if (charts[key]) {
        const c = charts[key];
        c.data.labels = labels;
        c.data.datasets[0].data = values;
        c.data.datasets[0].backgroundColor = colors;
        if (type === 'bar') c.data.datasets[0].borderColor = colors;
        c.update();
        return;
    }

    const isBar = type === 'bar';
    charts[key] = new Chart(canvas, {
        type,
        data: {
            labels,
            datasets: [{
                data: values,
                backgroundColor: colors,
                borderColor: isBar ? colors : '#fff',
                borderWidth: isBar ? 0 : 2,
                borderRadius: isBar ? 6 : 0,
                maxBarThickness: 26,
            }],
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            indexAxis: isBar ? 'y' : 'x',
            cutout: isBar ? undefined : '62%',
            plugins: {
                legend: isBar ? { display: false } : {
                    position: 'bottom',
                    labels: { usePointStyle: true, boxWidth: 8, font: { family: 'DM Sans', size: 11 }, color: '#687791' },
                },
            },
            scales: isBar ? {
                x: { beginAtZero: true, ticks: { precision: 0, color: '#8b98ad' }, grid: { color: '#f0f3f8' } },
                y: { ticks: { color: '#687791', font: { size: 11 } }, grid: { display: false } },
            } : {},
        },
    });
}

function renderTopAssets(top) {
    const list = document.getElementById('top-assets');
    if (!top.length) {
        list.innerHTML = '<li class="text-muted top-empty">No vulnerabilities linked to assets yet.</li>';
        return;
    }
    const max = top[0].count || 1;
    list.innerHTML = top.map(a => `
        <li>
            <a href="#" onclick="viewAsset(${a.id}); return false;" class="top-asset-name">${esc(a.name)}</a>
            <span class="top-asset-ip">${esc(a.ip_address || a.asset_type)}</span>
            <span class="top-asset-bar"><span style="width:${Math.round(a.count / max * 100)}%"></span></span>
            <span class="top-asset-count">${a.count}</span>
        </li>`).join('');
}

/* ---------------------------------------------------------------- vulnerabilities */
async function loadVulnerabilities() {
    const severity = document.getElementById('filter-severity').value;
    const status = document.getElementById('filter-status').value;
    const asset = document.getElementById('filter-asset').value;

    const params = new URLSearchParams({ severity, status, asset_id: asset });
    const { ok, data } = await api(`/api/vulnerabilities?${params}`);
    if (!ok) {
        toast(data.error || 'Could not load vulnerabilities.', 'danger');
        return;
    }
    allVulnerabilities = data;
    searchVulnerabilities();
    loadStats();
}

function displayVulnerabilities(vulnerabilities) {
    const tbody = document.getElementById('vulnerabilities-table');

    if (vulnerabilities.length === 0) {
        tbody.innerHTML = '<tr><td colspan="8" class="text-center">No vulnerabilities found</td></tr>';
        return;
    }

    tbody.innerHTML = vulnerabilities.map(v => `
        <tr>
            <td>${v.id}</td>
            <td><strong>${esc(v.title)}</strong></td>
            <td>${assetCell(v)}</td>
            <td><span class="badge bg-${getSeverityColor(v.severity)}">${esc(v.severity)}</span></td>
            <td>${v.cvss_score || '-'}</td>
            <td><span class="badge bg-${getStatusColor(v.status)}">${esc(v.status)}</span></td>
            <td>${fmtDate(v.discovered_date)}</td>
            <td class="text-nowrap">
                <button class="btn btn-sm btn-outline-primary" onclick="editVulnerability(${v.id})" title="Edit" aria-label="Edit vulnerability">
                    <i class="fas fa-edit"></i>
                </button>
                <button class="btn btn-sm btn-outline-danger" onclick="deleteVulnerability(${v.id})" title="Delete" aria-label="Delete vulnerability">
                    <i class="fas fa-trash"></i>
                </button>
            </td>
        </tr>
    `).join('');
}

function assetCell(v) {
    if (!v.asset_id) return v.asset ? esc(v.asset) : '<span class="text-muted">Unassigned</span>';
    return `<a href="#" class="asset-link" onclick="viewAsset(${v.asset_id}); return false;">${esc(v.asset_name)}</a>` +
        (v.asset_ip ? `<div class="cell-sub">${esc(v.asset_ip)}</div>` : '');
}

function searchVulnerabilities() {
    const term = document.getElementById('search-box').value.toLowerCase();
    const filtered = allVulnerabilities.filter(v =>
        v.title.toLowerCase().includes(term) ||
        (v.description && v.description.toLowerCase().includes(term)) ||
        (v.asset && v.asset.toLowerCase().includes(term)) ||
        (v.asset_ip && v.asset_ip.toLowerCase().includes(term))
    );
    displayVulnerabilities(filtered);
}

function populateAssetSelect(select, assets, firstLabel, keepValue = true) {
    const previous = keepValue ? select.value : '';
    select.innerHTML = `<option value="${select.id === 'filter-asset' ? 'all' : ''}">${esc(firstLabel)}</option>`;
    if (select.id === 'filter-asset') select.insertAdjacentHTML('beforeend', '<option value="none">Unassigned</option>');
    assets.forEach(a => {
        const opt = document.createElement('option');
        opt.value = a.id;
        opt.textContent = a.ip_address ? `${a.name} (${a.ip_address})` : a.name;
        select.appendChild(opt);
    });
    if ([...select.options].some(o => o.value === previous)) select.value = previous;
}

async function loadAssetOptions() {
    const { ok, data } = await api('/api/assets');
    if (!ok) return;
    allAssets = data;
    populateAssetSelect(document.getElementById('filter-asset'), allAssets, 'All Assets');
    populateAssetSelect(document.getElementById('vuln-asset'), allAssets, '— Select an asset —');
    document.getElementById('vuln-asset-hint').classList.toggle('d-none', allAssets.length > 0);
}

function openVulnModal(presetAssetId) {
    document.getElementById('vulnForm').reset();
    document.getElementById('vuln-id').value = '';
    document.getElementById('modalTitle').textContent = 'Add Vulnerability';
    showFormError('vuln-form-error', '');
    // Pre-select the asset currently being filtered on (or the one passed in).
    const filtered = document.getElementById('filter-asset').value;
    const preset = presetAssetId ?? (/^\d+$/.test(filtered) ? filtered : '');
    document.getElementById('vuln-asset').value = String(preset);
    modal('addModal').show();
}

function closeVulnModal() { modal('addModal').hide(); }

async function saveVulnerability() {
    const id = document.getElementById('vuln-id').value;
    const title = document.getElementById('vuln-title').value.trim();
    const assetId = document.getElementById('vuln-asset').value;
    const cvssRaw = document.getElementById('vuln-cvss').value;
    const cvss = cvssRaw === '' ? 0 : parseFloat(cvssRaw);

    if (!title) return showFormError('vuln-form-error', 'Title is required.');
    if (!assetId) return showFormError('vuln-form-error', 'Please select an asset (create one on the Assets page if none exist).');
    if (isNaN(cvss) || cvss < 0 || cvss > 10) return showFormError('vuln-form-error', 'CVSS score must be between 0 and 10.');
    showFormError('vuln-form-error', '');

    const data = {
        title,
        description: document.getElementById('vuln-description').value,
        severity: document.getElementById('vuln-severity').value,
        status: document.getElementById('vuln-status').value,
        asset_id: parseInt(assetId, 10),
        cvss_score: cvss,
    };

    const url = id ? `/api/vulnerabilities/${id}` : '/api/vulnerabilities';
    const res = await api(url, jsonOptions(id ? 'PUT' : 'POST', data));
    if (!res.ok) return showFormError('vuln-form-error', res.data.error || 'Could not save vulnerability.');

    modal('addModal').hide();
    toast(id ? 'Vulnerability updated.' : 'Vulnerability added.');
    refreshAll();
}

function editVulnerability(id) {
    const vuln = allVulnerabilities.find(v => v.id === id);
    if (!vuln) return;

    showFormError('vuln-form-error', '');
    document.getElementById('modalTitle').textContent = 'Edit Vulnerability';
    document.getElementById('vuln-id').value = vuln.id;
    document.getElementById('vuln-title').value = vuln.title;
    document.getElementById('vuln-description').value = vuln.description || '';
    document.getElementById('vuln-severity').value = vuln.severity;
    document.getElementById('vuln-status').value = vuln.status;
    document.getElementById('vuln-asset').value = vuln.asset_id ? String(vuln.asset_id) : '';
    document.getElementById('vuln-cvss').value = vuln.cvss_score || '';

    modal('addModal').show();
}

async function deleteVulnerability(id) {
    if (!confirm('Are you sure you want to delete this vulnerability?')) return;

    const res = await api(`/api/vulnerabilities/${id}`, { method: 'DELETE' });
    if (!res.ok) return toast(res.data.error || 'Could not delete vulnerability.', 'danger');
    toast('Vulnerability deleted.');
    refreshAll();
}

document.getElementById('addModal').addEventListener('hidden.bs.modal', function () {
    document.getElementById('modalTitle').textContent = 'Add Vulnerability';
    document.getElementById('vulnForm').reset();
    document.getElementById('vuln-id').value = '';
    showFormError('vuln-form-error', '');
});

/* ---------------------------------------------------------------- assets */
const debouncedAssetSearch = debounce(() => loadAssets(), 250);

async function loadAssets() {
    const params = new URLSearchParams({
        search: document.getElementById('asset-search').value.trim(),
        type: document.getElementById('asset-filter-type').value,
    });
    const { ok, data } = await api(`/api/assets?${params}`);
    if (!ok) return toast(data.error || 'Could not load assets.', 'danger');
    renderAssets(data);
}

function renderAssets(assets) {
    document.getElementById('asset-count').textContent = assets.length;
    const tbody = document.getElementById('assets-table');
    if (!assets.length) {
        const filtering = document.getElementById('asset-search').value.trim() ||
            document.getElementById('asset-filter-type').value !== 'all';
        tbody.innerHTML = `<tr><td colspan="9" class="text-center">${
            filtering ? 'No assets match your search.' : 'No assets registered yet. Click “New asset” to add one.'}</td></tr>`;
        return;
    }
    tbody.innerHTML = assets.map(a => `
        <tr>
            <td>${assetCode(a.id)}</td>
            <td><a href="#" class="asset-link" onclick="viewAsset(${a.id}); return false;"><strong>${esc(a.name)}</strong></a></td>
            <td>${esc(a.ip_address) || '-'}</td>
            <td><span class="badge bg-type">${esc(a.asset_type)}</span></td>
            <td>${esc(a.operating_system) || '-'}</td>
            <td>${esc(a.owner) || '-'}</td>
            <td>
                <span class="vuln-count ${a.vuln_count ? '' : 'zero'}">${a.vuln_count}</span>
                ${a.critical_count ? `<span class="badge bg-danger ms-1">${a.critical_count} critical</span>` : ''}
            </td>
            <td>${fmtDate(a.created_date)}</td>
            <td class="text-nowrap">
                <button class="btn btn-sm btn-outline-secondary-soft" onclick="viewAsset(${a.id})" title="View details" aria-label="View asset details"><i class="fas fa-eye"></i></button>
                <button class="btn btn-sm btn-outline-primary" onclick="openAssetModal(${a.id})" title="Edit" aria-label="Edit asset"><i class="fas fa-edit"></i></button>
                <button class="btn btn-sm btn-outline-danger" onclick="openDeleteAsset(${a.id})" title="Delete" aria-label="Delete asset"><i class="fas fa-trash"></i></button>
            </td>
        </tr>`).join('');
}

async function openAssetModal(id) {
    document.getElementById('assetForm').reset();
    document.getElementById('asset-id').value = '';
    document.getElementById('asset-created-note').textContent = '';
    showFormError('asset-form-error', '');
    document.getElementById('assetModalTitle').textContent = 'Add Asset';

    if (id) {
        const res = await api(`/api/assets/${id}`);
        if (!res.ok) return toast(res.data.error || 'Could not load asset.', 'danger');
        const a = res.data;
        document.getElementById('assetModalTitle').textContent = 'Edit Asset';
        document.getElementById('asset-id').value = a.id;
        document.getElementById('asset-name').value = a.name;
        document.getElementById('asset-ip').value = a.ip_address || '';
        document.getElementById('asset-type').value = a.asset_type;
        document.getElementById('asset-os').value = a.operating_system || '';
        document.getElementById('asset-owner').value = a.owner || '';
        document.getElementById('asset-description').value = a.description || '';
        document.getElementById('asset-created-note').textContent = `${assetCode(a.id)} · created ${fmtDate(a.created_date)}`;
    }
    afterHidden('assetDetailModal', () => modal('assetModal').show());
}

async function saveAsset() {
    const id = document.getElementById('asset-id').value;
    const data = {
        name: document.getElementById('asset-name').value.trim(),
        ip_address: document.getElementById('asset-ip').value.trim(),
        asset_type: document.getElementById('asset-type').value,
        operating_system: document.getElementById('asset-os').value.trim(),
        owner: document.getElementById('asset-owner').value.trim(),
        description: document.getElementById('asset-description').value.trim(),
    };
    if (!data.name) return showFormError('asset-form-error', 'Asset name is required.');

    const res = await api(id ? `/api/assets/${id}` : '/api/assets', jsonOptions(id ? 'PUT' : 'POST', data));
    if (!res.ok) return showFormError('asset-form-error', res.data.error || 'Could not save asset.');

    modal('assetModal').hide();
    toast(id ? 'Asset updated.' : 'Asset added.');
    refreshAll();
}

async function viewAsset(id) {
    const res = await api(`/api/assets/${id}`);
    if (!res.ok) return toast(res.data.error || 'Could not load asset.', 'danger');
    const a = res.data;
    assetDetailId = a.id;

    document.getElementById('detail-title').textContent = `${a.name} · ${assetCode(a.id)}`;
    const sev = a.severity_counts;
    const rows = a.vulnerabilities.map(v => `
        <tr>
            <td>${v.id}</td>
            <td><strong>${esc(v.title)}</strong></td>
            <td><span class="badge bg-${getSeverityColor(v.severity)}">${esc(v.severity)}</span></td>
            <td>${v.cvss_score || '-'}</td>
            <td><span class="badge bg-${getStatusColor(v.status)}">${esc(v.status)}</span></td>
            <td>${fmtDate(v.discovered_date)}</td>
        </tr>`).join('');

    document.getElementById('detail-body').innerHTML = `
        <div class="detail-grid">
            <div><span>Asset ID</span><strong>${assetCode(a.id)}</strong></div>
            <div><span>IP Address</span><strong>${esc(a.ip_address) || '-'}</strong></div>
            <div><span>Type</span><strong>${esc(a.asset_type)}</strong></div>
            <div><span>Operating System</span><strong>${esc(a.operating_system) || '-'}</strong></div>
            <div><span>Owner</span><strong>${esc(a.owner) || '-'}</strong></div>
            <div><span>Created</span><strong>${fmtDate(a.created_date)}</strong></div>
        </div>
        <div class="detail-desc"><span>Description</span><p>${esc(a.description) || '<em class="text-muted">No description.</em>'}</p></div>
        <div class="d-flex flex-wrap align-items-center gap-2 my-3">
            <h6 class="m-0 me-2 detail-heading">Vulnerabilities <span class="count-pill">${a.vuln_count}</span></h6>
            ${['Critical', 'High', 'Medium', 'Low'].map(s => `<span class="badge bg-${getSeverityColor(s)}">${sev[s]} ${s}</span>`).join('')}
            <span class="ms-auto d-flex gap-2">
                <button class="btn btn-sm-text btn-outline-primary" onclick="addVulnForAsset(${a.id})"><i class="fas fa-plus me-1"></i>Add vulnerability</button>
                ${a.vuln_count ? `<button class="btn btn-sm-text btn-outline-primary" onclick="showAssetOnDashboard(${a.id})"><i class="fas fa-filter me-1"></i>Filter dashboard</button>` : ''}
            </span>
        </div>
        <div class="table-responsive detail-table">
            <table class="table table-hover">
                <thead><tr><th>ID</th><th>Title</th><th>Severity</th><th>CVSS</th><th>Status</th><th>Discovered</th></tr></thead>
                <tbody>${rows || '<tr><td colspan="6" class="text-center">No vulnerabilities linked to this asset.</td></tr>'}</tbody>
            </table>
        </div>`;
    document.getElementById('detail-edit-btn').onclick = () => openAssetModal(a.id);
    modal('assetDetailModal').show();
}

function addVulnForAsset(assetId) {
    afterHidden('assetDetailModal', () => openVulnModal(assetId));
}

function showAssetOnDashboard(assetId) {
    afterHidden('assetDetailModal', () => {
        document.getElementById('filter-asset').value = String(assetId);
        if (location.hash !== '#dashboard') location.hash = '#dashboard'; else loadVulnerabilities();
        setTimeout(() => document.getElementById('vulnerabilities-table').closest('.card').scrollIntoView({ behavior: 'smooth' }), 150);
    });
}

function openDeleteAsset(id) {
    const asset = allAssets.find(a => a.id === id);
    if (!asset) return;

    const label = `${asset.name}${asset.ip_address ? ' (' + asset.ip_address + ')' : ''}`;
    document.getElementById('delete-asset-text').innerHTML =
        `Are you sure you want to delete <strong>${esc(label)}</strong>? This cannot be undone.`;

    const box = document.getElementById('delete-reassign');
    const select = document.getElementById('delete-reassign-select');
    if (asset.vuln_count > 0) {
        const n = asset.vuln_count;
        document.getElementById('delete-reassign-warning').textContent =
            `This asset has ${n} associated vulnerabilit${n === 1 ? 'y' : 'ies'}. They will not be deleted.`;
        select.innerHTML = allAssets.filter(a => a.id !== id)
            .map(a => `<option value="${a.id}">Reassign to ${esc(a.name)}${a.ip_address ? ' (' + esc(a.ip_address) + ')' : ''}</option>`).join('') +
            '<option value="none">Leave them unassigned</option>';
        box.classList.remove('d-none');
    } else {
        select.innerHTML = '';
        box.classList.add('d-none');
    }

    document.getElementById('delete-asset-confirm').onclick = async () => {
        const params = asset.vuln_count > 0 ? `?reassign_to=${encodeURIComponent(select.value)}` : '';
        const res = await api(`/api/assets/${id}${params}`, { method: 'DELETE' });
        modal('deleteAssetModal').hide();
        if (!res.ok) {
            toast(res.data.error || 'Could not delete asset.', 'danger');
        } else {
            toast(res.data.reassigned ? `Asset deleted; ${res.data.reassigned} vulnerabilities moved.` : 'Asset deleted.');
        }
        refreshAll();
    };
    modal('deleteAssetModal').show();
}

/* ---------------------------------------------------------------- CSV import */
function showImportResult(title, result) {
    const section = (label, items, cls) => items && items.length ? `
        <h6 class="mt-3 detail-heading">${label} (${items.length})</h6>
        <ul class="import-list ${cls}">
            ${items.slice(0, 50).map(i => `<li><strong>Row ${i.row}:</strong> ${esc(i.error)}</li>`).join('')}
            ${items.length > 50 ? `<li>…and ${items.length - 50} more</li>` : ''}
        </ul>` : '';
    document.getElementById('import-result-title').textContent = title;
    document.getElementById('import-result-body').innerHTML =
        `<p class="mb-0"><strong>${esc(result.message)}</strong></p>` +
        section('Duplicates skipped', result.duplicates, 'warn') +
        section('Invalid rows skipped', result.errors, 'err');
    modal('importResultModal').show();
}

async function uploadCsv(inputId, url, title) {
    const input = document.getElementById(inputId);
    const file = input.files[0];
    if (!file) return;

    const formData = new FormData();
    formData.append('file', file);
    const res = await api(url, { method: 'POST', body: formData });
    input.value = ''; // allow re-selecting the same file

    if (!res.ok) return toast('Import failed: ' + (res.data.error || 'unknown error'), 'danger');
    const r = res.data;
    if ((r.errors && r.errors.length) || (r.duplicates && r.duplicates.length)) {
        showImportResult(title, r);
    } else {
        toast(r.message);
    }
    refreshAll();
}

function importCSV() { return uploadCsv('csv-file-input', '/api/import-csv', 'Vulnerability import results'); }
function importAssetsCSV() { return uploadCsv('asset-csv-input', '/api/assets/import-csv', 'Asset import results'); }

/* ---------------------------------------------------------------- startup */
window.addEventListener('hashchange', route);
document.addEventListener('visibilitychange', () => { if (!document.hidden) refreshAll(); });
route();
