let chatHistory = [];
let currentUser = null;
let lastResults = { columns: [], rows: [] };
let currentSiem = localStorage.getItem('soc_siem') || 'splunk';

// ── TIME PICKER STATE ──
let timeState = { earliest: '0', latest: 'now', label: 'All time' };

// ── HISTORY (localStorage) ──
const HIST_KEY = 'pentagon_spl_history';
function loadHistory() { try { return JSON.parse(localStorage.getItem(HIST_KEY) || '[]'); } catch { return []; } }
function saveHistory(h) { localStorage.setItem(HIST_KEY, JSON.stringify(h.slice(0, 30))); }
function pushHistory(entry) {
  const h = loadHistory().filter(e => e.spl !== entry.spl);
  h.unshift(entry);
  saveHistory(h);
  renderHistory();
}
function clearHistory() { localStorage.removeItem(HIST_KEY); renderHistory(); }

function renderHistory() {
  const h = loadHistory();
  const strip = document.getElementById('histStrip');
  const items = document.getElementById('histItems');
  if (!h.length) { strip.style.display = 'none'; return; }
  strip.style.display = 'flex';
  items.innerHTML = h.map((e, i) => `
    <button class="hist-item" onclick="restoreHistory(${i})" title="${escapeHtml(e.spl)}">
      <span class="hist-item-spl">${escapeHtml(e.spl.substring(0, 60))}${e.spl.length > 60 ? '…' : ''}</span>
      <span class="hist-item-time">${e.ago}</span>
    </button>`).join('');
}

function restoreHistory(i) {
  const h = loadHistory();
  const e = h[i];
  if (!e) return;
  document.getElementById('splunkCode').value = e.spl;
  autoGrow(document.getElementById('splunkCode'));
  if (e.nl) document.getElementById('nlInput').value = e.nl;
  show('queryResults');
  // Set time if saved
  if (e.earliest) setTime(e.earliest, e.latest, e.label, false);
}

// ── TIME PICKER ──
// Tracks last *applied* custom values so half-edits are discarded on re-open
let lastAppliedCustom = { from: '', to: '' };

function toggleTimePicker() {
  const dd = document.getElementById('tpDropdown');
  const opening = dd.classList.contains('hidden');
  dd.classList.toggle('hidden');
  if (opening) {
    // Restore last applied custom values (discard any half-typed edits)
    document.getElementById('tpFrom').value = lastAppliedCustom.from;
    document.getElementById('tpTo').value   = lastAppliedCustom.to;
    // Highlight active preset
    document.querySelectorAll('.tp-preset').forEach(b => {
      b.classList.toggle('active', b.textContent.trim() === timeState.label);
    });
    setTimeout(() => {
      document.addEventListener('click', closeTpOnOutside, { once: true });
    }, 0);
  }
}
function closeTpOnOutside(e) {
  const wrap = document.getElementById('tpWrap');
  if (!wrap.contains(e.target)) {
    // Discard unapplied edits — restore last applied values
    document.getElementById('tpFrom').value = lastAppliedCustom.from;
    document.getElementById('tpTo').value   = lastAppliedCustom.to;
    document.getElementById('tpDropdown').classList.add('hidden');
  } else {
    document.addEventListener('click', closeTpOnOutside, { once: true });
  }
}
function setTime(earliest, latest, label, closeDropdown = true) {
  timeState = { earliest, latest, label };
  document.getElementById('tpLabel').textContent = label;
  document.querySelectorAll('.tp-preset').forEach(b => {
    b.classList.toggle('active', b.textContent.trim() === label);
  });
  if (closeDropdown) document.getElementById('tpDropdown').classList.add('hidden');
}
function applyCustomTime() {
  const from = document.getElementById('tpFrom').value;
  const to   = document.getElementById('tpTo').value;
  if (!from || !to) { toast('From və To tarixini seçin'); return; }
  // Save as last applied — only here, not on half-edits
  lastAppliedCustom = { from, to };
  const earliest = Math.floor(new Date(from).getTime() / 1000).toString();
  const latest   = Math.floor(new Date(to).getTime()   / 1000).toString();
  const label    = `${from.replace('T',' ')} → ${to.replace('T',' ')}`;
  setTime(earliest, latest, label);
}

// ── TAB NAVIGATION ──
document.querySelectorAll('.nav-item').forEach(btn => {
  btn.addEventListener('click', () => {
    const tab = btn.dataset.tab;
    document.querySelectorAll('.nav-item').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    btn.classList.add('active');
    document.getElementById('tab-' + tab).classList.add('active');
    const titles = {
      query:     ['Natural Language Query', 'Translate natural language into SIEM queries and run them live'],
      chat:      ['AI SOC Chat', 'Conversational threat hunting and security assistance'],
      deploy:    ['Deploy Agent', 'Build a Windows triage agent pre-configured for this server'],
      epdash:    ['Endpoint Reports', 'Live dashboard of triage reports received from deployed agents'],
      domain:    ['Domain Intelligence', 'DNS records, SPF, DMARC, SSL certificate and WHOIS analysis'],
      mail:      ['Mail Security Analysis', 'Validate email authenticity, MX, SPF, DMARC and spoofing risk'],
      ioc:       ['IOC Search', 'Search global threat intelligence — IP, domain, URL, hash'],
      insider:   ['Insider Threat Detection', 'Analyze employee behavior for signs of insider threat based on SIEM data'],
      settings:  ['Settings', 'API keys, appearance and platform configuration'],
    };
    document.getElementById('pageTitle').textContent = titles[tab]?.[0] ?? tab;
    document.getElementById('pageSub').textContent   = titles[tab]?.[1] ?? '';
    localStorage.setItem('soc_active_tab', tab);
    if (tab === 'deploy')   initDeployTab();
    if (tab === 'epdash')   startEpPoll();
    else                    stopEpPoll();
    if (tab === 'settings') loadSettings();
    if (tab === 'insider')  loadInsider();
  });
});

// Restore last active tab on load
(function restoreTab() {
  const saved = localStorage.getItem('soc_active_tab');
  if (saved) {
    const btn = document.querySelector(`.nav-item[data-tab="${saved}"]`);
    if (btn) { btn.click(); return; }
  }
  // default: activate first nav-item
  const first = document.querySelector('.nav-item[data-tab]');
  if (first) first.click();
})();

// ── NL QUERY ──
function setQuery(text) {
  document.getElementById('nlInput').value = text;
  document.getElementById('nlInput').focus();
}

document.getElementById('nlInput').addEventListener('keydown', e => {
  if (e.key === 'Enter') runQuery();
});

// Auto-grow textarea
function autoGrow(el) {
  el.style.height = 'auto';
  el.style.height = Math.min(el.scrollHeight, 200) + 'px';
}

// NL → AI → SIEM Query
async function runQuery() {
  const q = document.getElementById('nlInput').value.trim();
  if (!q) return;
  const btn = document.getElementById('runQueryBtn');
  btn.disabled = true;
  setLoadingText('AI sorğu yazır...');
  show('queryLoading');
  hide('queryResults');
  try {
    const res = await post('/api/nl-to-splunk', {
      query: q,
      siem:  currentSiem,
      earliest_time: timeState.earliest,
      latest_time:   timeState.latest
    });
    renderQueryResults(res);
    // Save to history
    pushHistory({
      nl:  q,
      spl: res.spl,
      earliest: timeState.earliest,
      latest:   timeState.latest,
      label:    timeState.label,
      ago: 'just now'
    });
  } catch (e) {
    toast('Xəta: ' + e.message);
  } finally {
    hide('queryLoading');
    btn.disabled = false;
  }
}

// Direct SPL run (edited textarea)
async function runSpl() {
  if (currentSiem !== 'splunk') {
    toast(`${SIEM_LABELS[currentSiem] || currentSiem} is not connected — query only mode`);
    return;
  }
  const spl = document.getElementById('splunkCode').value.trim();
  if (!spl) return;
  const btn = document.getElementById('runSplBtn');
  btn.disabled = true;
  setLoadingText('SIEM-də işlədilir...');
  show('queryLoading');
  document.getElementById('resultsBlock').classList.add('loading-overlay');
  try {
    const res = await post('/api/run-spl', {
      spl,
      siem: currentSiem,
      earliest_time: timeState.earliest,
      latest_time:   timeState.latest
    });
    renderQueryResults(res);
    pushHistory({
      nl:  document.getElementById('nlInput').value.trim(),
      spl,
      earliest: timeState.earliest,
      latest:   timeState.latest,
      label:    timeState.label,
      ago: 'just now'
    });
  } catch (e) {
    toast('Xəta: ' + e.message);
  } finally {
    hide('queryLoading');
    document.getElementById('resultsBlock').classList.remove('loading-overlay');
    btn.disabled = false;
  }
}

// Enter → run, Shift+Enter → newline
document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('splunkCode')?.addEventListener('keydown', e => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); runSpl(); }
  });
  renderHistory();
  checkAuth();
});

function copySpl() {
  navigator.clipboard.writeText(document.getElementById('splunkCode').value)
    .then(() => toast('Kopyalandı'));
}

function setLoadingText(text) {
  document.getElementById('queryLoadingText').textContent = text;
}

function renderQueryResults(res) {
  lastSpl = res.spl || '';
  lastResults = { columns: res.columns || [], rows: res.rows || [] };

  // Update query language label + run button visibility
  if (res.query_lang) {
    const lbl = document.getElementById('siemQueryLabel');
    if (lbl) lbl.textContent = res.query_lang + ' Query';
  }
  const canRun = res.can_run !== false && currentSiem === 'splunk';
  const runBtn = document.getElementById('runSplBtn');
  if (runBtn) runBtn.style.display = canRun ? '' : 'none';
  const noConn = document.getElementById('siemNoConn');
  if (noConn) noConn.classList.toggle('hidden', canRun);

  // Query block
  const splEl = document.getElementById('splunkCode');
  splEl.value = res.spl || '';
  autoGrow(splEl);

  // Explanation
  const exEl = document.getElementById('queryExplanation');
  exEl.textContent = res.explanation || '';

  // Notes
  const notesEl = document.getElementById('queryNotes');
  if (res.notes) {
    notesEl.textContent = res.notes;
    notesEl.classList.remove('hidden');
  } else {
    notesEl.classList.add('hidden');
  }

  // MITRE tags
  const mitreEl = document.getElementById('mitreTags');
  mitreEl.innerHTML = '';
  (res.mitre_techniques || []).forEach(t => {
    const span = document.createElement('span');
    span.className = 'mitre-tag';
    span.textContent = t;
    mitreEl.appendChild(span);
  });

  // Results meta
  const dur = res.duration_ms ? `${res.duration_ms}ms` : '';
  document.getElementById('resultsMeta').textContent =
    res.exec_error ? '' : `${res.total} nəticə  ·  ${dur}  ·  All time`;

  // Truncation warning
  res.truncated ? show('truncWarning') : hide('truncWarning');

  // Mode badge on results header
  const modeBadge = document.getElementById('resultsModeTag');
  if (modeBadge) {
    modeBadge.textContent = res.is_raw ? 'RAW' : 'TABLE';
    modeBadge.className = 'mode-badge ' + (res.is_raw ? 'raw' : 'table');
  }

  // Error state
  if (res.exec_error) {
    document.getElementById('execErrorText').textContent = res.exec_error;
    show('execError');
    hide('emptyState');
    hide('rawWrap');
    hide('tableWrap');
  } else if (!res.rows || res.rows.length === 0) {
    hide('execError');
    show('emptyState');
    hide('rawWrap');
    hide('tableWrap');
  } else if (res.is_raw) {
    hide('execError');
    hide('emptyState');
    hide('tableWrap');
    show('rawWrap');
    renderRaw(res.rows);
  } else {
    hide('execError');
    hide('emptyState');
    hide('rawWrap');
    show('tableWrap');
    renderTable(res.columns, res.rows);
  }

  show('queryResults');
}

// Fields always shown in the header strip (not repeated in field table)
const META_FIELDS = new Set(['_time','host','source','sourcetype','_raw',
  'index','linecount','punct','splunk_server','timestartpos','timeendpos',
  'eventtype','tag','_indextime','_cd','_si','_serial','_sourcetype']);

function renderRaw(rows) {
  const el = document.getElementById('rawWrap');
  el.innerHTML = rows.map((row, i) => {
    const time    = fmtTime(row['_time'] || '');
    const host    = row['host'] || '';
    const source  = row['source'] || '';
    const srctype = row['sourcetype'] || '';
    const rawText = row['_raw'] || '';

    // Extracted fields: everything except meta/internal
    const fields = Object.entries(row).filter(([k]) => !META_FIELDS.has(k));

    // Highlighted raw text
    const rawHl = hlRaw(escapeHtml(rawText));

    // Field rows for expanded view
    const fieldRows = fields.map(([k, v]) =>
      `<div class="ev-field-row">
         <span class="ev-field-key">${escapeHtml(k)}</span>
         <span class="ev-field-val">${escapeHtml(String(v))}</span>
       </div>`
    ).join('');

    // Preview: first 200 chars of raw
    const preview = rawHl.substring(0, 400);

    return `<div class="ev-wrap" id="ev-${i}">
      <div class="ev-header" onclick="toggleEv(${i})">
        <span class="ev-arrow" id="ea-${i}">▶</span>
        <span class="ev-time">${time}</span>
        <span class="ev-host">${escapeHtml(host)}</span>
        <span class="ev-src">${escapeHtml(source)}</span>
        <span class="ev-stype">${escapeHtml(srctype)}</span>
      </div>
      <div class="ev-preview">${preview}${rawText.length > 200 ? '<span class="ev-more">…</span>' : ''}</div>
      <div class="ev-expanded hidden" id="ex-${i}">
        <div class="ev-raw-block">${rawHl}</div>
        ${fields.length ? `<div class="ev-fields">
          <div class="ev-fields-title">Extracted Fields (${fields.length})</div>
          ${fieldRows}
        </div>` : ''}
      </div>
    </div>`;
  }).join('');
}

function toggleEv(i) {
  const ex  = document.getElementById(`ex-${i}`);
  const arr = document.getElementById(`ea-${i}`);
  const open = ex.classList.contains('hidden');
  ex.classList.toggle('hidden', !open);
  arr.textContent = open ? '▼' : '▶';
  // Also hide preview when expanded
  const ev = document.getElementById(`ev-${i}`);
  ev.querySelector('.ev-preview').classList.toggle('hidden', open);
}

function fmtTime(t) {
  if (!t) return '';
  // Convert ISO or splunk time to readable
  try {
    const d = new Date(t);
    if (isNaN(d)) return t;
    return d.toISOString().replace('T', ' ').replace(/\.\d+Z$/, '').replace('Z', '');
  } catch { return t; }
}

function hlRaw(s) {
  return s
    // key=value pairs
    .replace(/\b([A-Za-z_][A-Za-z0-9_]*)=(&quot;[^&]*?&quot;|[^\s,\]]+)/g,
      '<span class="hl-key">$1</span>=<span class="hl-val">$2</span>')
    // error/warn words
    .replace(/\b(ERROR|WARN|WARNING|FATAL|CRITICAL|FAILED?|DENIED|BLOCKED)\b/g,
      '<span class="hl-bad">$1</span>')
    // success words
    .replace(/\b(SUCCESS|INFO|OK|ALLOWED|COMPLETED)\b/g,
      '<span class="hl-good">$1</span>')
    // timestamps in raw text
    .replace(/\d{2}[\/\-]\w+[\/\-]\d{4}(?::\d{2}:\d{2}:\d{2})?/g,
      '<span class="hl-ts">$&</span>');
}

function renderTable(columns, rows) {
  // Header
  const thead = document.getElementById('tableHead');
  thead.innerHTML = '<tr>' + columns.map(c =>
    `<th>${escapeHtml(c)}</th>`
  ).join('') + '</tr>';

  // Body
  const tbody = document.getElementById('tableBody');
  tbody.innerHTML = rows.map((row, i) =>
    '<tr class="' + (i % 2 === 0 ? 'row-even' : 'row-odd') + '">' +
    columns.map(c => `<td>${escapeHtml(String(row[c] ?? ''))}</td>`).join('') +
    '</tr>'
  ).join('');
}

function exportCSV() {
  const { columns, rows } = lastResults;
  if (!columns.length) return;
  const lines = [columns.join(',')];
  rows.forEach(r => lines.push(columns.map(c => `"${String(r[c]??'').replace(/"/g,'""')}"`).join(',')));
  const blob = new Blob([lines.join('\n')], { type: 'text/csv' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'splunk_results.csv';
  a.click();
}

function copyEl(id) {
  const el = document.getElementById(id);
  const text = el.value !== undefined ? el.value : el.textContent;
  navigator.clipboard.writeText(text).then(() => toast('Kopyalandı'));
}

// ── CHAT ──
function quickChat(msg) {
  document.getElementById('chatInput').value = msg;
  sendChat();
}

async function sendChat() {
  const input = document.getElementById('chatInput');
  const msg = input.value.trim();
  if (!msg) return;
  input.value = '';
  appendChat('user', msg);
  chatHistory.push({ role: 'user', content: msg });
  const typing = appendChat('assistant', '...');
  try {
    const res = await post('/api/chat', { message: msg, history: chatHistory.slice(0,-1) });
    typing.remove();
    const el = appendChat('assistant', res.response);
    renderMarkdown(el.querySelector('.msg-bub'));
    chatHistory.push({ role: 'assistant', content: res.response });
  } catch (e) {
    typing.remove();
    appendChat('assistant', 'Xəta: ' + e.message);
  }
}

function appendChat(role, text) {
  const c = document.getElementById('chatMessages');
  const d = document.createElement('div');
  d.className = 'msg ' + role;
  d.innerHTML = `<div class="msg-av">${role==='assistant'?'AI':'SİZ'}</div><div class="msg-bub">${escapeHtml(text)}</div>`;
  c.appendChild(d);
  c.scrollTop = c.scrollHeight;
  return d;
}

function renderMarkdown(el) {
  let h = el.innerHTML;
  h = h.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
  h = h.replace(/^### (.+)$/gm, '<h3>$1</h3>');
  h = h.replace(/^## (.+)$/gm, '<h2>$1</h2>');
  h = h.replace(/^# (.+)$/gm, '<h1>$1</h1>');
  h = h.replace(/```[\w]*\n?([\s\S]*?)```/g, '<pre>$1</pre>');
  h = h.replace(/`([^`]+)`/g, '<code>$1</code>');
  h = h.replace(/^[•\-\*] (.+)$/gm, '<li>$1</li>');
  h = h.replace(/(<li>[\s\S]*?<\/li>)+/g, m => `<ul>${m}</ul>`);
  h = h.replace(/^\d+\. (.+)$/gm, '<li>$1</li>');
  h = h.replace(/\n\n/g, '</p><p>');
  h = h.replace(/\n/g, '<br>');
  el.innerHTML = '<p>' + h + '</p>';
}

// ── UTILS ──
function show(id) { document.getElementById(id)?.classList.remove('hidden'); }
function hide(id) { document.getElementById(id)?.classList.add('hidden'); }

async function get(url) {
  const r = await fetch(url);
  if (!r.ok) throw new Error(await r.text());
  return r.json();
}

async function post(url, body) {
  const r = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });
  if (!r.ok) throw new Error(await r.text());
  return r.json();
}

function escapeHtml(s) {
  return String(s)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// ── AUTH ──────────────────────────────────────────────────────
async function checkAuth() {
  try {
    const r = await get('/api/me');
    _setUser(r);
    document.getElementById('loginOverlay').classList.add('hidden');
  } catch(_) {
    document.getElementById('loginOverlay').classList.remove('hidden');
  }
}

function _setUser(u) {
  currentUser = u;
  document.getElementById('topbarUsername').textContent = u.username;
  applyUserRole(u.role);
}

function applyUserRole(role) {
  const isAdmin = role === 'admin';
  document.getElementById('apiKeysSection').style.display = isAdmin ? '' : 'none';
  document.getElementById('adminSection').style.display   = isAdmin ? '' : 'none';
}

async function doLogin() {
  const username = document.getElementById('loginUser').value.trim();
  const password = document.getElementById('loginPass').value;
  const errEl    = document.getElementById('loginError');
  const btn      = document.getElementById('loginBtn');
  if (!username || !password) {
    errEl.textContent = 'Username and password required';
    errEl.classList.remove('hidden'); return;
  }
  btn.disabled = true; btn.textContent = 'Signing in…';
  try {
    const r = await post('/api/login', { username, password });
    _setUser(r);
    document.getElementById('loginOverlay').classList.add('hidden');
    document.getElementById('loginPass').value = '';
    errEl.classList.add('hidden');
  } catch(_) {
    errEl.textContent = 'Invalid username or password';
    errEl.classList.remove('hidden');
  }
  btn.disabled = false; btn.textContent = 'Sign In';
}

async function doLogout() {
  await post('/api/logout', {}).catch(() => {});
  currentUser = null;
  document.getElementById('topbarUsername').textContent = '';
  document.getElementById('loginUser').value = '';
  document.getElementById('loginPass').value = '';
  document.getElementById('loginError').classList.add('hidden');
  document.getElementById('loginOverlay').classList.remove('hidden');
}

// ── USER MANAGEMENT ──────────────────────────────────────────
async function loadAdminUsers() {
  try {
    const d = await get('/api/admin/users');
    renderAdminUserList(d.data || []);
  } catch(_) {}
}

function renderAdminUserList(users) {
  const el = document.getElementById('adminUserList');
  if (!el) return;
  if (!users.length) { el.innerHTML = '<div class="ti-empty" style="padding:16px">No users</div>'; return; }
  el.innerHTML = users.map(u => `
    <div class="admin-user-row">
      <div class="admin-user-avatar">${escapeHtml(u.username[0].toUpperCase())}</div>
      <span class="admin-user-name">${escapeHtml(u.username)}</span>
      <span class="admin-user-role ${u.role}">${u.role}</span>
      <button class="admin-user-pw" onclick="adminOpenPwModal('${escapeHtml(u.username)}')">
        <svg width="11" height="11" viewBox="0 0 20 20" fill="currentColor" style="margin-right:3px"><path fill-rule="evenodd" d="M5 9V7a5 5 0 0110 0v2a2 2 0 012 2v5a2 2 0 01-2 2H5a2 2 0 01-2-2v-5a2 2 0 012-2zm8-2v2H7V7a3 3 0 016 0z" clip-rule="evenodd"/></svg>Password
      </button>
      ${u.username !== 'admin'
        ? `<button class="admin-user-del" onclick="adminDeleteUser('${escapeHtml(u.username)}')">Delete</button>`
        : '<span style="width:52px"></span>'}
    </div>`).join('');
}

async function adminAddUser() {
  const username = document.getElementById('newUserName').value.trim();
  const password = document.getElementById('newUserPass').value;
  const role     = document.getElementById('newUserRole').value;
  if (!username || !password) { showToast('Username and password required'); return; }
  try {
    await post('/api/admin/users', { username, password, role });
    showToast('User created: ' + username);
    document.getElementById('newUserName').value = '';
    document.getElementById('newUserPass').value = '';
    loadAdminUsers();
  } catch(e) { showToast('Error: ' + e.message); }
}

async function adminDeleteUser(username) {
  if (!confirm(`Delete user "${username}"?`)) return;
  try {
    const r = await fetch('/api/admin/users/' + encodeURIComponent(username), { method: 'DELETE' });
    if (!r.ok) throw new Error(await r.text());
    showToast('User deleted');
    loadAdminUsers();
  } catch(e) { showToast('Error: ' + e.message); }
}

let _pwChangeTarget = null;
function adminOpenPwModal(username) {
  _pwChangeTarget = username;
  document.getElementById('pwChangeTarget').textContent = 'User: ' + username;
  document.getElementById('pwChangeNew').value     = '';
  document.getElementById('pwChangeConfirm').value = '';
  document.getElementById('pwChangeModal').classList.remove('hidden');
  setTimeout(() => document.getElementById('pwChangeNew').focus(), 50);
}

async function adminConfirmPwChange() {
  const pw1 = document.getElementById('pwChangeNew').value;
  const pw2 = document.getElementById('pwChangeConfirm').value;
  if (!pw1 || pw1 !== pw2) { showToast('Passwords do not match'); return; }
  if (pw1.length < 4) { showToast('Min 4 characters'); return; }
  try {
    await post('/api/admin/users/' + encodeURIComponent(_pwChangeTarget) + '/password', { password: pw1 });
    showToast('Password changed for ' + _pwChangeTarget);
    document.getElementById('pwChangeModal').classList.add('hidden');
    _pwChangeTarget = null;
  } catch(e) { showToast('Error: ' + e.message); }
}

function toast(msg) {
  const el = document.getElementById('toast');
  el.textContent = msg;
  el.classList.remove('hidden');
  setTimeout(() => el.classList.add('hidden'), 3000);
}

// ── INIT ──
loadAlerts();

// ══════════════════════════════════════════════════════════
// DEPLOY AGENT
// ══════════════════════════════════════════════════════════
let _deployInit = false;

async function initDeployTab() {
  if (_deployInit) return;
  _deployInit = true;
  try {
    const d = await get('/api/agent/info');
    if (d.success) {
      document.getElementById('agentHost').placeholder = d.server_ip;
      document.getElementById('agentHost').value       = d.server_ip;
      document.getElementById('agentPort').value       = d.server_port;
      document.getElementById('dmCompiler').textContent =
        d.compiler_available ? '✓ ' + d.compiler.split('/').pop() : '✗ not found';
      document.getElementById('dmCompiler').style.color =
        d.compiler_available ? '#86efac' : '#f87171';
    }
  } catch (e) { /* ignore */ }
}

async function buildAgent() {
  const host = document.getElementById('agentHost').value.trim() ||
               document.getElementById('agentHost').placeholder;
  const port = parseInt(document.getElementById('agentPort').value) || 5000;
  const btn  = document.getElementById('btnBuild');
  const lbl  = document.getElementById('btnBuildLabel');
  const errEl = document.getElementById('buildError');
  const spinI = document.getElementById('buildSpinIcon');
  const dlI   = document.getElementById('buildDlIcon');

  btn.disabled = true;
  btn.classList.add('building');
  lbl.textContent = 'Compiling…';
  spinI.style.display = '';
  spinI.classList.add('spin');
  dlI.style.display = 'none';
  errEl.classList.add('hidden');

  try {
    const resp = await fetch('/api/agent/build', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ host, port }),
    });

    if (!resp.ok) {
      const j = await resp.json().catch(() => ({}));
      const msg = j.error || 'Build failed';
      const detail = j.stderr ? '\n\n' + j.stderr : '';
      errEl.textContent = msg + detail;
      errEl.classList.remove('hidden');
      return;
    }

    // Trigger browser download
    const blob = await resp.blob();
    const fname = `soc_agent_${host.replace(/\./g,'_')}_${port}.exe`;
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = fname;
    document.body.appendChild(a); a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    toast(`Downloaded ${fname}`);
  } catch (e) {
    errEl.textContent = String(e);
    errEl.classList.remove('hidden');
  } finally {
    btn.disabled = false;
    btn.classList.remove('building');
    lbl.textContent = 'Build & Download agent.exe';
    spinI.style.display = 'none';
    spinI.classList.remove('spin');
    dlI.style.display = '';
  }
}

/* loadReports / viewReport removed — dashboard uses openEpDrawer instead */

// ══════════════════════════════════════════════════════════
// ENDPOINT REPORTS DASHBOARD
// ══════════════════════════════════════════════════════════
let _epPollTimer = null;
let _epReports   = [];

async function loadEpDash() {
  try {
    const d = await get('/api/reports');
    if (!d.success) return;
    _epReports = d.data || [];
    renderEpDash();
    updateEpBadge();
  } catch (e) { /* network down */ }
}

function updateEpBadge() {
  const badge = document.getElementById('epBadge');
  if (!badge) return;
  const n = _epReports.length;
  badge.textContent = n;
  badge.style.display = n > 0 ? '' : 'none';
}

function renderEpDash() {
  const reports = _epReports;
  const grid    = document.getElementById('epCardGrid');
  const empty   = document.getElementById('epEmpty');
  if (!grid) return;

  // Summary stats
  const hosts   = new Set(reports.map(r => r.host || r.remote_addr));
  const high    = reports.filter(r => r.risk === 'HIGH').length;
  const med     = reports.filter(r => r.risk === 'MEDIUM').length;
  const clean   = reports.filter(r => r.risk === 'CLEAN').length;

  _setText('epStatTotal',     reports.length);
  _setText('epStatEndpoints', hosts.size);
  _setText('epStatHigh',      high);
  _setText('epStatMed',       med);
  _setText('epStatClean',     clean);

  if (!reports.length) {
    if (empty) empty.style.display = '';
    return;
  }
  if (empty) empty.style.display = 'none';

  grid.innerHTML = reports.map((r, i) => {
    const c  = r.counts || {};
    const os = r.os  ? r.os.replace(/\(build \d+\)/, '').trim() : '—';
    const dt = r.dt  || r.received_at || '—';
    const chips = [
      { key: 'REG',  val: c.registry ?? 0, hi: c.registry_high ?? 0 },
      { key: 'NET',  val: c.ports    ?? 0, hi: 0 },
      { key: 'SYS',  val: c.sys32    ?? 0, hi: 0 },
      { key: 'SVC',  val: c.services ?? 0, hi: c.svc_running ?? 0 },
      { key: 'TASK', val: c.tasks    ?? 0, hi: 0 },
    ].map(ch => {
      const hit = ch.val > 0;
      const flagged = ch.hi > 0;
      return `<span class="ep-count-chip${flagged ? ' has-hits' : hit ? ' has-info' : ''}">
        <span class="ckey">${ch.key}</span>
        <span class="cval">${ch.val}</span>
        ${flagged ? '<span class="chip-flag">⚑</span>' : ''}
      </span>`;
    }).join('');

    return `
    <div class="ep-card risk-${r.risk}" onclick="openEpDrawer('${r.id}')">
      <div class="ep-card-top">
        <div class="ep-card-hostname" title="${escapeHtml(r.host||'')}">${escapeHtml(r.host || r.remote_addr || '?')}</div>
        <span class="ep-risk-badge ${r.risk}">${r.risk}</span>
      </div>
      <div class="ep-card-meta">
        <span>👤 ${escapeHtml(r.user||'—')}</span>
        <span>🖥 ${escapeHtml(os)}</span><br>
        <span>🕐 ${escapeHtml(dt)}</span>
      </div>
      <div class="ep-card-counts">${chips}</div>
      <div class="ep-card-footer">
        <span class="ep-card-id">${r.id}</span>
        <span class="ep-card-time">${escapeHtml(r.received_at||'')}</span>
      </div>
    </div>`;
  }).join('');
}

function _setText(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}

async function openEpDrawer(id) {
  const meta = _epReports.find(x => x.id === id);
  if (!meta) return;

  // Header — show immediately
  document.getElementById('epDrawerHost').textContent =
    meta.host || meta.remote_addr || '?';
  document.getElementById('epDrawerMeta').textContent =
    [meta.os, `User: ${meta.user||'—'}`, meta.received_at, meta.remote_addr]
      .filter(Boolean).join('  •  ');

  const riskEl = document.getElementById('epDrawerRisk');
  riskEl.textContent  = meta.risk || '?';
  riskEl.className    = `ep-risk-badge ${meta.risk || 'UNKNOWN'}`;

  // Findings strip
  renderDrawerFindings(meta);

  const bodyEl = document.getElementById('epDrawerBody');
  bodyEl.textContent = 'Loading…';

  const drawer = document.getElementById('epDrawer');
  drawer.classList.remove('hidden');
  setTimeout(() => {
    document.addEventListener('click', _closeDrawerOutside, { once: true });
  }, 0);

  // Fetch full report text
  try {
    const d = await get('/api/reports/' + id);
    const text = d.data?.report || '(empty report)';
    bodyEl.innerHTML = colorizeReport(text);
    bodyEl.scrollTop = 0;
  } catch (e) {
    bodyEl.textContent = 'Failed to load report: ' + e.message;
  }
}

function renderDrawerFindings(meta) {
  const el = document.getElementById('epDrawerFindings');
  if (!el) return;
  const c = meta.counts || {};

  const chips = [
    { key: 'Registry',  val: c.registry || 0,  high: c.registry_high || 0,
      icon: '🔑', label: 'AUTORUN / IFEO / Winlogon' },
    { key: 'Sys32',     val: c.sys32    || 0,  high: 0,
      icon: '📁', label: 'Unusual files in System32' },
    { key: 'Services',  val: c.services || 0,  high: c.svc_running || 0,
      icon: '⚙️',  label: 'Non-standard services'    },
    { key: 'Tasks',     val: c.tasks    || 0,  high: 0,
      icon: '🗓',  label: 'Suspicious scheduled tasks'},
    { key: 'Ports',     val: c.ports    || 0,  high: 0,
      icon: '🌐', label: 'Open TCP/UDP ports'        },
  ];

  const html = chips.map(ch => {
    if (ch.val === 0) return `
      <div class="drf-chip clean" title="${ch.label}">
        <span class="drf-icon">${ch.icon}</span>
        <span class="drf-key">${ch.key}</span>
        <span class="drf-val">✓</span>
      </div>`;
    const cls = ch.high > 0 ? 'high' : 'info';
    return `
      <div class="drf-chip ${cls}" title="${ch.label}">
        <span class="drf-icon">${ch.icon}</span>
        <span class="drf-key">${ch.key}</span>
        <span class="drf-val">${ch.val}</span>
        ${ch.high > 0 ? `<span class="drf-flag">⚑ ${ch.high} HIGH</span>` : ''}
      </div>`;
  }).join('');

  el.innerHTML = html;
  el.classList.remove('hidden');
}

function colorizeReport(raw) {
  // Split into lines, wrap flagged lines with a highlight block
  const lines = escapeHtml(raw).split('\n');
  return lines.map(ln => {
    // Section headers — blue bold
    if (/^={3,}/.test(ln.trim())) {
      return `<span class="rl-section">${ln}</span>`;
    }
    // HIGH-risk autorun entries
    if (/\[AUTORUN-HIGH\]/.test(ln)) {
      return `<span class="rl-high">${
        ln.replace(/(\[AUTORUN-HIGH\])/g, '<strong>$1</strong>')
      }</span>`;
    }
    // INFO autorun entries (unknown vendor)
    if (/\[AUTORUN-INFO\]/.test(ln)) {
      return `<span class="rl-info">${
        ln.replace(/(\[AUTORUN-INFO\])/g, '<strong>$1</strong>')
      }</span>`;
    }
    // IFEO / Winlogon / SilentExit → always high
    if (/\[(IFEO HIJACK|WINLOGON TAMPER|SILENT_EXIT[^\]]*)\]/.test(ln)) {
      return `<span class="rl-high">${
        ln.replace(/(\[[^\]]+\])/g, '<strong>$1</strong>')
      }</span>`;
    }
    // Running suspicious service
    if (/\[RUNNING\]/.test(ln)) {
      return `<span class="rl-high">${
        ln.replace(/(\[RUNNING\])/g, '<strong>$1</strong>')
      }</span>`;
    }
    // Stopped suspicious service
    if (/\[STOPPED\]/.test(ln)) {
      return `<span class="rl-info">${
        ln.replace(/(\[STOPPED\])/g, '<strong>$1</strong>')
      }</span>`;
    }
    // Suspicious scheduled task
    if (/\[TASK\]/.test(ln)) {
      return `<span class="rl-med">${
        ln.replace(/(\[TASK\])/g, '<strong>$1</strong>')
      }</span>`;
    }
    // System32 flagged file
    if (/^\s+\[(E|N|T|\[)/.test(ln)) {
      return `<span class="rl-info">${ln}</span>`;
    }
    // Good news
    if (/\(none detected\)/.test(ln)) {
      return `<span class="rl-clean">${ln}</span>`;
    }
    // Reason / Path indented lines — dim
    if (/^\s+(Reason|Path|Value|Name|Action)\s*:/.test(ln)) {
      return `<span class="rl-detail">${ln}</span>`;
    }
    // Network: LISTEN / ESTABLISHED
    if (/\bLISTEN\b/.test(ln))      return `<span class="rl-net">${ln}</span>`;
    if (/\bESTABLISHED\b/.test(ln)) return `<span class="rl-net-estab">${ln}</span>`;
    return ln;
  }).join('\n');
}

function closeEpDrawer() {
  document.getElementById('epDrawer').classList.add('hidden');
}

function _closeDrawerOutside(e) {
  const drawer = document.getElementById('epDrawer');
  if (!drawer.contains(e.target)) {
    drawer.classList.add('hidden');
  } else {
    document.addEventListener('click', _closeDrawerOutside, { once: true });
  }
}

// Poll every 15s when dashboard is visible
function startEpPoll() {
  if (_epPollTimer) return;
  loadEpDash();
  _epPollTimer = setInterval(loadEpDash, 15000);
}
function stopEpPoll() {
  clearInterval(_epPollTimer);
  _epPollTimer = null;
}

// Hook into tab switching (patch existing handler)
const _origTabHandler = document.querySelectorAll('.nav-item');
document.querySelectorAll('.nav-item').forEach(btn => {
  btn.addEventListener('click', () => {
    if (btn.dataset.tab === 'epdash') startEpPoll();
    else stopEpPoll();
  });
});

// Background badge poll (every 30s regardless of active tab)
setInterval(updateEpBadge, 30000);
// Initial badge load
setTimeout(async () => {
  try {
    const d = await get('/api/reports');
    _epReports = d.data || [];
    updateEpBadge();
  } catch(e) {}
}, 2000);

// ══════════════════════════════════════════════════════════════
//  THREAT INTEL
// ══════════════════════════════════════════════════════════════

// ── shared helpers ──────────────────────────────────────────
function tiUnwrapAI(ai) {
  if (ai && !ai.risk && !ai.verdict && ai.summary && typeof ai.summary === 'string') {
    try { const m = ai.summary.match(/\{[\s\S]*\}/); if (m) return JSON.parse(m[0]); } catch(_) {}
  }
  return ai || {};
}

function tiRiskClass(risk) {
  const r = (risk||'').toUpperCase();
  if (r === 'HIGH'   || r === 'MALICIOUS')  return 'ti-risk-high';
  if (r === 'MEDIUM' || r === 'SUSPICIOUS') return 'ti-risk-med';
  if (r === 'LOW')                          return 'ti-risk-low';
  if (r === 'CLEAN')                        return 'ti-risk-clean';
  return 'ti-risk-unknown';
}
function tiPolicyBadge(pol) {
  const map = {
    hardfail:   ['HARDFAIL',   'ti-pol-good'],
    reject:     ['REJECT',     'ti-pol-good'],
    softfail:   ['SOFTFAIL',   'ti-pol-med'],
    quarantine: ['QUARANTINE', 'ti-pol-med'],
    neutral:    ['NEUTRAL',    'ti-pol-bad'],
    none:       ['NONE',       'ti-pol-bad'],
    missing:    ['MISSING',    'ti-pol-bad'],
    pass_all:   ['PASS ALL ⚠', 'ti-pol-crit'],
    incomplete: ['INCOMPLETE', 'ti-pol-bad'],
  };
  const [lbl, cls] = map[pol] || [pol||'?', 'ti-pol-bad'];
  return `<span class="ti-pol-badge ${cls}">${lbl}</span>`;
}
function tiRow(label, value) {
  return `<div class="ti-row"><span class="ti-row-lbl">${label}</span><span class="ti-row-val">${value}</span></div>`;
}
function tiDnsRow(type, val) {
  if (!val || (Array.isArray(val) && !val.length)) return '';
  if (val === null) return tiRow(type, '<span class="ti-row-miss">NXDOMAIN</span>');
  if (type === 'MX') {
    return val.map(r => tiRow(`MX (${r.pref})`, escapeHtml(r.host))).join('');
  }
  if (Array.isArray(val)) return val.map(v => tiRow(type, escapeHtml(v))).join('');
  return tiRow(type, escapeHtml(String(val)));
}
function tiBtn(label, busy, id) {
  const el = document.getElementById(id);
  if (el) { el.disabled = busy; el.textContent = busy ? label : el.textContent.replace('…',''); }
}

// ── DOMAIN SEARCH ────────────────────────────────────────────
function tiDomainSetAndRun(d) {
  document.getElementById('tiDomainInput').value = d;
  tiDomainSearch();
}

async function tiDomainSearch() {
  const domain = document.getElementById('tiDomainInput').value.trim();
  if (!domain) return;
  show('tiDomainLoading'); hide('tiDomainResults');
  document.getElementById('tiDomainBtn').disabled = true;
  document.getElementById('tiDomainBtn').textContent = 'Analyzing…';
  try {
    const d = await post('/api/ti/domain', { domain });
    const r = d.data;
    if (d.error || r?.error) { showToast(d.error || r.error); return; }
    renderDomainResults(r);
    show('tiDomainResults');
  } catch(e) { showToast('Domain check failed: ' + e.message); }
  finally {
    hide('tiDomainLoading');
    document.getElementById('tiDomainBtn').disabled = false;
    document.getElementById('tiDomainBtn').textContent = 'Analyze';
  }
}

function renderDomainResults(r) {
  // AI banner
  const ai = tiUnwrapAI(r.ai);
  const riskEl = document.getElementById('tiDomainRisk');
  riskEl.textContent = ai.risk || '?';
  riskEl.className = 'ti-verdict ' + tiRiskClass(ai.risk);
  document.getElementById('tiDomainAISummary').textContent = ai.summary || '';
  const concerns = (ai.concerns || []);
  document.getElementById('tiDomainAIConcerns').innerHTML =
    concerns.map(c => `<span class="ti-note-chip">⚠ ${escapeHtml(c)}</span>`).join('');
  document.getElementById('tiDomainAIActions').innerHTML =
    (ai.actions||[]).map(a => `<div class="ti-action-item">→ ${escapeHtml(a)}</div>`).join('');

  // DNS
  const dns = r.dns || {};
  document.getElementById('tiDomainDNSBody').innerHTML =
    ['A','AAAA','MX','NS','CNAME','SOA'].map(t => tiDnsRow(t, dns[t])).join('') ||
    '<div class="ti-empty">No DNS data</div>';

  // Email security
  const spf   = r.spf   || {};
  const dmarc = r.dmarc || {};
  const dkim  = r.dkim_selectors || [];
  let emailHtml = '';
  emailHtml += `<div class="ti-auth-row">
    <span class="ti-auth-lbl">SPF</span>
    ${tiPolicyBadge(spf.policy)}
    <span class="ti-auth-desc">${escapeHtml(spf.desc||'')}</span>
  </div>`;
  if (spf.record) emailHtml += `<div class="ti-record-line">${escapeHtml(spf.record)}</div>`;
  emailHtml += `<div class="ti-auth-row" style="margin-top:10px">
    <span class="ti-auth-lbl">DMARC</span>
    ${tiPolicyBadge(dmarc.policy)}
    <span class="ti-auth-desc">${escapeHtml(dmarc.desc||'')}</span>
  </div>`;
  if (dmarc.record) emailHtml += `<div class="ti-record-line">${escapeHtml(dmarc.record)}</div>`;
  if (dmarc.rua)    emailHtml += tiRow('Reports to', escapeHtml(dmarc.rua));
  emailHtml += `<div class="ti-auth-row" style="margin-top:10px">
    <span class="ti-auth-lbl">DKIM</span>
    ${dkim.length
      ? dkim.map(s => `<span class="ti-pol-badge ti-pol-good">${s}</span>`).join(' ')
      : '<span class="ti-pol-badge ti-pol-bad">NOT FOUND</span>'}
  </div>`;
  if (ai.email_security) emailHtml += `<div class="ti-ai-note" style="margin-top:10px">${escapeHtml(ai.email_security)}</div>`;
  document.getElementById('tiDomainEmailBody').innerHTML = emailHtml;

  // SSL
  const ssl = r.ssl || {};
  let sslHtml = '';
  if (ssl.valid === true) {
    const daysLeft = ssl.days_left;
    const daysClass = daysLeft < 14 ? 'ti-risk-high' : daysLeft < 30 ? 'ti-risk-med' : 'ti-risk-clean';
    sslHtml += `<div class="ti-ssl-valid"><svg width="14" height="14" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"/></svg> Valid</div>`;
    sslHtml += tiRow('Subject', escapeHtml(ssl.subject_cn||''));
    sslHtml += tiRow('Issuer',  escapeHtml((ssl.issuer_o||ssl.issuer_cn||'')));
    sslHtml += tiRow('Expires', `${escapeHtml(ssl.expiry||'')} <span class="${daysClass}" style="font-size:11px">(${daysLeft} days)</span>`);
    if (ssl.san && ssl.san.length) {
      sslHtml += tiRow('SANs', ssl.san.slice(0,6).map(s => `<span class="ti-san">${escapeHtml(s)}</span>`).join(' '));
    }
  } else if (ssl.valid === false) {
    sslHtml = `<div class="ti-ssl-invalid"><svg width="14" height="14" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z" clip-rule="evenodd"/></svg> Invalid / Untrusted</div><div class="ti-ssl-err">${escapeHtml(ssl.error||'')}</div>`;
  } else {
    sslHtml = `<div class="ti-ssl-na">Port 443 not reachable</div><div class="ti-ssl-err">${escapeHtml(ssl.error||'')}</div>`;
  }
  document.getElementById('tiDomainSSLBody').innerHTML = sslHtml;

  // WHOIS
  const w = r.whois || {};
  let whoisHtml = '';
  if (w.error) {
    whoisHtml = `<div class="ti-empty">${escapeHtml(w.error)}</div>`;
  } else {
    if (w.registrar) whoisHtml += tiRow('Registrar', escapeHtml(w.registrar));
    if (w.org)       whoisHtml += tiRow('Org',       escapeHtml(w.org));
    if (w.created)   whoisHtml += tiRow('Created',   escapeHtml(w.created));
    if (w.expires)   whoisHtml += tiRow('Expires',   escapeHtml(w.expires));
    if (w.updated)   whoisHtml += tiRow('Updated',   escapeHtml(w.updated));
    if (w.nameservers && w.nameservers.length)
      whoisHtml += tiRow('Nameservers', w.nameservers.map(n => `<span class="ti-san">${escapeHtml(n)}</span>`).join(' '));
    if (w.status && w.status.length)
      whoisHtml += tiRow('Status', w.status.slice(0,3).map(s => `<span class="ti-san">${escapeHtml(s.split(' ')[0])}</span>`).join(' '));
    if (!whoisHtml) whoisHtml = '<div class="ti-empty">No WHOIS data</div>';
  }
  document.getElementById('tiDomainWHOISBody').innerHTML = whoisHtml;
}

// ── MAIL SEARCH ───────────────────────────────────────────────
async function tiMailSearch() {
  const email = document.getElementById('tiMailInput').value.trim();
  if (!email) return;
  show('tiMailLoading'); hide('tiMailResults');
  document.getElementById('tiMailBtn').disabled = true;
  document.getElementById('tiMailBtn').textContent = 'Checking…';
  try {
    const d = await post('/api/ti/mail', { email });
    const r = d.data;
    if (d.error || r?.error) { showToast(d.error || r.error); return; }
    renderMailResults(r);
    show('tiMailResults');
  } catch(e) { showToast('Mail check failed: ' + e.message); }
  finally {
    hide('tiMailLoading');
    document.getElementById('tiMailBtn').disabled = false;
    document.getElementById('tiMailBtn').textContent = 'Check';
  }
}

function renderMailResults(r) {
  const ai = tiUnwrapAI(r.ai);
  // validity bar
  const validIcon = document.getElementById('tiMailValidIcon');
  const validText = document.getElementById('tiMailValidText');
  const validSub  = document.getElementById('tiMailValidSub');
  const badges    = document.getElementById('tiMailBadges');

  if (r.valid_format) {
    validIcon.innerHTML = `<svg width="20" height="20" viewBox="0 0 20 20" fill="currentColor" style="color:var(--green)"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"/></svg>`;
    validText.textContent = r.mx_exists ? 'Valid email address' : 'Valid format — domain has no MX records';
    validSub.textContent  = `${r.local}@${r.domain}`;
  } else {
    validIcon.innerHTML = `<svg width="20" height="20" viewBox="0 0 20 20" fill="currentColor" style="color:var(--red)"><path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z" clip-rule="evenodd"/></svg>`;
    validText.textContent = 'Invalid email format';
    validSub.textContent  = '';
  }
  let badgesHtml = '';
  if (r.is_disposable)    badgesHtml += '<span class="ti-badge-warn">DISPOSABLE</span>';
  if (r.is_free_provider) badgesHtml += '<span class="ti-badge-info">FREE PROVIDER</span>';
  if (!r.mx_exists)       badgesHtml += '<span class="ti-badge-crit">NO MX</span>';
  badges.innerHTML = badgesHtml;

  // AI banner
  const riskEl = document.getElementById('tiMailRisk');
  riskEl.textContent = ai.risk || '?';
  riskEl.className = 'ti-verdict ' + tiRiskClass(ai.risk);
  document.getElementById('tiMailAIVerdict').textContent = ai.verdict || '';
  document.getElementById('tiMailAINotes').innerHTML =
    (ai.notes||[]).map(n => `<span class="ti-note-chip">• ${escapeHtml(n)}</span>`).join('');

  const sc = document.getElementById('tiMailSpoofRisk');
  const pc = document.getElementById('tiMailPhishRisk');
  sc.textContent = ai.spoofing_risk || '?';
  sc.className   = 'ti-risk-chip ' + tiRiskClass(ai.spoofing_risk);
  pc.textContent = ai.phishing_risk || '?';
  pc.className   = 'ti-risk-chip ' + tiRiskClass(ai.phishing_risk);

  // MX
  const mx = r.mx_records || [];
  document.getElementById('tiMailMXBody').innerHTML = mx.length
    ? mx.map(m => tiRow(`Priority ${m.pref}`, escapeHtml(m.host))).join('')
    : '<div class="ti-empty">No MX records — domain cannot receive mail</div>';

  // Auth
  const spf   = r.spf   || {};
  const dmarc = r.dmarc || {};
  let authHtml = `
    <div class="ti-auth-row">
      <span class="ti-auth-lbl">SPF</span>
      ${tiPolicyBadge(spf.policy)}
      <span class="ti-auth-desc">${escapeHtml(spf.desc||'')}</span>
    </div>`;
  if (spf.record) authHtml += `<div class="ti-record-line">${escapeHtml(spf.record)}</div>`;
  authHtml += `<div class="ti-auth-row" style="margin-top:10px">
    <span class="ti-auth-lbl">DMARC</span>
    ${tiPolicyBadge(dmarc.policy)}
    <span class="ti-auth-desc">${escapeHtml(dmarc.desc||'')}</span>
  </div>`;
  if (dmarc.record) authHtml += `<div class="ti-record-line">${escapeHtml(dmarc.record)}</div>`;
  document.getElementById('tiMailAuthBody').innerHTML = authHtml;
}

// ── IOC SEARCH ────────────────────────────────────────────────
const IOC_TYPES = {
  sha256: 'SHA256', sha1: 'SHA1', md5: 'MD5',
  ip: 'IP', url: 'URL', domain: 'DOMAIN', unknown: '?'
};

function detectIocType(ioc) {
  if (!ioc) return null;
  if (/^[a-fA-F0-9]{64}$/.test(ioc)) return 'sha256';
  if (/^[a-fA-F0-9]{40}$/.test(ioc)) return 'sha1';
  if (/^[a-fA-F0-9]{32}$/.test(ioc)) return 'md5';
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(ioc)) return 'ip';
  if (/^https?:\/\//.test(ioc)) return 'url';
  if (/^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$/.test(ioc)) return 'domain';
  return null;
}

function tiIocTypeHint(val) {
  const t = detectIocType(val.trim());
  const chip = document.getElementById('tiIocTypeChip');
  if (t) {
    chip.textContent = IOC_TYPES[t] || t;
    chip.className = 'ti-type-chip ti-type-' + t;
    chip.classList.remove('hidden');
  } else {
    chip.classList.add('hidden');
  }
}

function tiIocSetAndRun(ioc) {
  document.getElementById('tiIocInput').value = ioc;
  tiIocTypeHint(ioc);
  tiIocSearch();
}

async function tiIocSearch() {
  const ioc = document.getElementById('tiIocInput').value.trim();
  if (!ioc) return;
  const type = detectIocType(ioc);
  const loadTxt = document.getElementById('tiIocLoadingText');
  const srcMap = { ip: 'URLhaus · Shodan InternetDB · ip-api', domain: 'URLhaus · DNS · WHOIS',
                   url: 'URLhaus · DNS', sha256: 'URLhaus hash lookup',
                   md5: 'URLhaus hash lookup', sha1: 'URLhaus hash lookup' };
  if (loadTxt) loadTxt.textContent = `Querying ${srcMap[type]||'threat intelligence'}…`;

  show('tiIocLoading'); hide('tiIocResults');
  document.getElementById('tiIocBtn').disabled = true;
  document.getElementById('tiIocBtn').textContent = 'Searching…';
  try {
    const d = await post('/api/ti/ioc', { ioc });
    const r = d.data;
    if (d.error || r?.error) { showToast(d.error || r.error); return; }
    renderIocResults(r);
    show('tiIocResults');
  } catch(e) { showToast('IOC search failed: ' + e.message); }
  finally {
    hide('tiIocLoading');
    document.getElementById('tiIocBtn').disabled = false;
    document.getElementById('tiIocBtn').textContent = 'Search';
  }
}

function renderIocResults(r) {
  const ai = tiUnwrapAI(r.ai);
  const verdict = (ai.verdict||'UNKNOWN').toUpperCase();

  // verdict banner
  const vEl = document.getElementById('tiIocVerdict');
  vEl.textContent = verdict;
  vEl.className = 'ti-verdict-large ' + tiRiskClass(verdict === 'MALICIOUS' ? 'HIGH' : verdict === 'SUSPICIOUS' ? 'MEDIUM' : 'CLEAN');
  document.getElementById('tiIocConfidence').textContent = ai.confidence ? `Confidence: ${ai.confidence}` : '';
  document.getElementById('tiIocSummary').textContent = ai.summary || '';
  document.getElementById('tiIocTags').innerHTML =
    (ai.tags||[]).map(t => `<span class="ti-tag">${escapeHtml(t)}</span>`).join('');

  // context + actions
  document.getElementById('tiIocContext').textContent = ai.threat_context || '—';
  document.getElementById('tiIocActions').innerHTML =
    (ai.actions||[]).map(a => `<div class="ti-action-item">→ ${escapeHtml(a)}</div>`).join('') || '<div class="ti-empty">—</div>';

  // source cards
  const sources = r.sources || {};
  let srcHtml = '';

  // URLhaus
  if (sources.urlhaus) {
    srcHtml += renderUrlhausCard(sources.urlhaus);
  }

  // Shodan InternetDB (IP only)
  if (sources.shodan) {
    srcHtml += renderShodanCard(sources.shodan, r.ioc);
  }

  // ip-api (IP only)
  if (sources.ipapi && sources.ipapi.status !== 'fail') {
    srcHtml += renderIpapiCard(sources.ipapi, r.rdns);
  }

  // DNS (domain/URL)
  if (r.dns) {
    let dnsHtml = ['A','MX','NS','TXT'].map(t => tiDnsRow(t, r.dns[t])).filter(Boolean).join('');
    if (dnsHtml) {
      srcHtml += `<div class="ti-src-card">
        <div class="ti-src-head"><span class="ti-src-name">DNS</span></div>
        <div class="ti-card-body">${dnsHtml}</div>
      </div>`;
    }
  }

  // WHOIS (domain)
  if (r.whois && !r.whois.error) {
    const w = r.whois;
    let wHtml = '';
    if (w.registrar) wHtml += tiRow('Registrar', escapeHtml(w.registrar));
    if (w.created)   wHtml += tiRow('Created',   escapeHtml(w.created));
    if (w.expires)   wHtml += tiRow('Expires',   escapeHtml(w.expires));
    srcHtml += `<div class="ti-src-card">
      <div class="ti-src-head"><span class="ti-src-name">WHOIS</span></div>
      <div class="ti-card-body">${wHtml}</div>
    </div>`;
  }

  document.getElementById('tiIocSources').innerHTML = srcHtml || '<div class="ti-empty">No source data</div>';
}

function renderUrlhausCard(u) {
  const status = u.query_status || 'error';
  const isHit  = status === 'is_host' || status === 'ok';
  const noHit  = status === 'no_results' || status === 'not_found';
  let body = '';
  if (u.error) {
    body = `<div class="ti-empty">${escapeHtml(u.error)}</div>`;
  } else if (noHit) {
    body = `<div class="ti-src-clean">✓ Not found in URLhaus database</div>`;
  } else if (isHit) {
    if (u.blacklists) {
      const bl = u.blacklists;
      body += tiRow('SURBL',    bl.surbl    || 'not listed');
      body += tiRow('GSAFE',    bl.gsb      || 'not listed');
      body += tiRow('Spamhaus', bl.spamhaus_dbl || 'not listed');
    }
    if (u.urls_count !== undefined) body += tiRow('Malicious URLs', u.urls_count);
    if (u.tags)         body += tiRow('Tags', u.tags.map(t => `<span class="ti-tag">${escapeHtml(t)}</span>`).join(' '));
    if (u.threat)       body += tiRow('Threat', escapeHtml(u.threat));
    if (u.url_status)   body += tiRow('Status', escapeHtml(u.url_status));
    if (u.date_added)   body += tiRow('First seen', escapeHtml(u.date_added));
    if (!body)          body = `<div class="ti-src-warn">Found in URLhaus (status: ${escapeHtml(status)})</div>`;
  } else {
    body = `<div class="ti-empty">Status: ${escapeHtml(status)}</div>`;
  }
  const badge = noHit ? '<span class="ti-src-badge clean">CLEAN</span>'
                      : isHit ? '<span class="ti-src-badge hit">HIT</span>'
                      : '<span class="ti-src-badge unknown">?</span>';
  return `<div class="ti-src-card">
    <div class="ti-src-head">
      <span class="ti-src-name">URLhaus <span class="ti-src-sub">abuse.ch</span></span>
      ${badge}
    </div>
    <div class="ti-card-body">${body}</div>
  </div>`;
}

function renderShodanCard(s, ip) {
  let body = '';
  if (s.error) {
    body = `<div class="ti-empty">${escapeHtml(String(s.error))}</div>`;
  } else {
    if (s.ports && s.ports.length)   body += tiRow('Open ports', s.ports.join(', '));
    if (s.vulns && s.vulns.length)   body += tiRow('CVEs', s.vulns.map(v => `<span class="ti-tag ti-tag-crit">${escapeHtml(v)}</span>`).join(' '));
    if (s.hostnames && s.hostnames.length) body += tiRow('Hostnames', s.hostnames.slice(0,4).map(h => escapeHtml(h)).join(', '));
    if (s.tags && s.tags.length)     body += tiRow('Tags', s.tags.map(t => `<span class="ti-tag">${escapeHtml(t)}</span>`).join(' '));
    if (!body) body = '<div class="ti-src-clean">✓ No notable findings</div>';
  }
  const hasCrit = s.vulns && s.vulns.length;
  const badge = hasCrit ? '<span class="ti-src-badge hit">CVEs</span>' : '<span class="ti-src-badge clean">OK</span>';
  return `<div class="ti-src-card">
    <div class="ti-src-head">
      <span class="ti-src-name">Shodan <span class="ti-src-sub">InternetDB</span></span>
      ${badge}
    </div>
    <div class="ti-card-body">${body}</div>
  </div>`;
}

function renderIpapiCard(a, rdns) {
  let body = '';
  if (a.country)     body += tiRow('Country',  `${escapeHtml(a.country)} (${escapeHtml(a.countryCode||'')})`);
  if (a.regionName)  body += tiRow('Region',   escapeHtml(a.regionName));
  if (a.city)        body += tiRow('City',     escapeHtml(a.city));
  if (a.org)         body += tiRow('Org',      escapeHtml(a.org));
  if (a.as)          body += tiRow('ASN',      escapeHtml(a.as));
  if (rdns)          body += tiRow('rDNS',     escapeHtml(rdns));
  const flags = [];
  if (a.proxy)   flags.push('<span class="ti-badge-warn">PROXY/VPN</span>');
  if (a.hosting) flags.push('<span class="ti-badge-info">HOSTING</span>');
  if (a.mobile)  flags.push('<span class="ti-badge-info">MOBILE</span>');
  if (flags.length) body += `<div style="margin-top:8px">${flags.join(' ')}</div>`;
  return `<div class="ti-src-card">
    <div class="ti-src-head">
      <span class="ti-src-name">Geolocation <span class="ti-src-sub">ip-api.com</span></span>
    </div>
    <div class="ti-card-body">${body}</div>
  </div>`;
}

// ══════════════════════════════════════════════════════════════
//  SIDEBAR SECTIONS
// ══════════════════════════════════════════════════════════════
function toggleSec(id) {
  const nav = document.getElementById('sec-' + id);
  const hdr = document.getElementById('hdr-' + id);
  if (!nav) return;
  const collapsed = nav.classList.toggle('sec-collapsed');
  hdr.classList.toggle('sec-hdr-collapsed', collapsed);
  const saved = JSON.parse(localStorage.getItem('soc_sec_state') || '{}');
  saved[id] = collapsed;
  localStorage.setItem('soc_sec_state', JSON.stringify(saved));
}
(function initSections() {
  const saved = JSON.parse(localStorage.getItem('soc_sec_state') || '{}');
  Object.entries(saved).forEach(([id, collapsed]) => {
    if (!collapsed) return;
    const nav = document.getElementById('sec-' + id);
    const hdr = document.getElementById('hdr-' + id);
    if (nav) nav.classList.add('sec-collapsed');
    if (hdr) hdr.classList.add('sec-hdr-collapsed');
  });
})();

// ── SIEM platform selector ──
const SIEM_LABELS = {
  splunk:   'Splunk',
  elastic:  'Elastic / ELK',
  sentinel: 'Microsoft Sentinel',
  qradar:   'IBM QRadar',
  wazuh:    'Wazuh',
  arcsight: 'ArcSight',
};
const SIEM_LANGS = {
  splunk:   'SPL',
  elastic:  'KQL',
  sentinel: 'KQL',
  qradar:   'AQL',
  wazuh:    'WQL',
  arcsight: 'ArcSight',
};
function setSiemPlatform(val) {
  currentSiem = val;
  localStorage.setItem('soc_siem', val);
  _applySiemUI();
}

function _applySiemUI() {
  const lang   = SIEM_LANGS[currentSiem]  || 'Query';
  const canRun = currentSiem === 'splunk';

  const lbl = document.getElementById('siemQueryLabel');
  if (lbl) lbl.textContent = lang + ' Query';

  const noConn = document.getElementById('siemNoConn');
  if (noConn) noConn.classList.toggle('hidden', canRun);

  const runBtn = document.getElementById('runSplBtn');
  if (runBtn) runBtn.style.display = canRun ? '' : 'none';

  const sel = document.getElementById('siemSelector');
  if (sel) sel.value = currentSiem;

  const editor = document.getElementById('splunkCode');
  if (editor) editor.placeholder = canRun
    ? 'SPL query — edit and run directly against Splunk...'
    : `${lang} query — generated for ${SIEM_LABELS[currentSiem] || currentSiem}`;
}

(function initSiem() { _applySiemUI(); })();

// ══════════════════════════════════════════════════════════════
//  THEME
// ══════════════════════════════════════════════════════════════
function applyTheme(t) {
  document.documentElement.setAttribute('data-theme', t);
  localStorage.setItem('soc_theme', t);
  document.getElementById('themeOptDark').classList.toggle('active',  t === 'dark');
  document.getElementById('themeOptViper').classList.toggle('active', t === 'viper');
  document.getElementById('themeOptLight').classList.toggle('active', t === 'light');
}
function toggleTheme() {
  const order = ['dark', 'viper', 'light'];
  const cur = document.documentElement.getAttribute('data-theme') || 'dark';
  applyTheme(order[(order.indexOf(cur) + 1) % order.length]);
}
// Apply on load
(function() {
  applyTheme(localStorage.getItem('soc_theme') || 'dark');
})();

// ══════════════════════════════════════════════════════════════
//  SETTINGS
// ══════════════════════════════════════════════════════════════
async function loadSettings() {
  if (currentUser) applyUserRole(currentUser.role);
  try {
    const d = await get('/api/settings');
    const s = d.data || {};
    const map = { virustotal_key: 'vtKey', abuseipdb_key: 'abuseKey', shodan_key: 'shodanKey' };
    for (const [k, elId] of Object.entries(map)) {
      const el = document.getElementById(elId);
      if (el) el.placeholder = s[k] ? 'Configured (' + s[k] + ')' : el.placeholder;
    }
  } catch(_) {}
  if (currentUser?.role === 'admin') loadAdminUsers();
}

async function saveSettings() {
  const btn = document.getElementById('cfgSaveBtn');
  btn.disabled = true; btn.textContent = 'Saving…';
  try {
    const payload = {
      virustotal_key: document.getElementById('vtKey').value,
      abuseipdb_key:  document.getElementById('abuseKey').value,
      shodan_key:     document.getElementById('shodanKey').value,
    };
    await post('/api/settings', payload);
    showToast('Settings saved');
    ['vtKey','abuseKey','shodanKey'].forEach(id => {
      const el = document.getElementById(id);
      if (el && el.value) { el.placeholder = 'Configured (●●●●●●)'; el.value = ''; }
    });
  } catch(e) { showToast('Save failed: ' + e.message); }
  finally { btn.disabled = false; btn.innerHTML = '<svg width="14" height="14" viewBox="0 0 20 20" fill="currentColor"><path d="M7.707 10.293a1 1 0 10-1.414 1.414l3 3a1 1 0 001.414 0l3-3a1 1 0 00-1.414-1.414L11 11.586V6h5a2 2 0 012 2v7a2 2 0 01-2 2H4a2 2 0 01-2-2V8a2 2 0 012-2h5v5.586l-1.293-1.293z"/></svg> Save API Keys'; }
}

async function testKey(service, inputId, statusId) {
  const key = document.getElementById(inputId).value.trim();
  const statusEl = document.getElementById(statusId);
  if (!key) { statusEl.textContent = 'Enter a key first'; statusEl.className = 'cfg-key-status warn'; return; }
  statusEl.textContent = 'Testing…'; statusEl.className = 'cfg-key-status';
  try {
    const d = await post('/api/settings/test', { service, key });
    statusEl.textContent = d.message || (d.ok ? '✓ OK' : '✗ Failed');
    statusEl.className = 'cfg-key-status ' + (d.ok ? 'ok' : 'fail');
  } catch(e) { statusEl.textContent = '✗ Error'; statusEl.className = 'cfg-key-status fail'; }
}

function toggleKeyVis(inputId, btn) {
  const el = document.getElementById(inputId);
  const isPass = el.type === 'password';
  el.type = isPass ? 'text' : 'password';
}

// ══════════════════════════════════════════════════════════════
//  NEW SOURCE RENDERERS (VT, AbuseIPDB, RBL, crt.sh)
// ══════════════════════════════════════════════════════════════
function renderVTCard(vt, iocType) {
  if (!vt || vt.error === 'no_key') {
    return `<div class="ti-src-card ti-src-nokey">
      <div class="ti-src-head"><span class="ti-src-name">VirusTotal</span><span class="ti-src-badge unknown">NO KEY</span></div>
      <div class="ti-card-body ti-empty">Add VirusTotal API key in Settings</div>
    </div>`;
  }
  if (vt.error === 'invalid_key') return renderSrcErr('VirusTotal', 'Invalid API key');
  if (vt.error === 'not_found')   return renderSrcErr('VirusTotal', 'Not found in VT database');
  if (vt.error)                   return renderSrcErr('VirusTotal', vt.error);

  const attr  = vt.data?.attributes || {};
  const stats = attr.last_analysis_stats || {};
  const mal   = (stats.malicious || 0);
  const sus   = (stats.suspicious || 0);
  const total = Object.values(stats).reduce((a,b)=>a+b, 0);
  const rep   = attr.reputation;
  const hasBad = mal > 0 || sus > 0;
  const badge = total > 0
    ? `<span class="ti-src-badge ${hasBad ? 'hit' : 'clean'}">${mal}/${total}</span>`
    : '<span class="ti-src-badge unknown">?</span>';

  let body = '';
  if (total > 0) body += tiRow('Detections', `<span class="${hasBad ? 'ti-risk-high' : 'ti-risk-clean'}" style="padding:1px 6px;border-radius:3px">${mal} malicious, ${sus} suspicious / ${total} engines</span>`);
  if (rep !== undefined) body += tiRow('Reputation', rep < 0 ? `<span style="color:var(--red)">${rep}</span>` : `<span style="color:var(--green)">${rep}</span>`);
  if (attr.country)    body += tiRow('Country', escapeHtml(attr.country));
  if (attr.as_owner)   body += tiRow('AS Owner', escapeHtml(attr.as_owner));
  if (attr.network)    body += tiRow('Network', escapeHtml(attr.network));
  if (attr.registrar)  body += tiRow('Registrar', escapeHtml(attr.registrar));
  const cats = attr.categories ? Object.values(attr.categories).slice(0,3).join(', ') : '';
  if (cats) body += tiRow('Categories', escapeHtml(cats));
  const votes = attr.total_votes;
  if (votes) body += tiRow('Community', `${votes.malicious || 0} malicious / ${votes.harmless || 0} harmless`);

  if (!body) body = `<div class="ti-src-clean">✓ No detections</div>`;
  return `<div class="ti-src-card">
    <div class="ti-src-head"><span class="ti-src-name">VirusTotal</span>${badge}</div>
    <div class="ti-card-body">${body}</div>
  </div>`;
}

function renderAbuseIPDBCard(ab) {
  if (!ab || ab.error === 'no_key') {
    return `<div class="ti-src-card ti-src-nokey">
      <div class="ti-src-head"><span class="ti-src-name">AbuseIPDB</span><span class="ti-src-badge unknown">NO KEY</span></div>
      <div class="ti-card-body ti-empty">Add AbuseIPDB API key in Settings</div>
    </div>`;
  }
  if (ab.error === 'invalid_key') return renderSrcErr('AbuseIPDB', 'Invalid API key');
  if (ab.error)                   return renderSrcErr('AbuseIPDB', ab.error);

  const d = ab.data || {};
  const score = d.abuseConfidenceScore ?? 0;
  const scoreClass = score >= 75 ? 'ti-risk-high' : score >= 25 ? 'ti-risk-med' : 'ti-risk-clean';
  const badge = `<span class="ti-src-badge ${score >= 25 ? 'hit' : 'clean'}">${score}%</span>`;

  let body = tiRow('Abuse Score', `<span class="${scoreClass}" style="padding:1px 6px;border-radius:3px;font-weight:700">${score}% confidence</span>`);
  if (d.totalReports !== undefined) body += tiRow('Reports', d.totalReports + (d.numDistinctUsers ? ` from ${d.numDistinctUsers} users` : ''));
  if (d.countryCode)  body += tiRow('Country',    escapeHtml(d.countryCode));
  if (d.isp)          body += tiRow('ISP',         escapeHtml(d.isp));
  if (d.usageType)    body += tiRow('Usage Type',  escapeHtml(d.usageType));
  if (d.domain)       body += tiRow('Domain',      escapeHtml(d.domain));
  if (d.isWhitelisted) body += tiRow('Whitelisted', 'Yes');
  if (d.isPublic === false) body += `<div style="margin-top:4px"><span class="ti-badge-info">PRIVATE IP</span></div>`;

  return `<div class="ti-src-card">
    <div class="ti-src-head"><span class="ti-src-name">AbuseIPDB</span>${badge}</div>
    <div class="ti-card-body">${body}</div>
  </div>`;
}

function renderRBLCard(rbl) {
  if (!rbl || rbl.error) return renderSrcErr('Blacklists (MXToolbox)', rbl?.error || 'check failed');
  const { listed=[], listed_count=0, checked=0 } = rbl;
  const badge = listed_count > 0
    ? `<span class="ti-src-badge hit">${listed_count} listed</span>`
    : `<span class="ti-src-badge clean">CLEAN</span>`;
  let body = tiRow('Checked', `${checked} blacklists`);
  if (listed_count === 0) {
    body += `<div class="ti-src-clean" style="margin-top:6px">✓ Not listed in any blacklist</div>`;
  } else {
    body += `<div style="margin-top:6px;display:flex;flex-wrap:wrap;gap:4px">
      ${listed.map(l => `<span class="ti-tag ti-tag-crit">${escapeHtml(l)}</span>`).join('')}
    </div>`;
  }
  return `<div class="ti-src-card">
    <div class="ti-src-head"><span class="ti-src-name">Blacklists <span class="ti-src-sub">MXToolbox style</span></span>${badge}</div>
    <div class="ti-card-body">${body}</div>
  </div>`;
}

function renderCrtshCard(crt, inline) {
  if (!crt || crt.error) return inline ? '' : renderSrcErr('crt.sh', crt?.error || 'failed');
  const names = crt.names || [];
  let body = tiRow('Total certs', crt.total_certs);
  body += tiRow('Unique names', crt.unique_names);
  if (crt.first_seen) body += tiRow('First seen', escapeHtml(crt.first_seen));
  if (crt.last_seen)  body += tiRow('Last seen',  escapeHtml(crt.last_seen));
  if (names.length) {
    body += `<div class="cfg-sub" style="margin-top:8px;margin-bottom:4px">Discovered names</div>
    <div class="ti-crt-names">${names.slice(0,20).map(n =>
      `<span class="ti-san">${escapeHtml(n.name)}</span>`
    ).join('')}${names.length > 20 ? `<span class="ti-empty"> +${names.length-20} more</span>` : ''}</div>`;
  }
  if (inline) return `<div class="ti-card" style="margin-top:14px">
    <div class="ti-card-head">
      <svg viewBox="0 0 20 20" fill="currentColor" width="14" height="14"><path fill-rule="evenodd" d="M5 9V7a5 5 0 0110 0v2a2 2 0 012 2v5a2 2 0 01-2 2H5a2 2 0 01-2-2v-5a2 2 0 012-2zm8-2v2H7V7a3 3 0 016 0z" clip-rule="evenodd"/></svg>
      Certificate Transparency (crt.sh)
    </div>
    <div class="ti-card-body">${body}</div>
  </div>`;
  return `<div class="ti-src-card">
    <div class="ti-src-head"><span class="ti-src-name">crt.sh <span class="ti-src-sub">Cert Transparency</span></span></div>
    <div class="ti-card-body">${body}</div>
  </div>`;
}

function renderSrcErr(name, msg) {
  return `<div class="ti-src-card">
    <div class="ti-src-head"><span class="ti-src-name">${escapeHtml(name)}</span></div>
    <div class="ti-card-body ti-empty">${escapeHtml(msg)}</div>
  </div>`;
}

// Patch renderIocResults to include new sources
const _origRenderIocResults = renderIocResults;
window.renderIocResults = function(r) {
  _origRenderIocResults(r);
  // Append new source cards into tiIocSources
  const sources = r.sources || {};
  const container = document.getElementById('tiIocSources');
  if (!container) return;
  let extra = '';
  if (sources.virustotal !== undefined) extra += renderVTCard(sources.virustotal, r.type);
  if (sources.abuseipdb  !== undefined) extra += renderAbuseIPDBCard(sources.abuseipdb);
  if (sources.rbl        !== undefined) extra += renderRBLCard(sources.rbl);
  if (sources.crt        !== undefined) extra += renderCrtshCard(sources.crt, false);
  container.innerHTML += extra;
};

// Patch renderDomainResults to include crt.sh + VT
const _origRenderDomainResults = renderDomainResults;
window.renderDomainResults = function(r) {
  _origRenderDomainResults(r);
  const grid = document.querySelector('#tiDomainResults .ti-grid');
  if (!grid) return;
  if (r.crt) { const el = createHtmlEl(renderCrtshCard(r.crt, true)); if (el) grid.appendChild(el); }
  if (r.virustotal && r.virustotal.error !== 'no_key') {
    const card = document.createElement('div');
    card.className = 'ti-card';
    card.innerHTML = `<div class="ti-card-head"><svg viewBox="0 0 20 20" fill="currentColor" width="14" height="14"><path fill-rule="evenodd" d="M2.166 4.999A11.954 11.954 0 0010 1.944 11.954 11.954 0 0017.834 5c.11.65.166 1.32.166 2.001 0 5.225-3.34 9.67-8 11.317C5.34 16.67 2 12.225 2 7c0-.682.057-1.35.166-2.001zm11.541 3.708a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"/></svg>VirusTotal</div>` +
      `<div class="ti-card-body">${renderVTCard(r.virustotal, 'domain').replace(/<div class="ti-src-card">.*?<div class="ti-card-body">/s,'').replace(/<\/div>\s*<\/div>\s*$/s,'')}</div>`;
    grid.appendChild(card);
  }
};

function createHtmlEl(html) {
  const t = document.createElement('template');
  t.innerHTML = html.trim();
  return t.content.firstChild;
}

// ══════════════════════════════════════════════════════════════
//  INSIDER THREAT DETECTION
// ══════════════════════════════════════════════════════════════

let _insiderUsers      = [];   // all users from Splunk
let _insiderData       = [];   // analyzed results
let _insiderDrawerUser = null;
let _insiderSearch     = '';
const _analyzingSet    = new Set();

const INS_CATS = [
  { key: 'off_hours',     icon: '🌙', label: 'Off-Hours Login'        },
  { key: 'failed_logins', icon: '🔐', label: 'Failed Logins'          },
  { key: 'file_access',   icon: '📂', label: 'Mass File Access'       },
  { key: 'usb_activity',  icon: '💾', label: 'USB Activity'           },
  { key: 'archive',       icon: '🗜', label: 'Archive Creation'       },
  { key: 'privilege_use', icon: '👑', label: 'Privilege Abuse'        },
  { key: 'exfil_tools',   icon: '📤', label: 'Exfil / Code Transfer'  },
  { key: 'abnormal_proc', icon: '⚡', label: 'Suspicious Process'     },
];

async function loadInsider() {
  const loadEl = document.getElementById('insLoading');
  const txtEl  = document.getElementById('insLoadingText');
  loadEl.classList.remove('hidden');
  txtEl.textContent = 'Loading users from SIEM...';
  try {
    const [ud, ad] = await Promise.all([get('/api/insider/users'), get('/api/insider/list')]);
    _insiderUsers = (ud.data || []).map(u => typeof u === 'object' ? u : { username: u, machine: '' });
    _insiderData  = ad.data || [];
    // ensure any previously analyzed users appear even if not in the Splunk query window
    _insiderData.forEach(d => {
      if (!_insiderUsers.find(u => u.username === d.username))
        _insiderUsers.push({ username: d.username, machine: d.machine || '' });
    });
    renderInsiderGrid();
  } catch(e) { showToast('Failed to load users'); }
  loadEl.classList.add('hidden');
}

function insiderSearch() {
  _insiderSearch = (document.getElementById('insSearch').value || '').trim().toLowerCase();
  renderInsiderGrid();
}

async function insiderAnalyzeAndOpen(username) {
  if (_analyzingSet.has(username)) return;
  const days = parseInt(document.getElementById('insDaysSelect').value) || 30;
  _analyzingSet.add(username);
  renderInsiderGrid();
  try {
    const r = await post('/api/insider/analyze', { username, days });
    if (r.success) {
      const idx = _insiderData.findIndex(x => x.username === username);
      if (idx >= 0) _insiderData[idx] = r.data;
      else _insiderData.push(r.data);
    } else {
      showToast('Analysis failed: ' + (r.error || 'Unknown'));
    }
  } catch(e) {
    showToast('Error: ' + e.message);
  }
  _analyzingSet.delete(username);
  renderInsiderGrid();
  if (_insiderData.find(u => u.username === username)) openInsiderDrawer(username);
}

function renderInsiderGrid() {
  const grid    = document.getElementById('insGrid');
  const empty   = document.getElementById('insEmpty');
  const statBar = document.getElementById('insStatBar');

  // Filter by search
  const q = _insiderSearch;
  const filtered = _insiderUsers.filter(u =>
    !q ||
    u.username.toLowerCase().includes(q) ||
    (u.machine || '').toLowerCase().includes(q)
  );

  if (!filtered.length) {
    grid.innerHTML = '';
    empty.style.display = '';
    statBar.classList.add('hidden');
    return;
  }
  empty.style.display = 'none';

  // Stats from analyzed data only
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, CLEAN: 0 };
  _insiderData.forEach(u => { if (counts[u.risk] !== undefined) counts[u.risk]++; });
  statBar.classList.remove('hidden');
  document.getElementById('insStatCrit').textContent  = counts.CRITICAL || 0;
  document.getElementById('insStatHigh').textContent  = counts.HIGH     || 0;
  document.getElementById('insStatMed').textContent   = counts.MEDIUM   || 0;
  document.getElementById('insStatLow').textContent   = counts.LOW      || 0;
  document.getElementById('insStatClean').textContent = counts.CLEAN    || 0;
  const highRisk = (counts.CRITICAL || 0) + (counts.HIGH || 0);
  const badge = document.getElementById('insiderBadge');
  if (badge) { badge.textContent = highRisk; badge.style.display = highRisk ? '' : 'none'; }

  // Sort: high-risk analyzed first → lower-risk analyzed → analyzing → unanalyzed
  const RISK_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, CLEAN: 4 };
  const sorted = [...filtered].sort((a, b) => {
    const da = _insiderData.find(x => x.username === a.username);
    const db = _insiderData.find(x => x.username === b.username);
    const ana = _analyzingSet.has(a.username);
    const anb = _analyzingSet.has(b.username);
    if (da && db) return (RISK_ORDER[da.risk] ?? 5) - (RISK_ORDER[db.risk] ?? 5);
    if (da) return -1;
    if (db) return 1;
    if (ana && !anb) return -1;
    if (anb && !ana) return 1;
    return a.username.localeCompare(b.username);
  });

  grid.innerHTML = sorted.map(u => {
    const analyzed  = _insiderData.find(x => x.username === u.username);
    const analyzing = _analyzingSet.has(u.username);
    const label     = u.machine ? `${u.username} — ${u.machine}` : u.username;

    if (analyzing) {
      return `<div class="ins-card ins-card-analyzing" data-user="${escapeHtml(u.username)}">
        <div class="ins-card-top">
          <span class="ins-card-user">${escapeHtml(label)}</span>
          <span class="ins-badge ins-badge-scanning">SCANNING</span>
        </div>
        <div class="ins-scan-track"><div class="ins-scan-bar"></div></div>
        <div class="ins-card-footer"><span class="ins-pending-hint">Analyzing behavior…</span><span></span></div>
      </div>`;
    }

    if (analyzed) {
      const flags    = INS_CATS.filter(c => (analyzed.findings?.[c.key]?.count || 0) > 0);
      const chipHtml = flags.slice(0, 4).map(c => {
        const sev = (analyzed.findings[c.key].sev || 'LOW').toLowerCase();
        return `<span class="ins-flag-chip ins-sev-${sev}">${c.icon} ${c.label}</span>`;
      }).join('');
      const extraFlags = flags.length > 4 ? `<span class="ins-flag-more">+${flags.length - 4} more</span>` : '';
      return `<div class="ins-card ins-risk-${analyzed.risk.toLowerCase()}" data-user="${escapeHtml(u.username)}" onclick="openInsiderDrawer(this.dataset.user)">
        <div class="ins-card-top">
          <span class="ins-card-user" title="${escapeHtml(label)}">${escapeHtml(label)}</span>
          <span class="ins-badge ins-badge-${analyzed.risk.toLowerCase()}">${analyzed.risk}</span>
        </div>
        <div class="ins-score-bar" style="margin-bottom:6px">
          <div class="ins-score-fill ins-fill-${analyzed.risk.toLowerCase()}" style="width:${analyzed.score}%"></div>
        </div>
        <div class="ins-flag-row">${chipHtml}${extraFlags}</div>
        <div class="ins-card-footer">
          <span>Score: <strong>${analyzed.score}</strong>/100</span>
          <span>${(analyzed.analyzed_at || '').substring(0, 10)}</span>
        </div>
      </div>`;
    }

    // Unanalyzed
    return `<div class="ins-card ins-card-pending" data-user="${escapeHtml(u.username)}" onclick="insiderAnalyzeAndOpen(this.dataset.user)">
      <div class="ins-card-top">
        <span class="ins-card-user" title="${escapeHtml(label)}">${escapeHtml(label)}</span>
        <span class="ins-badge ins-badge-pending">—</span>
      </div>
      <div class="ins-card-footer">
        <span class="ins-pending-hint">Click to analyze</span>
        <span></span>
      </div>
    </div>`;
  }).join('');
}

function openInsiderDrawer(username) {
  const user = _insiderData.find(u => u.username === username);
  if (!user) return;
  _insiderDrawerUser = username;

  const backdrop = document.getElementById('insBackdrop');
  const drawer   = document.getElementById('insDrawer');
  backdrop.classList.remove('hidden');
  drawer.classList.remove('hidden');

  const ai       = user.ai || {};
  const concerns = (ai.key_concerns || []).filter(Boolean).map(c => `<li>${escapeHtml(c)}</li>`).join('');
  const actions  = (ai.recommended_actions || []).filter(Boolean).map(a => `<li>${escapeHtml(a)}</li>`).join('');

  const catCards = INS_CATS.map(c => {
    const f   = user.findings?.[c.key] || { count: 0, label: c.label, sev: 'NONE' };
    const sev = (f.sev || 'NONE').toLowerCase();
    const active = sev !== 'none';
    return `<div class="ins-cat-card${active ? ' ins-cat-active ins-cat-sev-' + sev : ''}">
      <div class="ins-cat-card-top">
        <span class="ins-cat-card-lbl"><span>${c.icon}</span>${escapeHtml(f.label)}</span>
        <span class="ins-sev-pill ins-sev-${sev}">${sev.toUpperCase()}</span>
      </div>
      <div class="ins-cat-card-count">${f.count}</div>
    </div>`;
  }).join('');

  const displayLabel = user.machine ? `${username} — ${user.machine}` : username;
  drawer.innerHTML = `
    <div class="ins-drawer-hdr">
      <div class="ins-drawer-title">
        <svg width="16" height="16" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M10 9a3 3 0 100-6 3 3 0 000 6zm-7 9a7 7 0 1114 0H3z" clip-rule="evenodd"/></svg>
        <span>${escapeHtml(username)}</span>
        ${user.machine ? `<span class="ins-machine-tag">🖥 ${escapeHtml(user.machine)}</span>` : ''}
        <span class="ins-badge ins-badge-${user.risk.toLowerCase()}">${user.risk}</span>
      </div>
      <button class="ins-drawer-close" onclick="closeInsiderDrawer()">✕</button>
    </div>

    <div class="ins-drawer-score-row">
      <div class="ins-drawer-score-top">
        <span class="ins-drawer-score-num ins-dscore-${user.risk.toLowerCase()}">${user.score}</span>
        <span class="ins-drawer-score-denom">/ 100</span>
        <span class="ins-badge ins-badge-${user.risk.toLowerCase()}" style="margin-left:4px">${user.risk}</span>
        <span class="ins-drawer-score-label">${user.days}-day window &nbsp;•&nbsp; ${(user.analyzed_at || '').substring(0, 10)}${user.machine ? ' &nbsp;•&nbsp; 🖥 ' + escapeHtml(user.machine) : ''}</span>
      </div>
      <div class="ins-score-bar large">
        <div class="ins-score-fill ins-fill-${user.risk.toLowerCase()}" style="width:${user.score}%"></div>
      </div>
    </div>

    <div class="ins-drawer-body">
      <div class="ins-section-hdr">Behavioral Indicators</div>
      <div class="ins-cat-cards">${catCards}</div>

      ${ai.summary ? `
      <div class="ins-section-hdr" style="margin-top:20px">AI Risk Assessment</div>
      <div class="ins-ai-card">
        <div class="ins-ai-summary">${escapeHtml(ai.summary)}</div>
        ${concerns ? `<div class="ins-ai-sub">Key Concerns</div><ul class="ins-ai-list">${concerns}</ul>` : ''}
        <div class="ins-ai-cause"><strong>Likely cause:</strong> ${escapeHtml(ai.likely_cause || '—')}</div>
        <div class="ins-ai-conf">AI confidence: <span class="ins-conf-${(ai.confidence || 'low').toLowerCase()}">${escapeHtml(ai.confidence || '—').toUpperCase()}</span></div>
      </div>` : ''}

      ${actions ? `
      <div class="ins-section-hdr" style="margin-top:20px">Recommended Actions</div>
      <ol class="ins-actions-list">${actions}</ol>` : ''}
    </div>

    <div class="ins-drawer-footer">
      <button class="btn-ghost" onclick="insiderDeleteUser(_insiderDrawerUser)">
        <svg width="13" height="13" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M9 2a1 1 0 00-.894.553L7.382 4H4a1 1 0 000 2v10a2 2 0 002 2h8a2 2 0 002-2V6a1 1 0 100-2h-3.382l-.724-1.447A1 1 0 0011 2H9zM7 8a1 1 0 012 0v6a1 1 0 11-2 0V8zm5-1a1 1 0 00-1 1v6a1 1 0 102 0V8a1 1 0 00-1-1z" clip-rule="evenodd"/></svg>
        Remove
      </button>
      <button class="btn-primary" onclick="insiderReanalyze(_insiderDrawerUser)">
        <svg width="13" height="13" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M4 2a1 1 0 011 1v2.101a7.002 7.002 0 0111.601 2.566 1 1 0 11-1.885.666A5.002 5.002 0 005.999 7H9a1 1 0 010 2H4a1 1 0 01-1-1V3a1 1 0 011-1zm.008 9.057a1 1 0 011.276.61A5.002 5.002 0 0014.001 13H11a1 1 0 110-2h5a1 1 0 011 1v5a1 1 0 11-2 0v-2.101a7.002 7.002 0 01-11.601-2.566 1 1 0 01.61-1.276z" clip-rule="evenodd"/></svg>
        Re-analyze
      </button>
    </div>
  `;

  drawer.scrollTop = 0;
}

function closeInsiderDrawer() {
  document.getElementById('insDrawer').classList.add('hidden');
  document.getElementById('insBackdrop').classList.add('hidden');
  _insiderDrawerUser = null;
}

async function insiderDeleteUser(username) {
  try {
    await post('/api/insider/delete', { username });
    _insiderData = _insiderData.filter(u => u.username !== username);
    closeInsiderDrawer();
    renderInsiderGrid();  // card remains but reverts to pending state
  } catch(_) {}
}

async function insiderReanalyze(username) {
  closeInsiderDrawer();
  await insiderAnalyzeAndOpen(username);
}
