/* ═══════════════════════════════════════════════════════════════
   DriftDB Dashboard — App Logic
   ═══════════════════════════════════════════════════════════════ */

const DriftApp = (() => {
  // ── State ─────────────────────────────────────────────────
  let sessionToken = null;
  let nodes = [];
  let activities = [];
  let statsInterval = null;

  // ── API Helpers ───────────────────────────────────────────
  const API_BASE = window.location.origin;

  async function api(path, options = {}) {
    const headers = {
      'Content-Type': 'application/json',
      ...(options.headers || {}),
    };
    if (sessionToken) {
      headers['Authorization'] = `Bearer ${sessionToken}`;
    }
    try {
      const res = await fetch(`${API_BASE}${path}`, {
        ...options,
        headers,
      });
      const data = await res.json();
      if (!res.ok && !data) {
        throw new Error(`HTTP ${res.status}`);
      }
      return data;
    } catch (err) {
      throw err;
    }
  }

  // ── Toast Notifications ──────────────────────────────────
  function toast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    const el = document.createElement('div');
    el.className = `toast toast-${type}`;
    el.textContent = message;
    container.appendChild(el);
    setTimeout(() => {
      el.style.opacity = '0';
      el.style.transform = 'translateX(40px)';
      el.style.transition = 'all 0.3s ease';
      setTimeout(() => el.remove(), 300);
    }, 3500);
  }

  // ── Auth Flow ────────────────────────────────────────────
  function initAuth() {
    const saved = sessionStorage.getItem('drift_token');
    if (saved) {
      sessionToken = saved;
      checkSession();
    }

    const form = document.getElementById('login-form');
    form.addEventListener('submit', handleLogin);

    document.getElementById('logout-btn').addEventListener('click', handleLogout);
  }

  async function handleLogin(e) {
    e.preventDefault();
    const token = document.getElementById('token-input').value.trim();
    if (!token) {
      showLoginError('Please enter an authentication token.');
      return;
    }

    const btn = document.getElementById('login-btn');
    btn.innerHTML = '<span class="spinner"></span> Signing in...';
    btn.disabled = true;

    try {
      // Test the token against the health endpoint (with auth)
      const res = await fetch(`${API_BASE}/health`, {
        headers: { 'Authorization': `Bearer ${token}` },
      });
      const data = await res.json();

      if (data.success && data.data && data.data.version) {
        // Token worked — we got full stats (authenticated response)
        sessionToken = token;
        sessionStorage.setItem('drift_token', token);
        hideLoginError();
        showDashboard();
        toast('Signed in successfully', 'success');
        addActivity('Authenticated and connected to DriftDB');
      } else if (data.success && data.data && !data.data.version) {
        // Got minimal health response — means auth is required but token was wrong
        showLoginError('Invalid token — authentication failed.');
      } else {
        showLoginError('Could not verify token. Is the server running?');
      }
    } catch (err) {
      showLoginError('Connection failed. Is DriftDB running with --rest?');
    }

    btn.innerHTML = 'Sign In';
    btn.disabled = false;
  }

  async function checkSession() {
    try {
      const res = await fetch(`${API_BASE}/health`, {
        headers: { 'Authorization': `Bearer ${sessionToken}` },
      });
      const data = await res.json();
      if (data.success && data.data && data.data.version) {
        showDashboard();
        return;
      }
    } catch (e) {}
    // Session invalid
    sessionToken = null;
    sessionStorage.removeItem('drift_token');
  }

  function handleLogout() {
    sessionToken = null;
    sessionStorage.removeItem('drift_token');
    showLogin();
    toast('Signed out', 'info');
  }

  function showLoginError(msg) {
    const el = document.getElementById('login-error');
    el.textContent = msg;
    el.classList.add('show');
  }

  function hideLoginError() {
    document.getElementById('login-error').classList.remove('show');
  }

  // ── Page Navigation ──────────────────────────────────────
  function showLogin() {
    document.getElementById('login-page').style.display = 'flex';
    document.getElementById('dashboard').classList.remove('active');
    if (statsInterval) clearInterval(statsInterval);
  }

  function showDashboard() {
    document.getElementById('login-page').style.display = 'none';
    document.getElementById('dashboard').classList.add('active');
    loadDashboardData();
    // Poll stats every 10 seconds
    statsInterval = setInterval(loadStats, 10000);
  }

  // ── Dashboard Data ───────────────────────────────────────
  async function loadDashboardData() {
    await Promise.all([loadStats(), loadNodes()]);
  }

  async function loadStats() {
    try {
      const data = await api('/health');
      if (data.success && data.data) {
        const d = data.data;
        document.getElementById('stat-status').textContent = d.status || '—';
        document.getElementById('stat-version').textContent = d.version || '—';
        document.getElementById('stat-connections').textContent = d.connections ?? '—';
        document.getElementById('dash-version').textContent = `v${d.version || '0.1.5'}`;

        // Parse stats string if available
        if (d.stats) {
          parseStats(d.stats);
        }

        setConnected(true);
      }
    } catch (err) {
      setConnected(false);
    }
  }

  function parseStats(statsStr) {
    // Try to extract node/edge counts from the stats string
    const nodeMatch = statsStr.match(/(\d+)\s*node/i);
    const edgeMatch = statsStr.match(/(\d+)\s*edge/i);
    if (nodeMatch) document.getElementById('stat-nodes').textContent = nodeMatch[1];
    if (edgeMatch) document.getElementById('stat-edges').textContent = edgeMatch[1];
  }

  async function loadNodes() {
    try {
      const data = await api('/nodes');
      if (data.success && data.data) {
        nodes = data.data.nodes || [];
        document.getElementById('stat-nodes').textContent = data.data.count ?? nodes.length;
        renderNodes(nodes);
      }
    } catch (err) {
      // Nodes endpoint might fail if no nodes exist
    }
  }

  function setConnected(connected) {
    const dot = document.getElementById('status-dot');
    const text = document.getElementById('status-text');
    if (connected) {
      dot.classList.remove('disconnected');
      text.textContent = 'Connected';
    } else {
      dot.classList.add('disconnected');
      text.textContent = 'Disconnected';
    }
  }

  // ── Node Browser ─────────────────────────────────────────
  function renderNodes(nodeList) {
    const container = document.getElementById('node-list');
    const countEl = document.getElementById('node-count');
    countEl.textContent = `${nodeList.length} node${nodeList.length !== 1 ? 's' : ''}`;

    if (nodeList.length === 0) {
      container.innerHTML = `
        <div class="empty-state">
          <div class="empty-icon">
            <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/></svg>
          </div>
          <p>No nodes yet. Create one using the console.</p>
        </div>`;
      return;
    }

    container.innerHTML = nodeList.map(node => {
      const labels = (node.labels || []).map(l =>
        `<span class="node-label">${escapeHtml(l)}</span>`
      ).join('');

      const props = Object.entries(node.properties || {}).map(([k, v]) =>
        `<span class="key">${escapeHtml(k)}</span>: <span class="value">${escapeHtml(formatValue(v))}</span>`
      ).join(', ');

      const shortId = String(node.id).substring(0, 12);

      return `
        <div class="node-item" onclick="DriftApp.inspectNode('${node.id}')">
          <div class="node-item-header">
            <div class="node-labels">${labels || '<span style="color:var(--text-dim);font-size:.7rem">no labels</span>'}</div>
            <span class="node-id">#${escapeHtml(shortId)}</span>
          </div>
          <div class="node-props">${props || '<span style="color:var(--text-dim)">no properties</span>'}</div>
          <div class="node-actions">
            <button class="btn btn-secondary btn-sm" onclick="event.stopPropagation(); DriftApp.deleteNode('${node.id}')">Delete</button>
          </div>
        </div>`;
    }).join('');
  }

  function initNodeSearch() {
    const search = document.getElementById('node-search');
    search.addEventListener('input', () => {
      const q = search.value.toLowerCase();
      if (!q) {
        renderNodes(nodes);
        return;
      }
      const filtered = nodes.filter(n => {
        const labelMatch = (n.labels || []).some(l => l.toLowerCase().includes(q));
        const propMatch = Object.entries(n.properties || {}).some(([k, v]) =>
          k.toLowerCase().includes(q) || String(v).toLowerCase().includes(q)
        );
        const idMatch = String(n.id).toLowerCase().includes(q);
        return labelMatch || propMatch || idMatch;
      });
      renderNodes(filtered);
    });
  }

  // ── DriftQL Execution ────────────────────────────────────
  async function executeQuery() {
    const editor = document.getElementById('query-editor');
    const query = editor.value.trim();
    if (!query) {
      toast('Enter a query first', 'error');
      return;
    }

    const btn = document.getElementById('execute-btn');
    btn.innerHTML = '<span class="spinner"></span> Running...';
    btn.disabled = true;

    try {
      const data = await api('/query', {
        method: 'POST',
        body: JSON.stringify({ query }),
      });

      if (data.success && data.data) {
        renderResult(data.data);
        addActivity(`Query executed: ${query.substring(0, 50)}${query.length > 50 ? '...' : ''}`);

        // Refresh nodes if it was a mutation
        const upper = query.toUpperCase();
        if (upper.includes('CREATE') || upper.includes('DELETE') || upper.includes('SET') || upper.includes('LINK')) {
          setTimeout(loadNodes, 300);
        }
      } else {
        renderError(data.error || 'Unknown error');
      }
    } catch (err) {
      renderError(err.message || 'Connection failed');
    }

    btn.innerHTML = '▶ Execute';
    btn.disabled = false;
  }

  function renderResult(result) {
    const container = document.getElementById('query-results');

    switch (result.type) {
      case 'table':
        if (!result.columns || !result.rows) {
          container.innerHTML = '<div class="result-info">Empty result set.</div>';
          break;
        }
        let html = '<table class="results-table"><thead><tr>';
        result.columns.forEach(col => {
          html += `<th>${escapeHtml(col)}</th>`;
        });
        html += '</tr></thead><tbody>';
        result.rows.forEach(row => {
          html += '<tr>';
          row.forEach(cell => {
            html += `<td>${escapeHtml(formatValue(cell))}</td>`;
          });
          html += '</tr>';
        });
        html += '</tbody></table>';
        container.innerHTML = html;
        break;

      case 'node_created':
        container.innerHTML = `
          <div class="result-ok">✓ Node created — ID: ${escapeHtml(String(result.id))}</div>
          <div class="result-json">${escapeHtml(JSON.stringify(result, null, 2))}</div>`;
        break;

      case 'edge_created':
        container.innerHTML = `
          <div class="result-ok">✓ Edge created — Type: ${escapeHtml(result.edge_type)}</div>`;
        break;

      case 'deleted':
        container.innerHTML = `
          <div class="result-ok">✓ Deleted — ID: ${escapeHtml(String(result.id))}</div>`;
        break;

      case 'property_set':
        container.innerHTML = `
          <div class="result-ok">✓ Property set: ${escapeHtml(result.property)} on node ${escapeHtml(String(result.node_id))}</div>`;
        break;

      case 'info':
        container.innerHTML = `<div class="result-info">${escapeHtml(result.text).replace(/\n/g, '<br>')}</div>`;
        break;

      case 'help':
        container.innerHTML = `<pre class="result-json">${escapeHtml(result.text)}</pre>`;
        break;

      case 'similar':
        let shtml = '<table class="results-table"><thead><tr><th>Node</th><th>Similarity</th></tr></thead><tbody>';
        (result.results || []).forEach(r => {
          shtml += `<tr><td>${escapeHtml(r.node)}</td><td>${Number(r.similarity).toFixed(4)}</td></tr>`;
        });
        shtml += '</tbody></table>';
        container.innerHTML = shtml;
        break;

      case 'ok':
        container.innerHTML = '<div class="result-ok">✓ OK</div>';
        break;

      default:
        container.innerHTML = `<div class="result-json">${escapeHtml(JSON.stringify(result, null, 2))}</div>`;
    }
  }

  function renderError(msg) {
    const container = document.getElementById('query-results');
    container.innerHTML = `<div class="result-error">✗ ${escapeHtml(msg)}</div>`;
  }

  // ── Examples ─────────────────────────────────────────────
  const examples = {
    create: 'CREATE (u:User {name: "Alice", age: 25, active: true})',
    find: 'FIND (n:User) RETURN n.name, n.age',
    stats: 'SHOW STATS',
  };

  function loadExample(name) {
    const editor = document.getElementById('query-editor');
    editor.value = examples[name] || '';
    editor.focus();
  }

  // ── Activity Feed ────────────────────────────────────────
  function addActivity(message) {
    const now = new Date();
    const time = now.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
    activities.unshift({ time, message });
    if (activities.length > 50) activities.length = 50;
    renderActivities();
  }

  function renderActivities() {
    const container = document.getElementById('activity-feed');
    if (activities.length === 0) {
      container.innerHTML = `
        <div class="empty-state">
          <div class="empty-icon">
            <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
          </div>
          <p>Waiting for activity...</p>
        </div>`;
      return;
    }

    container.innerHTML = activities.map(a => `
      <div class="activity-item">
        <span class="activity-time">${escapeHtml(a.time)}</span>
        <span class="activity-message">${escapeHtml(a.message)}</span>
      </div>
    `).join('');
  }

  function clearActivity() {
    activities = [];
    renderActivities();
  }

  // ── Node Actions ─────────────────────────────────────────
  function inspectNode(id) {
    const editor = document.getElementById('query-editor');
    editor.value = `FIND (n) WHERE n.__id = "${id}" RETURN n`;
    executeQuery();
  }

  async function deleteNode(id) {
    if (!confirm(`Delete node ${id}?`)) return;
    try {
      const data = await api(`/nodes/${id}`, { method: 'DELETE' });
      if (data.success) {
        toast('Node deleted', 'success');
        addActivity(`Deleted node #${String(id).substring(0, 12)}`);
        await loadNodes();
      } else {
        toast(data.error || 'Delete failed', 'error');
      }
    } catch (err) {
      toast('Delete failed: ' + err.message, 'error');
    }
  }

  // ── Keyboard Shortcuts ───────────────────────────────────
  function initKeyboard() {
    document.addEventListener('keydown', (e) => {
      // Ctrl+Enter or Cmd+Enter → execute query
      if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
        const editor = document.getElementById('query-editor');
        if (document.activeElement === editor || document.getElementById('dashboard').classList.contains('active')) {
          e.preventDefault();
          executeQuery();
        }
      }
    });
  }

  // ── Utilities ────────────────────────────────────────────
  function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = String(str);
    return div.innerHTML;
  }

  function formatValue(v) {
    if (v === null || v === undefined) return 'null';
    if (typeof v === 'object') return JSON.stringify(v);
    return String(v);
  }

  // ── Init ─────────────────────────────────────────────────
  function init() {
    initAuth();
    initNodeSearch();
    initKeyboard();

    document.getElementById('refresh-btn').addEventListener('click', () => {
      loadDashboardData();
      toast('Refreshed', 'info');
      addActivity('Dashboard data refreshed');
    });

    // Check if server has no auth (try unauthenticated health check)
    checkNoAuth();
  }

  async function checkNoAuth() {
    try {
      const res = await fetch(`${API_BASE}/health`);
      const data = await res.json();
      // If we get full stats without auth, server has no token set
      if (data.success && data.data && data.data.version) {
        sessionToken = null; // no token needed
        showDashboard();
        addActivity('Connected (no authentication required)');
      }
    } catch (e) {
      // Server not reachable or auth required — stay on login
    }
  }

  // ── Start ────────────────────────────────────────────────
  document.addEventListener('DOMContentLoaded', init);

  // Public API
  return {
    executeQuery,
    loadExample,
    clearActivity,
    inspectNode,
    deleteNode,
  };
})();
