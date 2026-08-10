let paused = false;
let totalPackets = 0;
let flaggedPackets = 0;
let totalBytes = 0;

const tbody     = document.getElementById('packet-body');
const cntTotal  = document.getElementById('cnt-total');
const cntFlagged= document.getElementById('cnt-flagged');
const cntBytes  = document.getElementById('cnt-bytes');
const wsStatus  = document.getElementById('ws-status');
const btnPause  = document.getElementById('btn-pause');
const btnClear  = document.getElementById('btn-clear');
const MAX_ROWS  = 200;

function fmtBytes(b) {
  if (b < 1024) return `${b} B`;
  if (b < 1048576) return `${(b/1024).toFixed(1)} KB`;
  return `${(b/1048576).toFixed(2)} MB`;
}

function addRow(p) {
  if (paused) return;
  totalPackets++;
  totalBytes += p.size || 0;
  if (p.flagged) flaggedPackets++;

  cntTotal.textContent  = totalPackets;
  cntFlagged.textContent= flaggedPackets;
  cntBytes.textContent  = fmtBytes(totalBytes);

  // Remove placeholder
  const placeholder = tbody.querySelector('.empty-state');
  if (placeholder) placeholder.parentElement.remove();

  // Trim old rows
  while (tbody.rows.length >= MAX_ROWS) tbody.deleteRow(tbody.rows.length - 1);

  const tr = document.createElement('tr');
  tr.className = `packet-new${p.flagged ? ' packet-flagged' : ''}`;
  tr.innerHTML = `
    <td class="mono">${p.timestamp || '—'}</td>
    <td class="mono">${p.src_ip || '—'}${p.src_port ? ':' + p.src_port : ''}</td>
    <td class="mono">${p.dst_ip || '—'}${p.dst_port ? ':' + p.dst_port : ''}</td>
    <td>${p.protocol || '—'}</td>
    <td>${p.size || 0}</td>
    <td>${p.flagged ? '⚠ FLAGGED' : '—'}</td>
  `;
  tbody.insertBefore(tr, tbody.firstChild);
  setTimeout(() => tr.classList.remove('packet-new'), 300);
}

// ── WebSocket ─────────────────────────────────────────────────────────────
function connect() {
  const ws = new WebSocket(WS_URL);
  ws.onopen = () => {
    wsStatus.textContent = '⬤ Live';
    wsStatus.className = 'live-badge connected';
  };
  ws.onmessage = e => {
    try { addRow(JSON.parse(e.data)); } catch {}
  };
  ws.onclose = () => {
    wsStatus.textContent = '⬤ Disconnected';
    wsStatus.className = 'live-badge disconnected';
    setTimeout(connect, 3000);
  };
  ws.onerror = () => ws.close();
}

connect();

btnPause.addEventListener('click', () => {
  paused = !paused;
  btnPause.textContent = paused ? 'Resume' : 'Pause';
});

btnClear.addEventListener('click', () => {
  tbody.innerHTML = '<tr><td colspan="6" class="empty-state">Cleared.</td></tr>';
  totalPackets = flaggedPackets = totalBytes = 0;
  cntTotal.textContent = cntFlagged.textContent = '0';
  cntBytes.textContent = '0 B';
});
