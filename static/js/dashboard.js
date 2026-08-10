// ── IDS Toggle ────────────────────────────────────────────────────────────
const toggleBtn = document.getElementById('btn-toggle-ids');
if (toggleBtn) {
  toggleBtn.addEventListener('click', async () => {
    const url = toggleBtn.dataset.url;
    try {
      const res = await fetch(url, { method: 'POST', headers: { 'X-CSRFToken': getCsrf() } });
      const data = await res.json();
      const on = data.idps_on;
      toggleBtn.className = `btn btn-toggle ${on ? 'btn-on' : 'btn-off'}`;
      document.getElementById('toggle-label').textContent = on ? 'ON' : 'OFF';
      const dot = document.getElementById('ids-status-dot');
      const txt = document.getElementById('ids-status-text');
      if (dot) { dot.className = `status-dot ${on ? 'on' : 'off'}`; }
      if (txt) { txt.textContent = `IDS ${on ? 'ON' : 'OFF'}`; }
    } catch (e) {
      console.error('Toggle failed:', e);
    }
  });
}

// ── Chatbot ───────────────────────────────────────────────────────────────
const chatWindow = document.getElementById('chat-window');
const chatInput  = document.getElementById('chat-input');
const chatSend   = document.getElementById('chat-send');

function appendMsg(role, text) {
  const div = document.createElement('div');
  div.className = `chat-msg ${role}`;
  div.innerHTML = `<div class="chat-bubble">${escapeHtml(text)}</div>`;
  chatWindow.appendChild(div);
  chatWindow.scrollTop = chatWindow.scrollHeight;
  return div;
}

function showTyping() {
  const div = document.createElement('div');
  div.className = 'chat-msg bot';
  div.id = 'typing-indicator';
  div.innerHTML = `<div class="chat-bubble"><span class="typing-dots"><span></span><span></span><span></span></span></div>`;
  chatWindow.appendChild(div);
  chatWindow.scrollTop = chatWindow.scrollHeight;
}

function removeTyping() {
  const t = document.getElementById('typing-indicator');
  if (t) t.remove();
}

async function sendChat() {
  if (!chatInput || !chatSend) return;
  const message = chatInput.value.trim();
  if (!message) return;
  chatInput.value = '';
  chatSend.disabled = true;
  appendMsg('user', message);
  showTyping();
  try {
    const res = await fetch(chatSend.dataset.url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CSRFToken': getCsrf() },
      body: JSON.stringify({ message }),
    });
    const data = await res.json();
    removeTyping();
    appendMsg('bot', data.response || data.error || 'No response.');
  } catch (e) {
    removeTyping();
    appendMsg('bot', 'Error contacting AI service.');
  } finally {
    chatSend.disabled = false;
    chatInput.focus();
  }
}

if (chatSend) chatSend.addEventListener('click', sendChat);
if (chatInput) chatInput.addEventListener('keydown', e => { if (e.key === 'Enter') sendChat(); });

// ── Helpers ───────────────────────────────────────────────────────────────
function getCsrf() {
  const m = document.cookie.match(/csrftoken=([^;]+)/);
  return m ? m[1] : '';
}

function escapeHtml(s) {
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}
