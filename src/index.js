const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const { WebSocketServer } = require('ws');
const crypto = require('crypto');
const { db, hashToken, nextTicketNo } = require('./db');
const {
  isHomeAuthorized,
  generateDeviceToken,
  findDeviceByToken,
  generatePairingCode,
} = require('./auth');

const PORT = process.env.PORT || 8080;
const MAX_MESSAGE_LENGTH = 1000;
const PAIRING_TTL_MS = (Number(process.env.PAIRING_CODE_TTL_MINUTES) || 10) * 60 * 1000;
const CONTENT_RETENTION_MS = (Number(process.env.CONTENT_RETENTION_HOURS) || 24) * 60 * 60 * 1000;

const app = express();
app.use(cors());
app.use(express.json({ limit: '64kb' }));

// ---------------------------------------------------------------------------
// In-memory connection registry. Actual message state lives in SQLite so a
// server restart never loses the queue or causes a duplicate print.
// ---------------------------------------------------------------------------
let desktopSocket = null; // only one home computer per deployment
const phoneSockets = new Map(); // deviceId -> Set<ws>

function desktopOnline() {
  return desktopSocket !== null && desktopSocket.readyState === desktopSocket.OPEN;
}

function broadcastStatusToPhones() {
  const payload = JSON.stringify({ type: 'status', printerOnline: desktopOnline() });
  for (const set of phoneSockets.values()) {
    for (const ws of set) {
      if (ws.readyState === ws.OPEN) ws.send(payload);
    }
  }
}

function pushMessageToDesktop(row) {
  if (!desktopOnline()) return false;
  desktopSocket.send(JSON.stringify({
    type: 'message',
    id: row.id,
    ticketNo: row.ticket_no,
    deviceName: row.device_name,
    content: row.content,
    charCount: row.char_count,
    createdAt: row.created_at,
  }));
  return true;
}

// ---------------------------------------------------------------------------
// Rate limiting & basic hygiene
// ---------------------------------------------------------------------------
const sendLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 12, // 12 messages/minute per device is plenty for a personal messenger
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => req.device ? req.device.id : req.ip,
});

const pairingLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
});

// ---------------------------------------------------------------------------
// Auth middleware
// ---------------------------------------------------------------------------
function requireHome(req, res, next) {
  if (!isHomeAuthorized(req.headers.authorization)) {
    return res.status(401).json({ error: 'unauthorized' });
  }
  next();
}

function requireDevice(req, res, next) {
  const auth = req.headers.authorization || '';
  if (!auth.startsWith('Bearer ')) return res.status(401).json({ error: 'unauthorized' });
  const token = auth.slice('Bearer '.length).trim();
  const device = findDeviceByToken(token);
  if (!device) return res.status(401).json({ error: 'unauthorized' });
  req.device = device;
  next();
}

// ---------------------------------------------------------------------------
// Pairing: desktop generates a code, a phone claims it once.
// ---------------------------------------------------------------------------
app.post('/api/pairing/generate', requireHome, pairingLimiter, (req, res) => {
  const code = generatePairingCode();
  const now = Date.now();
  db.prepare('INSERT INTO pairing_codes (code, created_at, expires_at, used) VALUES (?, ?, ?, 0)')
    .run(code, now, now + PAIRING_TTL_MS);
  res.json({ code, expiresAt: now + PAIRING_TTL_MS });
});

app.post('/api/pairing/claim', pairingLimiter, (req, res) => {
  const { code, deviceName } = req.body || {};
  if (!code || typeof code !== 'string') return res.status(400).json({ error: 'code required' });
  const name = (typeof deviceName === 'string' && deviceName.trim()) ? deviceName.trim().slice(0, 40) : 'Unnamed phone';

  const row = db.prepare('SELECT * FROM pairing_codes WHERE code = ?').get(code.toUpperCase());
  if (!row) return res.status(404).json({ error: 'invalid code' });
  if (row.used) return res.status(410).json({ error: 'code already used' });
  if (Date.now() > row.expires_at) return res.status(410).json({ error: 'code expired' });

  db.prepare('UPDATE pairing_codes SET used = 1 WHERE code = ?').run(code.toUpperCase());

  const deviceId = crypto.randomUUID();
  const token = generateDeviceToken();
  db.prepare('INSERT INTO devices (id, name, token_hash, created_at, revoked) VALUES (?, ?, ?, ?, 0)')
    .run(deviceId, name, hashToken(token), Date.now());

  res.json({ deviceId, deviceToken: token, deviceName: name });
});

// ---------------------------------------------------------------------------
// Device management (from the Windows dashboard)
// ---------------------------------------------------------------------------
app.get('/api/devices', requireHome, (req, res) => {
  const rows = db.prepare('SELECT id, name, created_at, revoked FROM devices ORDER BY created_at DESC').all();
  res.json({ devices: rows });
});

app.delete('/api/devices/:id', requireHome, (req, res) => {
  const result = db.prepare('UPDATE devices SET revoked = 1 WHERE id = ?').run(req.params.id);
  if (result.changes === 0) return res.status(404).json({ error: 'not found' });
  // Drop any live socket for that device immediately.
  const set = phoneSockets.get(req.params.id);
  if (set) for (const ws of set) ws.close(4001, 'revoked');
  res.json({ ok: true });
});

// ---------------------------------------------------------------------------
// Status (used by the phone app before it opens a WS, and for simple polling)
// ---------------------------------------------------------------------------
app.get('/api/status', requireDevice, (req, res) => {
  res.json({ printerOnline: desktopOnline() });
});

// ---------------------------------------------------------------------------
// Sending a message
// ---------------------------------------------------------------------------
app.post('/api/messages', requireDevice, sendLimiter, (req, res) => {
  const { content } = req.body || {};
  if (typeof content !== 'string' || content.trim().length === 0) {
    return res.status(400).json({ error: 'content required' });
  }
  const trimmed = content.slice(0, MAX_MESSAGE_LENGTH);
  if (content.length > MAX_MESSAGE_LENGTH) {
    return res.status(413).json({ error: `message too long (max ${MAX_MESSAGE_LENGTH} characters)` });
  }

  const ticketNo = nextTicketNo();
  const now = Date.now();
  const info = db.prepare(`
    INSERT INTO messages (ticket_no, device_id, device_name, content, char_count, created_at, status)
    VALUES (?, ?, ?, ?, ?, ?, 'queued')
  `).run(ticketNo, req.device.id, req.device.name, trimmed, trimmed.length, now);

  const row = db.prepare('SELECT * FROM messages WHERE id = ?').get(info.lastInsertRowid);
  const delivered = pushMessageToDesktop(row);
  if (delivered) {
    db.prepare("UPDATE messages SET status = 'delivered', delivered_at = ? WHERE id = ?").run(Date.now(), row.id);
  }

  res.json({ id: row.id, ticketNo, status: delivered ? 'delivered' : 'queued' });
});

// A phone can poll the status of its own recent messages (session-only on
// the client side; this just answers "did it print yet?").
app.get('/api/messages/:id/status', requireDevice, (req, res) => {
  const row = db.prepare('SELECT id, status, ticket_no FROM messages WHERE id = ? AND device_id = ?')
    .get(req.params.id, req.device.id);
  if (!row) return res.status(404).json({ error: 'not found' });
  res.json({ id: row.id, ticketNo: row.ticket_no, status: row.status });
});

// ---------------------------------------------------------------------------
// Desktop pulls anything it missed while offline (e.g. right after reconnect)
// ---------------------------------------------------------------------------
app.get('/api/queue', requireHome, (req, res) => {
  const rows = db.prepare("SELECT * FROM messages WHERE status IN ('queued','delivered') ORDER BY id ASC").all();
  res.json({
    messages: rows.map((row) => ({
      id: row.id,
      ticketNo: row.ticket_no,
      deviceName: row.device_name,
      content: row.content,
      charCount: row.char_count,
      createdAt: row.created_at,
    })),
  });
});

// Desktop confirms a message printed successfully. Content is scrubbed
// immediately; only id/status/timestamps remain (duplicate-print guard).
app.post('/api/messages/:id/ack', requireHome, (req, res) => {
  const { status } = req.body || {}; // 'printed' | 'failed'
  const finalStatus = status === 'failed' ? 'failed' : 'printed';
  const result = db.prepare(`
    UPDATE messages
    SET status = ?, printed_at = CASE WHEN ? = 'printed' THEN ? ELSE printed_at END,
        content = CASE WHEN ? = 'printed' THEN NULL ELSE content END,
        content_cleared = CASE WHEN ? = 'printed' THEN 1 ELSE content_cleared END
    WHERE id = ?
  `).run(finalStatus, finalStatus, Date.now(), finalStatus, finalStatus, req.params.id);
  if (result.changes === 0) return res.status(404).json({ error: 'not found' });
  res.json({ ok: true });
});

// ---------------------------------------------------------------------------
// Retention sweep: scrub content of anything old, regardless of status, and
// drop failed messages older than the retention window entirely from the
// "actionable queue" concept (row stays for id continuity, content gone).
// ---------------------------------------------------------------------------
setInterval(() => {
  const cutoff = Date.now() - CONTENT_RETENTION_MS;
  db.prepare('UPDATE messages SET content = NULL, content_cleared = 1 WHERE created_at < ? AND content IS NOT NULL')
    .run(cutoff);
}, 15 * 60 * 1000);

// ---------------------------------------------------------------------------
// WebSocket layer
// ---------------------------------------------------------------------------
const server = app.listen(PORT, () => {
  console.log(`Paperline relay server listening on :${PORT}`);
});

const wss = new WebSocketServer({ noServer: true });

server.on('upgrade', (req, socket, head) => {
  let url;
  try {
    url = new URL(req.url, 'http://localhost');
  } catch {
    socket.destroy();
    return;
  }

  if (url.pathname === '/ws/desktop') {
    if (!isHomeAuthorized(req.headers.authorization)) {
      socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
      socket.destroy();
      return;
    }
    wss.handleUpgrade(req, socket, head, (ws) => handleDesktopConnection(ws));
    return;
  }

  if (url.pathname === '/ws/phone') {
    const auth = req.headers.authorization || '';
    const token = auth.startsWith('Bearer ') ? auth.slice(7).trim() : url.searchParams.get('token');
    const device = token ? findDeviceByToken(token) : null;
    if (!device) {
      socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
      socket.destroy();
      return;
    }
    wss.handleUpgrade(req, socket, head, (ws) => handlePhoneConnection(ws, device));
    return;
  }

  socket.destroy();
});

function handleDesktopConnection(ws) {
  // Only one home computer is expected; a fresh connection replaces a stale one.
  if (desktopSocket && desktopSocket !== ws) {
    try { desktopSocket.close(4000, 'replaced'); } catch {}
  }
  desktopSocket = ws;
  console.log('Desktop connected');
  broadcastStatusToPhones();

  ws.on('message', (raw) => {
    let msg;
    try { msg = JSON.parse(raw); } catch { return; }
    // Desktop can ack over the socket too (faster than HTTP round trip),
    // mirroring POST /api/messages/:id/ack.
    if (msg.type === 'ack' && msg.id) {
      const finalStatus = msg.status === 'failed' ? 'failed' : 'printed';
      db.prepare(`
        UPDATE messages
        SET status = ?, printed_at = CASE WHEN ? = 'printed' THEN ? ELSE printed_at END,
            content = CASE WHEN ? = 'printed' THEN NULL ELSE content END,
            content_cleared = CASE WHEN ? = 'printed' THEN 1 ELSE content_cleared END
        WHERE id = ?
      `).run(finalStatus, finalStatus, Date.now(), finalStatus, finalStatus, msg.id);
    }
  });

  ws.on('close', () => {
    if (desktopSocket === ws) {
      desktopSocket = null;
      console.log('Desktop disconnected');
      broadcastStatusToPhones();
    }
  });
}

function handlePhoneConnection(ws, device) {
  if (!phoneSockets.has(device.id)) phoneSockets.set(device.id, new Set());
  phoneSockets.get(device.id).add(ws);
  ws.send(JSON.stringify({ type: 'status', printerOnline: desktopOnline() }));

  ws.on('close', () => {
    const set = phoneSockets.get(device.id);
    if (set) {
      set.delete(ws);
      if (set.size === 0) phoneSockets.delete(device.id);
    }
  });
}

// Heartbeat to prune dead sockets (covers flaky mobile networks / sleeping desktops)
setInterval(() => {
  const check = (ws) => {
    if (!ws) return;
    if (ws.isAlive === false) { try { ws.terminate(); } catch {} return; }
    ws.isAlive = false;
    try { ws.ping(); } catch {}
  };
  check(desktopSocket);
  for (const set of phoneSockets.values()) for (const ws of set) check(ws);
}, 30000);

wss.on('connection', (ws) => {
  ws.isAlive = true;
  ws.on('pong', () => { ws.isAlive = true; });
});
