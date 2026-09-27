const Database = require('better-sqlite3');
const path = require('path');
const crypto = require('crypto');

const DB_PATH = process.env.DB_PATH || path.join(__dirname, '..', 'paperline.db');
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');

db.exec(`
CREATE TABLE IF NOT EXISTS devices (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  created_at INTEGER NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS pairing_codes (
  code TEXT PRIMARY KEY,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  used INTEGER NOT NULL DEFAULT 0
);

-- Messages are the print queue. "content" is nulled out once printed+acked
-- (or after retention expiry), but the row (id/status) is kept so a message
-- can never be delivered twice, per the ephemeral-privacy requirement.
CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ticket_no INTEGER NOT NULL,
  device_id TEXT NOT NULL,
  device_name TEXT NOT NULL,
  content TEXT,
  char_count INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'queued', -- queued | delivered | printed | failed
  delivered_at INTEGER,
  printed_at INTEGER,
  content_cleared INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS counters (
  name TEXT PRIMARY KEY,
  value INTEGER NOT NULL
);
INSERT OR IGNORE INTO counters (name, value) VALUES ('ticket_no', 0);
`);

function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

function nextTicketNo() {
  const row = db.prepare('UPDATE counters SET value = value + 1 WHERE name = ? RETURNING value')
    .get('ticket_no');
  return row.value;
}

module.exports = { db, hashToken, nextTicketNo };
