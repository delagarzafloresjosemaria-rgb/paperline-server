const crypto = require('crypto');
const { db, hashToken } = require('./db');

const HOME_SECRET = process.env.HOME_SECRET;
if (!HOME_SECRET || HOME_SECRET.length < 16) {
  console.error('FATAL: HOME_SECRET is not set (or too short) in the environment. Refusing to start.');
  process.exit(1);
}

function timingSafeEqualStr(a, b) {
  const bufA = Buffer.from(String(a));
  const bufB = Buffer.from(String(b));
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

// The Windows app authenticates with the single, long, random HOME_SECRET
// (generated once during setup, never sent to the phone).
function isHomeAuthorized(headerValue) {
  if (!headerValue || !headerValue.startsWith('Bearer ')) return false;
  const token = headerValue.slice('Bearer '.length).trim();
  return timingSafeEqualStr(token, HOME_SECRET);
}

// Each phone gets its own per-device token, generated at pairing time and
// stored on the server only as a salted hash.
function generateDeviceToken() {
  return crypto.randomBytes(32).toString('base64url');
}

function findDeviceByToken(token) {
  const hash = hashToken(token);
  return db.prepare('SELECT * FROM devices WHERE token_hash = ? AND revoked = 0').get(hash);
}

function generatePairingCode() {
  // 6 characters, easy to type by hand if the QR scan fails, drawn from an
  // unambiguous alphabet (no 0/O/1/I).
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let code = '';
  for (let i = 0; i < 6; i++) {
    code += alphabet[crypto.randomInt(alphabet.length)];
  }
  return code;
}

module.exports = {
  HOME_SECRET,
  isHomeAuthorized,
  generateDeviceToken,
  findDeviceByToken,
  generatePairingCode,
};
