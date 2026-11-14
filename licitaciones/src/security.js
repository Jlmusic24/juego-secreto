'use strict';
const crypto = require('node:crypto');
const { promisify } = require('node:util');

const scrypt = promisify(crypto.scrypt);

// ---------- Contraseñas (scrypt, parámetros recomendados por OWASP) ----------
const SCRYPT = { N: 2 ** 17, r: 8, p: 1, maxmem: 256 * 1024 * 1024 };
const KEYLEN = 64;

async function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const key = await scrypt(password, salt, KEYLEN, SCRYPT);
  return `scrypt$${SCRYPT.N}$${SCRYPT.r}$${SCRYPT.p}$${salt.toString('base64')}$${key.toString('base64')}`;
}

async function verifyPassword(password, stored) {
  const parts = String(stored).split('$');
  if (parts.length !== 6 || parts[0] !== 'scrypt') return false;
  const [, N, r, p, saltB64, keyB64] = parts;
  const expected = Buffer.from(keyB64, 'base64');
  const key = await scrypt(password, Buffer.from(saltB64, 'base64'), expected.length, {
    N: Number(N), r: Number(r), p: Number(p), maxmem: SCRYPT.maxmem,
  });
  return crypto.timingSafeEqual(key, expected);
}

// Hash ficticio para igualar el tiempo de respuesta cuando el usuario no existe.
let dummyHashPromise = null;
function dummyHash() {
  if (!dummyHashPromise) dummyHashPromise = hashPassword(crypto.randomBytes(16).toString('hex'));
  return dummyHashPromise;
}

function validatePasswordStrength(pw) {
  if (typeof pw !== 'string') return 'Contraseña inválida';
  if (pw.length < 10) return 'La contraseña debe tener al menos 10 caracteres';
  if (pw.length > 200) return 'La contraseña es demasiado larga';
  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter((re) => re.test(pw)).length;
  if (classes < 3) return 'Usa al menos 3 de: minúsculas, mayúsculas, números y símbolos';
  return null;
}

// ---------- TOTP (RFC 6238) para la doble verificación del administrador ----------
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32Encode(buf) {
  let bits = 0, value = 0, out = '';
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += B32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}

function base32Decode(str) {
  const clean = String(str).toUpperCase().replace(/=+$/, '').replace(/\s/g, '');
  let bits = 0, value = 0;
  const out = [];
  for (const ch of clean) {
    const idx = B32.indexOf(ch);
    if (idx === -1) throw new Error('base32 inválido');
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

function generateTotpSecret() {
  return base32Encode(crypto.randomBytes(20));
}

function hotp(secretB32, counter) {
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(counter));
  const mac = crypto.createHmac('sha1', base32Decode(secretB32)).update(buf).digest();
  const offset = mac[mac.length - 1] & 0xf;
  const code = (mac.readUInt32BE(offset) & 0x7fffffff) % 1_000_000;
  return String(code).padStart(6, '0');
}

function totpNow(secretB32, now = Date.now()) {
  return hotp(secretB32, Math.floor(now / 30000));
}

/**
 * Verifica un código TOTP con tolerancia de ±1 intervalo.
 * Devuelve el contador usado (para impedir reutilizar el mismo código) o null.
 */
function verifyTotp(secretB32, code, lastCounter = 0, now = Date.now()) {
  if (!/^\d{6}$/.test(String(code || ''))) return null;
  const current = Math.floor(now / 30000);
  for (const c of [current - 1, current, current + 1]) {
    if (c <= lastCounter) continue; // código ya usado (anti-replay)
    const expected = Buffer.from(hotp(secretB32, c));
    if (crypto.timingSafeEqual(expected, Buffer.from(String(code)))) return c;
  }
  return null;
}

function otpauthUri(secretB32, email, issuer = 'LicitApp') {
  return `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(email)}?secret=${secretB32}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
}

// ---------- Utilidades ----------
function sha256(s) {
  return crypto.createHash('sha256').update(s).digest('hex');
}

function randomToken() {
  return crypto.randomBytes(32).toString('base64url');
}

/** Limitador de peticiones en memoria por clave (IP, email...). */
function createRateLimiter({ windowMs, max }) {
  const hits = new Map();
  setInterval(() => {
    const now = Date.now();
    for (const [k, v] of hits) if (v.reset <= now) hits.delete(k);
  }, windowMs).unref();
  return function hit(key) {
    const now = Date.now();
    let entry = hits.get(key);
    if (!entry || entry.reset <= now) {
      entry = { count: 0, reset: now + windowMs };
      hits.set(key, entry);
    }
    entry.count += 1;
    return { allowed: entry.count <= max, retryAfterSec: Math.ceil((entry.reset - now) / 1000) };
  };
}

module.exports = {
  hashPassword, verifyPassword, dummyHash, validatePasswordStrength,
  generateTotpSecret, totpNow, verifyTotp, otpauthUri, base32Encode, base32Decode,
  sha256, randomToken, createRateLimiter,
};
