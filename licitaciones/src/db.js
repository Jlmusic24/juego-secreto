'use strict';
const { DatabaseSync } = require('node:sqlite');
const crypto = require('node:crypto');

const SCHEMA = `
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS settings (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
  id                INTEGER PRIMARY KEY AUTOINCREMENT,
  email             TEXT NOT NULL UNIQUE COLLATE NOCASE,
  name              TEXT NOT NULL,
  password_hash     TEXT NOT NULL,
  role              TEXT NOT NULL CHECK (role IN ('admin','bidder')),
  status            TEXT NOT NULL CHECK (status IN ('pending','active','blocked')),
  totp_secret       TEXT,
  totp_last_counter INTEGER NOT NULL DEFAULT 0,
  failed_logins     INTEGER NOT NULL DEFAULT 0,
  locked_until      INTEGER NOT NULL DEFAULT 0,
  created_at        INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
  id_hash    TEXT PRIMARY KEY,
  user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL,
  last_seen  INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  ip         TEXT,
  user_agent TEXT
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

CREATE TABLE IF NOT EXISTS auctions (
  id                   INTEGER PRIMARY KEY AUTOINCREMENT,
  title                TEXT NOT NULL,
  description          TEXT NOT NULL DEFAULT '',
  mode                 TEXT NOT NULL CHECK (mode IN ('abierta','sellada')),
  starting_price_cents INTEGER NOT NULL CHECK (starting_price_cents > 0),
  min_increment_cents  INTEGER NOT NULL CHECK (min_increment_cents > 0),
  status               TEXT NOT NULL CHECK (status IN ('borrador','activa','pausada','cerrada','cancelada')),
  starts_at            INTEGER NOT NULL,
  ends_at              INTEGER NOT NULL,
  paused_remaining_ms  INTEGER,
  winner_user_id       INTEGER REFERENCES users(id),
  winning_bid_cents    INTEGER,
  created_by           INTEGER NOT NULL REFERENCES users(id),
  created_at           INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS bids (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  auction_id   INTEGER NOT NULL REFERENCES auctions(id),
  user_id      INTEGER NOT NULL REFERENCES users(id),
  amount_cents INTEGER NOT NULL CHECK (amount_cents > 0),
  created_at   INTEGER NOT NULL,
  ip           TEXT
);
CREATE INDEX IF NOT EXISTS idx_bids_auction ON bids(auction_id, amount_cents DESC);

CREATE TABLE IF NOT EXISTS audit (
  id        INTEGER PRIMARY KEY AUTOINCREMENT,
  ts        INTEGER NOT NULL,
  actor_id  INTEGER,
  action    TEXT NOT NULL,
  details   TEXT NOT NULL,
  prev_hash TEXT NOT NULL,
  hash      TEXT NOT NULL
);
`;

function openDb(path) {
  const db = new DatabaseSync(path);
  db.exec(SCHEMA);
  return db;
}

/** Ejecuta fn dentro de una transacción con bloqueo de escritura inmediato. */
function tx(db, fn) {
  db.exec('BEGIN IMMEDIATE');
  try {
    const result = fn();
    db.exec('COMMIT');
    return result;
  } catch (err) {
    db.exec('ROLLBACK');
    throw err;
  }
}

/** Secreto del servidor: usa APP_SECRET si existe, si no genera y persiste uno. */
function getAppSecret(db) {
  if (process.env.APP_SECRET && process.env.APP_SECRET.length >= 32) return process.env.APP_SECRET;
  const row = db.prepare("SELECT value FROM settings WHERE key = 'app_secret'").get();
  if (row) return row.value;
  const secret = crypto.randomBytes(32).toString('hex');
  db.prepare("INSERT INTO settings (key, value) VALUES ('app_secret', ?)").run(secret);
  return secret;
}

module.exports = { openDb, tx, getAppSecret };
