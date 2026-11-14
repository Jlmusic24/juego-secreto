'use strict';
const { sha256 } = require('./security');

/**
 * Bitácora de auditoría encadenada: cada registro incluye el hash del anterior,
 * así que cualquier modificación o borrado posterior se detecta con verifyAudit().
 */
const GENESIS = '0'.repeat(64);

function entryHash(e) {
  return sha256(JSON.stringify([e.prev_hash, e.ts, e.actor_id, e.action, e.details]));
}

function createAudit(db, onEntry = () => {}) {
  const lastStmt = db.prepare('SELECT hash FROM audit ORDER BY id DESC LIMIT 1');
  const insertStmt = db.prepare(
    'INSERT INTO audit (ts, actor_id, action, details, prev_hash, hash) VALUES (?, ?, ?, ?, ?, ?)'
  );

  function log(actorId, action, details = {}) {
    const prev = lastStmt.get();
    const e = {
      ts: Date.now(),
      actor_id: actorId ?? null,
      action,
      details: JSON.stringify(details),
      prev_hash: prev ? prev.hash : GENESIS,
    };
    e.hash = entryHash(e);
    const r = insertStmt.run(e.ts, e.actor_id, e.action, e.details, e.prev_hash, e.hash);
    const entry = { id: Number(r.lastInsertRowid), ...e };
    try { onEntry(entry); } catch { /* las notificaciones nunca rompen la auditoría */ }
    return entry;
  }

  function verify() {
    let prev = GENESIS;
    let count = 0;
    for (const row of db.prepare('SELECT * FROM audit ORDER BY id ASC').iterate()) {
      if (row.prev_hash !== prev || entryHash(row) !== row.hash) {
        return { ok: false, brokenAt: row.id, checked: count };
      }
      prev = row.hash;
      count += 1;
    }
    return { ok: true, checked: count };
  }

  return { log, verify };
}

module.exports = { createAudit };
